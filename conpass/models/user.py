"""User model with lockout state tracking.

The lockout logic follows what the DC actually does (samsrv.dll):
- badPwdCount and badPasswordTime are not replicated, the PDC Emulator holds the
  authoritative counter and is the one that writes lockoutTime.
- Nothing is reset by a timer: if badPasswordTime is older than the observation
  window, the next failure restarts the counter at 1, whatever value is stored.
- A lockout ends when lockoutTime + lockoutDuration is in the past, even though
  lockoutTime keeps its value until the next successful logon.
"""

from collections import deque
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum

from conpass.models.password_policy import PasswordPolicy

# Added to every window / lockout end to absorb clock drift and network latency
TIME_MARGIN = timedelta(seconds=2)
# Re-check delay for an account locked out for an unknown duration
LOCKED_RECHECK_DELAY = timedelta(minutes=5)


class UserStatus(Enum):
    """Status of a user account after password test."""

    PASSWORD_FOUND = "password_found"
    PASSWORD_EXPIRED = "password_expired"
    ACCOUNT_EXPIRED = "account_expired"
    ACCOUNT_DISABLED = "account_disabled"
    LOGON_RESTRICTED = "logon_restricted"
    ACCOUNT_RESTRICTED = "account_restricted"
    INVALID_PASSWORD = "invalid_password"
    PREVIOUS_PASSWORD = "previous_password"
    LOCKED_OUT = "locked_out"
    PENDING = "pending"


@dataclass(frozen=True)
class LockoutState:
    """Lockout-related attributes of a user, as read on the PDC Emulator."""

    bad_pwd_count: int = 0
    bad_pwd_filetime: int = 0  # raw value, compared to detect uncounted failures
    bad_pwd_time: datetime | None = None
    lockout_time: datetime | None = None
    locked: bool = False  # UF_LOCKOUT from msDS-User-Account-Control-Computed
    pwd_last_set: datetime | None = None
    disabled: bool = False


class User:
    """
    User account to spray.

    A user is handed to a single worker at a time by the scheduler, so its state
    does not need its own lock.
    """

    def __init__(
        self,
        samaccountname: str,
        dn: str | None,
        policy: PasswordPolicy,
        security_threshold: int,
        state: LockoutState | None = None,
    ):
        self.samaccountname = samaccountname
        self.dn = dn
        self.policy = policy
        self.security_threshold = security_threshold
        self.state = state or LockoutState()

        # Pessimistic floor built from our own failed attempts, in case the
        # value read on the PDC lags behind
        self._local_count = 0
        self._local_bad_time: datetime | None = None
        self._previous_local: tuple[int, datetime | None] = (0, None)

        # Spray state, managed by the scheduler
        self.cursor = 0  # index of the next password in the shared list
        self.extra: deque[str] = deque()  # user-specific passwords, tested first
        self.tested: set[str] = set()
        self.finished = False

        self.found_password: str | None = None
        self.status = UserStatus.PENDING

    @property
    def has_lockout_info(self) -> bool:
        """True when the lockout state comes from the DC (online mode)."""
        return self.dn is not None

    def _window_end(self, bad_time: datetime) -> datetime:
        return bad_time + timedelta(seconds=self.policy.lockout_window_seconds) + TIME_MARGIN

    def _in_window(self, bad_time: datetime | None, now: datetime) -> bool:
        return bad_time is not None and now < self._window_end(bad_time)

    def effective_bad_count(self, now: datetime) -> int:
        """Counter value the next failure will be added to."""
        pdc = self.state.bad_pwd_count if self._in_window(self.state.bad_pwd_time, now) else 0
        local = self._local_count if self._in_window(self._local_bad_time, now) else 0
        return max(pdc, local)

    def attempts_left(self, now: datetime) -> int | None:
        """Attempts left before reaching the security threshold, None if unlimited."""
        if not self.policy.has_lockout:
            return None
        return self.policy.lockout_threshold - self.security_threshold - self.effective_bad_count(now)

    def lockout_end(self, now: datetime) -> datetime | None:
        """End of the current lockout (DC time), None if the account is not locked out."""
        lockout_time = self.state.lockout_time
        if lockout_time is not None:
            duration = self.policy.lockout_duration_seconds
            if duration == 0:  # locked until an administrator unlocks it
                return now + LOCKED_RECHECK_DELAY
            end = lockout_time + timedelta(seconds=duration) + TIME_MARGIN
            if now < end:
                return end
        if self.state.locked:  # the PDC says locked, but we can't tell until when
            return now + LOCKED_RECHECK_DELAY
        return None

    def next_attempt_time(self, now: datetime) -> datetime:
        """Earliest time (DC clock) the next attempt can be made safely."""
        lockout_end = self.lockout_end(now)
        if lockout_end is not None:
            return lockout_end
        left = self.attempts_left(now)
        if left is None or left > 0:
            return now
        last_failures = [
            t for t in (self.state.bad_pwd_time, self._local_bad_time) if self._in_window(t, now)
        ]
        return max(self._window_end(t) for t in last_failures)

    def apply_state(self, state: LockoutState) -> None:
        """Replace the lockout state with a fresh read from the PDC."""
        self.state = state

    def record_failure(self, now: datetime) -> None:
        """
        Account for one failed attempt, `now` taken after the answer.

        Must be called before applying the state read after the attempt, which
        already includes it.
        """
        self._previous_local = (self._local_count, self._local_bad_time)
        self._local_count = self.effective_bad_count(now) + 1
        self._local_bad_time = now

    def cancel_last_failure(self) -> None:
        """Forget the last recorded failure, the DC did not count it."""
        self._local_count, self._local_bad_time = self._previous_local

    def __str__(self) -> str:
        return (
            f"User: {self.samaccountname}\n"
            f"  DN: {self.dn}\n"
            f"  Policy: {self.policy.name}\n"
            f"  PDC badPwdCount: {self.state.bad_pwd_count} (last failure {self.state.bad_pwd_time})\n"
            f"  Local estimate: {self._local_count} (last failure {self._local_bad_time})\n"
            f"  lockoutTime: {self.state.lockout_time} (UF_LOCKOUT={self.state.locked})\n"
            f"  Tested passwords: {len(self.tested)}\n"
            f"  Status: {self.status.value}"
        )

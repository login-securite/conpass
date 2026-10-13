"""
Lockout model: when can a password be tested on an account without locking it out.

The rules follow what the domain controller actually does (samsrv.dll):

- badPwdCount and badPasswordTime are not replicated. A failure on another DC is
  forwarded to the PDC Emulator, which holds the authoritative counter and is the
  one writing lockoutTime. conpass authenticates against the PDC and reads the
  state there, so the counter it reads is the counter its attempts move.
- Nothing is reset by a timer. When badPasswordTime is older than the observation
  window, the next failure restarts the counter at 1, whatever value is stored:
  the stored badPwdCount has to be ignored once the window has elapsed.
- A lockout ends when lockoutTime + lockoutDuration is in the past, although
  lockoutTime keeps its value until the next successful logon.
"""

from collections import deque
from dataclasses import dataclass
from datetime import datetime, timedelta

# Added to every window and lockout end, to absorb clock drift and network latency
TIME_MARGIN = timedelta(seconds=2)
# Re-check delay for an account locked out for an unknown duration
LOCKED_RECHECK_DELAY = timedelta(minutes=5)

DEFAULT_POLICY_NAME = "Default Domain Policy"


@dataclass(frozen=True)
class PasswordPolicy:
    """Password policy of the domain or of a Password Settings Object (PSO)."""

    name: str
    lockout_threshold: int  # 0 means accounts are never locked out
    lockout_window_seconds: int
    lockout_duration_seconds: int = 0  # 0 means locked until an administrator unlocks it
    min_pwd_length: int = 0
    pwd_history_length: int = 0
    max_pwd_age_days: int = 0
    min_pwd_age_days: int = 0
    complexity_enabled: bool = False

    @property
    def has_lockout(self) -> bool:
        return self.lockout_threshold > 0

    def __str__(self) -> str:
        return (
            f"{self.name} (threshold={self.lockout_threshold}, "
            f"window={self.lockout_window_seconds}s, duration={self.lockout_duration_seconds}s)"
        )


@dataclass(frozen=True)
class LockoutState:
    """Lockout-related attributes of an account, as read on the PDC Emulator."""

    bad_pwd_count: int = 0
    bad_pwd_filetime: int = 0  # raw value, compared before/after an attempt
    bad_pwd_time: datetime | None = None
    lockout_time: datetime | None = None
    locked: bool = False  # UF_LOCKOUT bit of msDS-User-Account-Control-Computed
    pwd_last_set: datetime | None = None
    disabled: bool = False


class User:
    """
    An account to spray, with its lockout bookkeeping and spraying progress.

    The scheduler hands a user to a single worker at a time, so a user needs no
    lock of its own.
    """

    def __init__(
        self,
        samaccountname: str,
        dn: str | None,
        policy: PasswordPolicy,
        security_threshold: int,
        state: LockoutState | None = None,
    ):
        """
        Args:
            samaccountname: Account name
            dn: Distinguished name, None in offline mode (no LDAP access)
            policy: Effective password policy of the account
            security_threshold: Attempts always kept unused below the lockout threshold
            state: Lockout state read on the PDC, if any
        """
        self.samaccountname = samaccountname
        self.dn = dn
        self.policy = policy
        self.security_threshold = security_threshold
        self.state = state or LockoutState()

        # Pessimistic estimate built from our own failures, used as a floor in case
        # the value read on the PDC lags behind (and as the only source offline)
        self._local_count = 0
        self._local_bad_time: datetime | None = None
        self._previous_local: tuple[int, datetime | None] = (0, None)

        # Spraying progress, managed by the scheduler
        self.cursor = 0  # index of the next shared password to test
        self.extra: deque[str] = deque()  # passwords specific to this user, tested first
        self.tested: set[str] = set()
        self.finished = False

    @property
    def online(self) -> bool:
        """True when the lockout state is read from the PDC."""
        return self.dn is not None

    def _window_end(self, bad_time: datetime) -> datetime:
        return bad_time + timedelta(seconds=self.policy.lockout_window_seconds) + TIME_MARGIN

    def _in_window(self, bad_time: datetime | None, now: datetime) -> bool:
        return bad_time is not None and now < self._window_end(bad_time)

    def effective_bad_count(self, now: datetime) -> int:
        """Value of the counter the next failure will be added to."""
        pdc = self.state.bad_pwd_count if self._in_window(self.state.bad_pwd_time, now) else 0
        local = self._local_count if self._in_window(self._local_bad_time, now) else 0
        return max(pdc, local)

    def attempts_left(self, now: datetime) -> int | None:
        """Attempts left before reaching the security threshold, None if unlimited."""
        if not self.policy.has_lockout:
            return None
        return self.policy.lockout_threshold - self.security_threshold - self.effective_bad_count(now)

    def lockout_end(self, now: datetime) -> datetime | None:
        """End of the current lockout (DC clock), None if the account is not locked out."""
        if self.state.lockout_time is not None:
            duration = self.policy.lockout_duration_seconds
            if duration == 0:
                return now + LOCKED_RECHECK_DELAY
            end = self.state.lockout_time + timedelta(seconds=duration) + TIME_MARGIN
            if now < end:
                return end
        if self.state.locked:  # the PDC says locked out, but not until when
            return now + LOCKED_RECHECK_DELAY
        return None

    def next_attempt_time(self, now: datetime) -> datetime:
        """Earliest time (DC clock) at which the next attempt is safe."""
        lockout_end = self.lockout_end(now)
        if lockout_end is not None:
            return lockout_end
        left = self.attempts_left(now)
        if left is None or left > 0:
            return now
        last_failures = [t for t in (self.state.bad_pwd_time, self._local_bad_time) if self._in_window(t, now)]
        return max(self._window_end(t) for t in last_failures)

    def record_failure(self, now: datetime) -> None:
        """
        Account for a failed attempt, `now` being taken after the answer.

        Must be called before applying the state read after the attempt, which
        already includes it.
        """
        self._previous_local = (self._local_count, self._local_bad_time)
        self._local_count = self.effective_bad_count(now) + 1
        self._local_bad_time = now

    def cancel_last_failure(self) -> None:
        """Forget the last recorded failure: the DC did not count it."""
        self._local_count, self._local_bad_time = self._previous_local

    def __str__(self) -> str:
        return (
            f"{self.samaccountname} ({self.dn})\n"
            f"  Policy: {self.policy}\n"
            f"  PDC: badPwdCount={self.state.bad_pwd_count}, badPasswordTime={self.state.bad_pwd_time}, "
            f"lockoutTime={self.state.lockout_time}, locked={self.state.locked}\n"
            f"  Local estimate: {self._local_count} failure(s), last at {self._local_bad_time}\n"
            f"  Passwords tested: {len(self.tested)}"
        )

"""User model with thread-safe password spray state management."""

import threading
from datetime import datetime, timedelta, timezone
from enum import Enum


class UserStatus(Enum):
    """Status of a user account after password test."""

    PASSWORD_FOUND = "password_found"
    PASSWORD_EXPIRED = "password_expired"
    ACCOUNT_EXPIRED = "account_expired"
    ACCOUNT_RESTRICTED = "account_restricted"
    INVALID_PASSWORD = "invalid_password"
    LOCKED_OUT = "locked_out"
    PENDING = "pending"


class User:
    """
    User account with thread-safe password spray state management.

    All mutable state is protected by an internal lock to prevent race conditions
    that could lead to account lockouts.
    """

    def __init__(
        self,
        samaccountname: str,
        dn: str | None,
        policy: 'PasswordPolicy',
        bad_password_count: int,
        bad_password_time: datetime,
        time_delta: timedelta,
        security_threshold: int,
        lockout_time: datetime | None = None,
    ):
        # Identity (immutable)
        self.samaccountname = samaccountname
        self.dn = dn
        self.policy = policy

        # Configuration (immutable)
        self.time_delta = time_delta
        self.security_threshold = security_threshold

        # Mutable state (protected by lock)
        self._lock = threading.RLock()  # Use RLock for reentrant locking
        self._bad_password_count = bad_password_count
        self._bad_password_time = bad_password_time
        self._lockout_time = lockout_time if lockout_time else datetime(1970, 1, 1, tzinfo=timezone.utc)
        self._tested_passwords: list[str] = []
        self._found_password: str | None = None
        self._status = UserStatus.PENDING
        self._is_restricted = False  # Account has restrictions (Protected Users, etc.)
        self._history_candidates: set[str] = set() # # Potential n-1 / n-2 password history matches

    def try_acquire_lock(self, blocking: bool = True, timeout: float = -1) -> bool:
        """
        Try to acquire the user's lock for testing.

        Args:
            blocking: If True, wait for lock. If False, return immediately.
            timeout: Maximum time to wait for lock (only if blocking=True)

        Returns:
            True if lock was acquired, False otherwise
        """
        return self._lock.acquire(blocking=blocking, timeout=timeout)

    def release_lock(self) -> None:
        """Release the user's lock."""
        try:
            self._lock.release()
        except RuntimeError:
            pass

    def get_remaining_attempts(self) -> int:
        """
        Calculate remaining password attempts before lockout.

        MUST be called while holding the lock to ensure thread-safety.
        """
        if not self.policy.allows_spraying:
            return 0
        return max(0, self.policy.lockout_threshold - self.security_threshold - self._bad_password_count)

    def get_observation_window_end(self) -> datetime:
        """Calculate when the observation window ends (with 1 second buffer)."""
        return self._bad_password_time + timedelta(seconds=self.policy.lockout_window_seconds + 1)

    def is_observation_window_passed(self, current_time: datetime | None = None) -> bool:
        """Check if the observation window has passed."""
        if current_time is None:
            current_time = datetime.now(timezone.utc) - self.time_delta
        return self.get_observation_window_end() <= current_time

    def is_locked_out(self, current_time: datetime | None = None) -> bool:
        """
        Check if the account is currently locked out based on lockoutTime and lockoutDuration.

        MUST be called while holding the lock to ensure thread-safety.

        Returns:
            True if account is locked out, False otherwise
        """
        if current_time is None:
            current_time = datetime.now(timezone.utc) - self.time_delta

        # Check if lockout_time is set (not epoch)
        epoch = datetime(1970, 1, 1, tzinfo=timezone.utc)
        if self._lockout_time <= epoch:
            return False

        # If lockout_duration is 0, account is locked until manual unlock
        if self.policy.lockout_duration_seconds == 0:
            return True

        # Check if lockout duration has passed
        lockout_end = self._lockout_time + timedelta(seconds=self.policy.lockout_duration_seconds)
        return current_time < lockout_end

    def can_test_password(self, password: str) -> tuple[bool, str]:
        """
        Check if a password can be tested for this user.

        MUST be called while holding the lock to ensure thread-safety.

        Returns:
            Tuple of (can_test, reason)
            - can_test: True if password can be tested
            - reason: Human-readable reason if cannot test
        """
        # Check if account is locked out
        if self.is_locked_out():
            return False, "account_locked_out"

        # Check if account is restricted (Protected Users, etc.)
        if self._is_restricted:
            return False, "account_restricted"

        # Check if already tested
        if password in self._tested_passwords:
            return False, "already_tested"

        # Check if password already found
        if self._found_password:
            return False, "password_already_found"

        # Reset bad password count if observation window passed
        if self.is_observation_window_passed():
            self._bad_password_count = 0
            self._bad_password_time = datetime.now(timezone.utc) - self.time_delta

        # Check remaining attempts
        if self.policy.allows_spraying and self.get_remaining_attempts() <= 0:
            return False, "no_remaining_attempts"

        return True, "ok"

    def get_wait_time_for_next_attempt(self, password: str) -> float:
        """
        Get time to wait (in seconds) before next password attempt.

        MUST be called while holding the lock to ensure thread-safety.

        Returns:
            0 if password can be tested now
            positive value (seconds) if we should wait for observation window
            -1 if password should never be tested
        """
        # These conditions mean we should never test this password
        if password in self._tested_passwords:
            return -1
        if self._found_password:
            return -1

        # If policy doesn't allow spraying, don't wait
        if not self.policy.allows_spraying:
            return -1

        # Reset bad password count if observation window passed
        if self.is_observation_window_passed():
            self._bad_password_count = 0
            return 0

        # Check if we have remaining attempts now
        if self.get_remaining_attempts() > 0:
            return 0

        # No remaining attempts, calculate time to wait
        current_time = datetime.now(timezone.utc) - self.time_delta
        time_remaining = (self.get_observation_window_end() - current_time).total_seconds()

        return max(0, time_remaining)

    def mark_password_tested(self, password: str, success: bool, status: UserStatus) -> None:
        """
        Mark a password as tested and update user state.

        MUST be called while holding the lock to ensure thread-safety.

        Args:
            password: The tested password
            success: Whether the password was correct
            status: The status result from the test
        """
        self._tested_passwords.append(password)
        self._status = status

        if success:
            self._found_password = password
            self._bad_password_count = 0
        elif status == UserStatus.ACCOUNT_RESTRICTED:
            # Mark account as restricted - don't test it anymore
            self._is_restricted = True
        elif status == UserStatus.INVALID_PASSWORD:
            self._bad_password_count += 1
            self._bad_password_time = datetime.now(timezone.utc) - self.time_delta

    def is_restricted(self) -> bool:
        """Check if account has restrictions (thread-safe read)."""
        with self._lock:
            return self._is_restricted

    def update_from_ldap(self, bad_password_count: int, bad_password_time: datetime, lockout_time: datetime | None = None) -> None:
        """
        Update bad password and lockout information from DC.

        MUST be called while holding the lock to ensure thread-safety.
        """
        self._bad_password_count = bad_password_count
        self._bad_password_time = bad_password_time
        if lockout_time:
            self._lockout_time = lockout_time

    def get_status(self) -> UserStatus:
        """Get current user status (thread-safe read)."""
        with self._lock:
            return self._status

    def get_found_password(self) -> str | None:
        """Get found password (thread-safe read)."""
        with self._lock:
            return self._found_password

    def get_tested_passwords(self) -> list[str]:
        """Get copy of tested passwords (thread-safe read)."""
        with self._lock:
            return self._tested_passwords.copy()

    def get_bad_password_count(self) -> int:
        """Get bad password count (thread-safe read)."""
        with self._lock:
            return self._bad_password_count

    def add_history_candidate(self, password: str) -> None:
        """Record a potential n-1 / n-2 password history match."""
        with self._lock:
            self._history_candidates.add(password)

    def get_history_candidates(self) -> list[str]:
        """Get all potential n-1 / n-2 password history matches."""
        with self._lock:
            return sorted(self._history_candidates)

    def __str__(self) -> str:
        with self._lock:
            return (
                f"User: {self.samaccountname}\n"
                f"  DN: {self.dn}\n"
                f"  Policy: {self.policy.name}\n"
                f"  Bad Password Count: {self._bad_password_count}\n"
                f"  Remaining Attempts: {self.get_remaining_attempts()}\n"
                f"  Tested Passwords: {len(self._tested_passwords)}\n"
                f"  Status: {self._status.value}\n"
                f"  Found Password: {'Yes' if self._found_password else 'No'}"
            )

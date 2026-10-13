"""Password policy model."""

from dataclasses import dataclass


@dataclass(frozen=True)
class PasswordPolicy:
    """Password policy information (default domain policy or PSO)."""

    name: str
    lockout_threshold: int
    lockout_window_seconds: int
    lockout_duration_seconds: int = 0
    min_pwd_length: int = 0
    pwd_history_length: int = 0
    max_pwd_age_days: int = 0
    min_pwd_age_days: int = 0
    complexity_enabled: bool = False

    @property
    def has_lockout(self) -> bool:
        """Check if accounts under this policy can be locked out (threshold > 0)."""
        return self.lockout_threshold > 0

    @property
    def is_default(self) -> bool:
        """Check if this is the default domain policy."""
        return self.name == "Default Domain Policy"

    def __str__(self) -> str:
        return (
            f"{self.name}: "
            f"Lockout Threshold={self.lockout_threshold}, "
            f"Lockout Window={self.lockout_window_seconds}s, "
            f"Lockout Duration={self.lockout_duration_seconds}s"
        )

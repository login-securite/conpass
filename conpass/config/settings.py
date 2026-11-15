from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class SprayConfig:
    """Configuration for password spraying operation."""

    # Domain information
    domain: str
    dc_ip: str | None = None
    dc_host: str | None = None
    dns_ip: str | None = None

    # Authentication
    use_ssl: bool = False

    # Files
    password_file: Path | None = None
    user_file: Path | None = None
    database_path: Path | None = None

    # Spray settings
    user_as_pass: bool = False
    security_threshold: int = 2
    disable_spray: bool = False

    # Manual policy (when no LDAP access)
    manual_lockout_threshold: int | None = None
    manual_lockout_observation_window: int | None = None

    # Performance
    max_threads: int = 10
    timeout: int = 3
    limit_memory: bool = False

    # N-2 Rule detection delay (seconds to wait after failed auth before re-querying LDAP)
    n2_detection_delay: float = 1.0

    # Debug
    debug: bool = False

    # LDAP settings
    ldap_page_size: int = 1000

    @property
    def base_dn(self) -> str:
        """Generate base DN from domain."""
        return ','.join(f'dc={part}' for part in self.domain.split('.'))

    @property
    def is_online_mode(self) -> bool:
        """Check if we have credentials for online LDAP access."""
        return self.manual_lockout_threshold is None

    @property
    def use_database(self) -> bool:
        """Check if database tracking is enabled."""
        return self.database_path is not None

    def __post_init__(self):
        """Validate configuration."""
        if '.' not in self.domain:
            raise ValueError("Domain must be fully qualified (e.g., domain.local)")

        if not self.is_online_mode:
            if self.manual_lockout_observation_window is None:
                raise ValueError(
                    "manual_lockout_observation_window is required when manual_lockout_threshold is set"
                )
            if self.user_file is None:
                raise ValueError("user_file is required in offline mode")

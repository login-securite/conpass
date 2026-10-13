"""Settings of a spraying session, built from the command line."""

from dataclasses import dataclass
from pathlib import Path

from conpass.hashes import parse_hashes
from conpass.lockout import PasswordPolicy


@dataclass(frozen=True)
class Credentials:
    """Domain account used to read users and policies over LDAP."""

    username: str
    domain: str  # authentication domain, may differ from the sprayed domain
    password: str = ""
    lm_hash: str = ""
    nt_hash: str = ""

    @classmethod
    def parse(cls, username: str, target_domain: str, password: str | None, hashes: str | None) -> "Credentials":
        """
        Build credentials from the command line.

        A username given as DOMAIN\\user authenticates against DOMAIN, which allows
        spraying a trusting domain with an account of another domain.

        Raises:
            ValueError: If the hashes are malformed
        """
        domain, _, name = username.rpartition("\\")
        lm_hash, nt_hash = parse_hashes(hashes) if hashes else ("", "")
        return cls(name, domain or target_domain, password or "", lm_hash, nt_hash)


@dataclass(frozen=True)
class SprayConfig:
    """Everything the orchestrator needs to run a session."""

    domain: str
    credentials: Credentials | None  # None in offline mode
    dc_ip: str | None = None
    dns_ip: str | None = None
    use_ldaps: bool = False
    password_file: Path | None = None
    user_file: Path | None = None
    database_path: Path | None = None
    user_as_pass: bool = False
    security_threshold: int = 2
    spray: bool = True
    manual_policy: PasswordPolicy | None = None  # offline mode only
    threads: int = 10
    timeout: int = 5

    @property
    def online(self) -> bool:
        """True when credentials allow reading users, policies and lockout state over LDAP."""
        return self.credentials is not None

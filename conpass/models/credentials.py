"""Credentials model for authentication."""

from dataclasses import dataclass


@dataclass(frozen=True)
class Credentials:
    """User credentials for authentication."""

    username: str
    domain: str
    password: str | None = None
    hashes: str | None = None

    def __post_init__(self):
        """Validate that either password or hashes is provided."""
        if self.password is None and self.hashes is None:
            raise ValueError("Either password or hashes must be provided")
        if self.password is not None and self.hashes is not None:
            raise ValueError("Password and hashes are mutually exclusive")

    @property
    def user_principal(self) -> str:
        """Get user principal name for LDAP binding.

        If the username already carries its own domain (``DOMAIN\\user``), that
        domain is used for authentication, letting the auth domain differ from
        the target domain (``-d``) for cross-domain spraying. Otherwise the
        target domain is used.
        """
        if "\\" in self.username:
            return self.username
        return f"{self.domain}\\{self.username}"

    @property
    def has_password(self) -> bool:
        """Check if credentials use cleartext password."""
        return self.password is not None

    @property
    def has_hash(self) -> bool:
        """Check if credentials use hash."""
        return self.hashes is not None

    def get_password_or_hash(self) -> str:
        """Get the password or hash value."""
        if self.password is not None:
            return self.password
        if self.hashes is not None:
            return self.hashes
        raise ValueError("No password or hash available")

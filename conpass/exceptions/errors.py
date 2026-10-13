"""Exception classes for ConPass."""


class ConpassError(Exception):
    """Base exception for all conpass errors."""


class LdapConnectionError(ConpassError):
    """Error connecting to LDAP server."""


class SmbConnectionError(ConpassError):
    """Error connecting to SMB server."""


class UserLockedOutError(ConpassError):
    """User account has been locked out."""

    def __init__(self, username: str):
        self.username = username
        super().__init__(f"User account '{username}' has been locked out")


class ConfigurationError(ConpassError):
    """Configuration error."""


class PdcNotFoundError(ConpassError):
    """PDC Emulator FSMO role holder not found."""


class AuthAttemptLostError(ConpassError):
    """The connection dropped during an authentication attempt.

    The DC may or may not have processed the attempt, so it must be counted as a
    failure and must not be replayed blindly.
    """

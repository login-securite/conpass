"""Custom exceptions for ConPass."""

from conpass.exceptions.errors import (
    AuthAttemptLostError,
    ConpassError,
    ConfigurationError,
    LdapConnectionError,
    PdcNotFoundError,
    SmbConnectionError,
    UserLockedOutError,
)

__all__ = [
    "AuthAttemptLostError",
    "ConpassError",
    "ConfigurationError",
    "LdapConnectionError",
    "PdcNotFoundError",
    "SmbConnectionError",
    "UserLockedOutError",
]

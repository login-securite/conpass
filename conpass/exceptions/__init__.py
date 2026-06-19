"""Custom exceptions for ConPass."""

from conpass.exceptions.errors import (
    ConpassError,
    ConfigurationError,
    LdapConnectionError,
    PdcNotFoundError,
    SmbConnectionError,
    UserLockedOutError,
)

__all__ = [
    "ConpassError",
    "ConfigurationError",
    "LdapConnectionError",
    "PdcNotFoundError",
    "SmbConnectionError",
    "UserLockedOutError",
]

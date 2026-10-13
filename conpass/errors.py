"""Exceptions raised by conpass."""


class ConpassError(Exception):
    """Base class for all conpass errors, displayed without a stack trace."""


class ConfigurationError(ConpassError):
    """Invalid command line arguments or unusable environment."""


class ConnectionFailedError(ConpassError):
    """A domain controller could not be reached or refused our credentials."""


class UserLockedOutError(ConpassError):
    """An account is locked out: spraying must stop immediately."""

    def __init__(self, username: str):
        self.username = username
        super().__init__(f"Account '{username}' is locked out")


class AuthAttemptLostError(ConpassError):
    """
    The connection dropped during an authentication attempt.

    The DC may or may not have processed the attempt, so it must be accounted for
    as a failure and never be replayed blindly.
    """

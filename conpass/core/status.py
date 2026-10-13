"""Authentication status codes and conversion logic."""

from enum import Enum

# NTSTATUS returned by msv1_0 only after the password was validated: the account
# restrictions (SamIAccountRestrictions) are checked after the password test.
_VALID_PASSWORD_STATUSES = {
    'STATUS_PASSWORD_EXPIRED': 'PASSWORD_EXPIRED',
    'STATUS_PASSWORD_MUST_CHANGE': 'PASSWORD_MUST_CHANGE',
    'STATUS_ACCOUNT_EXPIRED': 'ACCOUNT_EXPIRED',
    'STATUS_ACCOUNT_DISABLED': 'ACCOUNT_DISABLED',
    'STATUS_INVALID_WORKSTATION': 'INVALID_WORKSTATION',
    'STATUS_INVALID_LOGON_HOURS': 'INVALID_LOGON_HOURS',
    'STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT': 'MACHINE_ACCOUNT',
    'STATUS_NOLOGON_SERVER_TRUST_ACCOUNT': 'MACHINE_ACCOUNT',
    'STATUS_NOLOGON_INTERDOMAIN_TRUST_ACCOUNT': 'MACHINE_ACCOUNT',
}


class AuthStatus(Enum):
    """Authentication status codes from SMB login attempts."""

    SUCCESS = "success"
    PASSWORD_EXPIRED = "password_expired"
    PASSWORD_MUST_CHANGE = "password_must_change"
    ACCOUNT_EXPIRED = "account_expired"
    ACCOUNT_DISABLED = "account_disabled"
    INVALID_WORKSTATION = "invalid_workstation"
    INVALID_LOGON_HOURS = "invalid_logon_hours"
    MACHINE_ACCOUNT = "machine_account"
    INVALID_PASSWORD = "invalid_password"
    ACCOUNT_LOCKOUT = "account_lockout"
    ACCOUNT_RESTRICTION = "account_restriction"
    UNKNOWN = "unknown"

    @classmethod
    def from_exception(cls, exception: Exception) -> 'AuthStatus':
        """
        Determine authentication status from SMB exception.

        Args:
            exception: Exception raised during SMB login

        Returns:
            AuthStatus corresponding to the exception
        """
        error_str = str(exception)

        # Account lockout - CRITICAL
        if 'STATUS_ACCOUNT_LOCKED_OUT' in error_str:
            return cls.ACCOUNT_LOCKOUT

        for nt_status, name in _VALID_PASSWORD_STATUSES.items():
            if nt_status in error_str:
                return cls[name]

        # Protected Users, blank password restriction...
        if 'STATUS_ACCOUNT_RESTRICTION' in error_str:
            return cls.ACCOUNT_RESTRICTION

        if 'STATUS_LOGON_FAILURE' in error_str or 'STATUS_WRONG_PASSWORD' in error_str:
            return cls.INVALID_PASSWORD

        return cls.UNKNOWN

    @property
    def is_success(self) -> bool:
        """Check if this status proves the password is valid."""
        return self in (
            AuthStatus.SUCCESS,
            AuthStatus.PASSWORD_EXPIRED,
            AuthStatus.PASSWORD_MUST_CHANGE,
            AuthStatus.ACCOUNT_EXPIRED,
            AuthStatus.ACCOUNT_DISABLED,
            AuthStatus.INVALID_WORKSTATION,
            AuthStatus.INVALID_LOGON_HOURS,
            AuthStatus.MACHINE_ACCOUNT,
        )

    @property
    def is_lockout(self) -> bool:
        """Check if this status represents account lockout."""
        return self == AuthStatus.ACCOUNT_LOCKOUT

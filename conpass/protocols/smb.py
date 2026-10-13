"""
Password tests over SMB (NTLM network logon) and DC clock reading.

The NTSTATUS returned by a failed logon tells more than "wrong password": msv1_0
checks the account restrictions (expiration, logon hours, workstations...) only
after validating the password, so these statuses prove the password is right.
"""

import os
import time
from datetime import datetime
from enum import Enum

from impacket import nmb, nt_errors, smb3structs
from impacket.smbconnection import SessionError, SMBConnection

from conpass.errors import AuthAttemptLostError, ConnectionFailedError
from conpass.hashes import is_nt_hash
from conpass.output import debug
from conpass.timeutils import filetime_to_datetime

SMB_PORT = 445
CONNECT_RETRIES = 3


class AuthStatus(Enum):
    """Outcome of an authentication attempt. The value describes it for display."""

    # The password is valid
    SUCCESS = ""
    PASSWORD_EXPIRED = "password expired"
    PASSWORD_MUST_CHANGE = "password must be changed"
    ACCOUNT_EXPIRED = "account expired"
    ACCOUNT_DISABLED = "account disabled"
    INVALID_WORKSTATION = "logon restricted to some workstations"
    INVALID_LOGON_HOURS = "outside allowed logon hours"
    MACHINE_ACCOUNT = "machine or trust account"
    # The password is not proven valid
    INVALID_PASSWORD = "invalid password"
    ACCOUNT_LOCKED_OUT = "account locked out"
    ACCOUNT_RESTRICTION = "account restriction (Protected Users, blank password...)"
    UNKNOWN = "unexpected answer"

    @property
    def password_valid(self) -> bool:
        return self in _VALID_PASSWORD_STATUSES


_VALID_PASSWORD_STATUSES = {
    AuthStatus.SUCCESS,
    AuthStatus.PASSWORD_EXPIRED,
    AuthStatus.PASSWORD_MUST_CHANGE,
    AuthStatus.ACCOUNT_EXPIRED,
    AuthStatus.ACCOUNT_DISABLED,
    AuthStatus.INVALID_WORKSTATION,
    AuthStatus.INVALID_LOGON_HOURS,
    AuthStatus.MACHINE_ACCOUNT,
}

_NTSTATUS = {
    nt_errors.STATUS_LOGON_FAILURE: AuthStatus.INVALID_PASSWORD,
    nt_errors.STATUS_WRONG_PASSWORD: AuthStatus.INVALID_PASSWORD,
    nt_errors.STATUS_ACCOUNT_LOCKED_OUT: AuthStatus.ACCOUNT_LOCKED_OUT,
    nt_errors.STATUS_ACCOUNT_RESTRICTION: AuthStatus.ACCOUNT_RESTRICTION,
    nt_errors.STATUS_PASSWORD_EXPIRED: AuthStatus.PASSWORD_EXPIRED,
    nt_errors.STATUS_PASSWORD_MUST_CHANGE: AuthStatus.PASSWORD_MUST_CHANGE,
    nt_errors.STATUS_ACCOUNT_EXPIRED: AuthStatus.ACCOUNT_EXPIRED,
    nt_errors.STATUS_ACCOUNT_DISABLED: AuthStatus.ACCOUNT_DISABLED,
    nt_errors.STATUS_INVALID_WORKSTATION: AuthStatus.INVALID_WORKSTATION,
    nt_errors.STATUS_INVALID_LOGON_HOURS: AuthStatus.INVALID_LOGON_HOURS,
    nt_errors.STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT: AuthStatus.MACHINE_ACCOUNT,
    nt_errors.STATUS_NOLOGON_SERVER_TRUST_ACCOUNT: AuthStatus.MACHINE_ACCOUNT,
    nt_errors.STATUS_NOLOGON_INTERDOMAIN_TRUST_ACCOUNT: AuthStatus.MACHINE_ACCOUNT,
}


class SmbAuthenticator:
    """SMB connection to a domain controller, reused for many logon attempts. Not thread-safe."""

    def __init__(self, host: str, domain: str, timeout: float):
        """
        Args:
            host: Domain controller IP
            domain: Domain of the tested accounts
            timeout: Network timeout, in seconds
        """
        self.host = host
        self.domain = domain
        self.timeout = timeout
        self.last_error = ""  # raw error of the last UNKNOWN status
        self._connection: SMBConnection | None = None

    def connect(self) -> None:
        """
        Open the SMB connection, retrying a few times.

        Raises:
            ConnectionFailedError: If the DC cannot be reached
        """
        self.close()
        for attempt in range(1, CONNECT_RETRIES + 1):
            try:
                self._connection = SMBConnection(self.host, self.host, sess_port=SMB_PORT, timeout=self.timeout)
            except Exception as e:
                if attempt == CONNECT_RETRIES:
                    msg = f"Could not connect to {self.host} over SMB: {e}"
                    raise ConnectionFailedError(msg) from e
                time.sleep(0.5)
            else:
                return

    def close(self) -> None:
        if self._connection:
            try:
                self._connection.close()
            except Exception as e:
                debug(f"Error while closing the SMB connection to {self.host}: {e}")
        self._connection = None

    def authenticate(self, username: str, password: str) -> AuthStatus:
        """
        Try a password (or an NT hash) on an account.

        An attempt is never replayed: when the connection drops, the DC may already
        have counted it, so the caller has to account for it first.

        Raises:
            AuthAttemptLostError: If the connection dropped during the attempt
            ConnectionFailedError: If the connection cannot be restored
        """
        if not self._connection:
            self.connect()
        nt_hash = password if is_nt_hash(password) else ""
        try:
            self._connection.login(username, "" if nt_hash else password, self.domain, nthash=nt_hash)
        except SessionError as e:
            status = _NTSTATUS.get(e.getErrorCode(), AuthStatus.UNKNOWN)
            self.last_error = str(e)
            return status
        except Exception as e:  # transport failure, the attempt may or may not have been processed
            self.connect()
            msg = f"Connection lost while testing {username}: {type(e).__name__} {e}"
            raise AuthAttemptLostError(msg) from e

        try:
            self._connection.logoff()
        except Exception:
            self.connect()
        return AuthStatus.SUCCESS


def get_server_time(host: str, timeout: float) -> datetime:
    """
    Read the clock of a server from its SMB2 NEGOTIATE response, without authentication.

    badPasswordTime and lockoutTime are written with the DC clock, so every time
    computation is made on the DC clock.

    Raises:
        ConnectionFailedError: If the server cannot be reached or gives no time
    """
    try:
        session = nmb.NetBIOSTCPSession("", host, host, sess_port=SMB_PORT, timeout=timeout)
        try:
            negotiate = smb3structs.SMB2Negotiate()
            negotiate["SecurityMode"] = smb3structs.SMB2_NEGOTIATE_SIGNING_ENABLED
            negotiate["ClientGuid"] = os.urandom(16)
            negotiate["Dialects"] = [smb3structs.SMB2_DIALECT_002, smb3structs.SMB2_DIALECT_21]
            negotiate["DialectCount"] = len(negotiate["Dialects"])
            packet = smb3structs.SMB2Packet()
            packet["Command"] = smb3structs.SMB2_NEGOTIATE
            packet["Data"] = negotiate
            session.send_packet(packet.getData())
            answer = smb3structs.SMB2Packet(session.recv_packet(timeout).get_trailer())
            server_time = filetime_to_datetime(smb3structs.SMB2Negotiate_Response(answer["Data"])["SystemTime"])
        finally:
            session.close()
    except Exception as e:
        msg = f"Could not read the clock of {host} over SMB: {type(e).__name__} {e}"
        raise ConnectionFailedError(msg) from e
    if server_time is None:
        msg = f"{host} did not send its clock in the SMB negotiation"
        raise ConnectionFailedError(msg)
    return server_time

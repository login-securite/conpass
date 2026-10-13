"""
Kerberos check telling a current password from the previous one.

For a few minutes after a password change (OldPasswordAllowedPeriod, 5 minutes by
default), a DC still accepts the previous password for NTLM network logons.
Kerberos never does: the KDC rejects it with KDC_ERR_PREAUTH_FAILED and, since it
matches the previous keys, does not count this failure in badPwdCount. Checking an
NTLM success with Kerberos is therefore free of lockout risk.

Two impacket behaviours are adjusted, process-wide, when this module is imported:

- the pre-authentication timestamp is taken on the DC clock, otherwise the KDC
  answers KRB_AP_ERR_SKEW whatever the password as soon as the local clock is
  more than 5 minutes off;
- AES keys are derived with hashlib (C) instead of a pure Python PBKDF2, which
  takes a fraction of a second per key and holds the GIL.
"""

import datetime as dt
import hashlib
import socket
from enum import Enum
from struct import unpack

from impacket.krb5 import constants, kerberosv5
from impacket.krb5.crypto import _AESEnctype
from impacket.krb5.kerberosv5 import KerberosError, getKerberosTGT
from impacket.krb5.types import Principal

from conpass.hashes import is_nt_hash
from conpass.output import debug

KERBEROS_PORT = 88


class KerberosVerdict(Enum):
    """Outcome of the Kerberos check of a password accepted over NTLM."""

    CURRENT = "current"
    PREVIOUS = "previous"
    UNKNOWN = "unknown"  # the KDC could not tell (unreachable, account restrictions...)


class _DcClock(dt.datetime):
    """datetime class used by impacket's Kerberos code, shifted to the DC clock."""

    offset = dt.timedelta(0)  # local clock minus DC clock

    @classmethod
    def now(cls, tz=None):
        return dt.datetime.now(tz) - cls.offset


class _DcDatetimeModule:
    """Stand-in for the datetime module inside impacket.krb5.kerberosv5."""

    datetime = _DcClock
    timedelta = dt.timedelta
    timezone = dt.timezone


def _aes_string_to_key(cls, string, salt, params):
    """impacket's AES string-to-key (RFC 3962), with PBKDF2 computed by hashlib."""
    if not isinstance(string, bytes):
        string = string.encode("utf-8")
    if not isinstance(salt, bytes):
        salt = salt.encode("utf-8")
    (iterations,) = unpack(">L", params or b"\x00\x00\x10\x00")
    seed = hashlib.pbkdf2_hmac("sha1", string, salt, iterations, cls.seedsize)
    return cls.derive(cls.random_to_key(seed), b"kerberos")


kerberosv5.datetime = _DcDatetimeModule
_AESEnctype.string_to_key = classmethod(_aes_string_to_key)


class KerberosChecker:
    """Ask the KDC for a TGT to know whether a password is the current one. Thread-safe."""

    def __init__(self, kdc: str, domain: str, time_delta: dt.timedelta, timeout: float):
        """
        Args:
            kdc: KDC IP, the PDC Emulator
            domain: Domain of the accounts
            time_delta: Local clock minus DC clock
            timeout: Timeout of the reachability check, in seconds
        """
        self.kdc = kdc
        self.domain = domain
        _DcClock.offset = time_delta
        self.available = self._is_reachable(timeout)

    def _is_reachable(self, timeout: float) -> bool:
        """impacket opens Kerberos sockets without timeout: make sure the KDC answers first."""
        try:
            with socket.create_connection((self.kdc, KERBEROS_PORT), timeout=timeout):
                return True
        except OSError as e:
            debug(f"KDC {self.kdc} unreachable ({e}): recent passwords cannot be confirmed")
            return False

    def verify(self, username: str, password: str) -> KerberosVerdict:
        """Check a password (or NT hash) that NTLM accepted."""
        if not self.available:
            return KerberosVerdict.UNKNOWN
        nt_hash = password if is_nt_hash(password) else ""
        principal = Principal(username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
        try:
            getKerberosTGT(principal, "" if nt_hash else password, self.domain, "", nt_hash, kdcHost=self.kdc)
        except KerberosError as e:
            code = e.getErrorCode()
            if code == constants.ErrorCodes.KDC_ERR_KEY_EXPIRED.value:
                return KerberosVerdict.CURRENT
            if code == constants.ErrorCodes.KDC_ERR_PREAUTH_FAILED.value:
                return KerberosVerdict.PREVIOUS
            debug(f"Kerberos check of {username}: {e.getErrorString()}")
            return KerberosVerdict.UNKNOWN
        except Exception as e:
            debug(f"Kerberos check of {username} failed: {type(e).__name__} {e}")
            return KerberosVerdict.UNKNOWN
        return KerberosVerdict.CURRENT

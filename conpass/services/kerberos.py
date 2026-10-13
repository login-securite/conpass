"""Kerberos check used to tell a current password from the previous one.

For 5 minutes after a password change (OldPasswordAllowedPeriod), a DC accepts
the previous password for NTLM network logons. Kerberos never does: the KDC
rejects it with KDC_ERR_PREAUTH_FAILED, and since it matches the OldCredentials
keys, this failure is not counted in badPwdCount. Checking an NTLM success with
Kerberos is therefore free of lockout risk.
"""

import datetime as _datetime
import hashlib
from enum import Enum
from struct import unpack

from impacket.krb5 import constants
from impacket.krb5 import kerberosv5
from impacket.krb5.crypto import _AESEnctype
from impacket.krb5.kerberosv5 import KerberosError, getKerberosTGT
from impacket.krb5.types import Principal

from conpass.utils import is_nt_hash


class KerberosVerdict(Enum):
    """Outcome of a Kerberos check on a password accepted over NTLM."""

    CURRENT = "current"
    PREVIOUS = "previous"
    UNKNOWN = "unknown"


class _DcClock(_datetime.datetime):
    """
    datetime seen by impacket, shifted to the DC clock.

    The pre-authentication timestamp must be within 5 minutes of the KDC clock,
    otherwise the KDC answers KRB_AP_ERR_SKEW whatever the password.
    """

    offset = _datetime.timedelta(0)  # local clock - DC clock

    @classmethod
    def utcnow(cls):
        return _datetime.datetime.utcnow() - cls.offset

    @classmethod
    def now(cls, tz=None):
        return _datetime.datetime.now(tz) - cls.offset


class _DcDatetimeModule:
    """Stand-in for the datetime module inside impacket.krb5.kerberosv5."""

    datetime = _DcClock
    timedelta = _datetime.timedelta
    timezone = _datetime.timezone


def _aes_string_to_key(cls, string, salt, params):
    """Same as impacket, with PBKDF2 done by hashlib (C) instead of pure Python."""
    if not isinstance(string, bytes):
        string = string.encode("utf-8")
    if not isinstance(salt, bytes):
        salt = salt.encode("utf-8")
    (iterations,) = unpack('>L', params or b'\x00\x00\x10\x00')
    seed = hashlib.pbkdf2_hmac('sha1', string, salt, iterations, cls.seedsize)
    return cls.derive(cls.random_to_key(seed), b'kerberos')


kerberosv5.datetime = _DcDatetimeModule
_AESEnctype.string_to_key = classmethod(_aes_string_to_key)


def verify_password(
    username: str,
    password: str,
    domain: str,
    kdc_ip: str,
    time_delta: _datetime.timedelta = _datetime.timedelta(0),
) -> KerberosVerdict:
    """
    Ask a TGT for the user to know if the password is the current one.

    Args:
        time_delta: Local clock minus KDC clock, as measured on the PDC
    """
    _DcClock.offset = time_delta
    nthash = ''
    if is_nt_hash(password):
        nthash, password = password, ''

    principal = Principal(username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
    try:
        getKerberosTGT(principal, password, domain, '', nthash, kdcHost=kdc_ip)
    except KerberosError as e:
        code = e.getErrorCode()
        if code == constants.ErrorCodes.KDC_ERR_KEY_EXPIRED.value:
            return KerberosVerdict.CURRENT
        if code == constants.ErrorCodes.KDC_ERR_PREAUTH_FAILED.value:
            return KerberosVerdict.PREVIOUS
        return KerberosVerdict.UNKNOWN
    except Exception:
        return KerberosVerdict.UNKNOWN
    return KerberosVerdict.CURRENT

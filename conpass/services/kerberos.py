"""Kerberos check used to tell a current password from the previous one.

For 5 minutes after a password change (OldPasswordAllowedPeriod), a DC accepts
the previous password for NTLM network logons. Kerberos never does: the KDC
rejects it with KDC_ERR_PREAUTH_FAILED, and since it matches the OldCredentials
keys, this failure is not counted in badPwdCount. Checking an NTLM success with
Kerberos is therefore free of lockout risk.
"""

from enum import Enum

from impacket.krb5 import constants
from impacket.krb5.kerberosv5 import KerberosError, getKerberosTGT
from impacket.krb5.types import Principal

from conpass.utils import is_nt_hash


class KerberosVerdict(Enum):
    """Outcome of a Kerberos check on a password accepted over NTLM."""

    CURRENT = "current"
    PREVIOUS = "previous"
    UNKNOWN = "unknown"


def verify_password(username: str, password: str, domain: str, kdc_ip: str) -> KerberosVerdict:
    """Ask a TGT for the user to know if the password is the current one."""
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

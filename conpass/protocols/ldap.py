"""
LDAP access to domain controllers, built on impacket.

Connections are protected so that they work whatever the DC enforces:

- ldap:// (389) authenticates with NTLM and signs and seals every message, which
  satisfies "LDAP server signing requirements";
- ldaps:// (636) sends the TLS channel binding token, which satisfies
  "LDAP server channel binding token requirements" (EPA).

Values are read raw and parsed here, so no schema download is needed and
badPasswordTime keeps its exact FILETIME value.
"""

import socket
from collections.abc import Sequence
from dataclasses import dataclass

from impacket.ldap import ldap, ldapasn1

from conpass.config import Credentials
from conpass.errors import ConnectionFailedError
from conpass.lockout import DEFAULT_POLICY_NAME, LockoutState, PasswordPolicy
from conpass.output import debug
from conpass.timeutils import filetime_to_datetime, interval_to_seconds

SCHEME_PORTS = {"ldap": 389, "ldaps": 636}
PAGE_SIZE = 1000

UF_ACCOUNTDISABLE = 0x2
UF_LOCKOUT = 0x10
UF_SERVER_TRUST_ACCOUNT = 0x2000
DOMAIN_PASSWORD_COMPLEX = 0x1
LDAP_NO_SUCH_OBJECT = 32
MATCHING_RULE_BIT_AND = "1.2.840.113556.1.4.803"

LOCKOUT_ATTRIBUTES = (
    "badPwdCount",
    "badPasswordTime",
    "lockoutTime",
    "pwdLastSet",
    "userAccountControl",
    "msDS-User-Account-Control-Computed",  # holds UF_LOCKOUT, unlike userAccountControl
)

# Enabled user accounts, machine accounts excluded (they are never locked out)
ENABLED_USERS_FILTER = (
    "(&(objectCategory=person)(objectClass=user)(!(sAMAccountName=*$))"
    f"(!(userAccountControl:{MATCHING_RULE_BIT_AND}:={UF_ACCOUNTDISABLE})))"
)


@dataclass(frozen=True)
class LdapEntry:
    """A search result, with raw values keyed by lowercase attribute name."""

    dn: str
    attributes: dict[str, list[bytes]]

    def get_str(self, name: str) -> str | None:
        values = self.attributes.get(name.lower())
        return values[0].decode("utf-8", errors="replace") if values else None

    def get_int(self, name: str) -> int:
        value = self.get_str(name)
        return int(value) if value else 0

    def get_bool(self, name: str) -> bool:
        return (self.get_str(name) or "").upper() == "TRUE"


def domain_to_dn(domain: str) -> str:
    """hackn.lab -> DC=hackn,DC=lab"""
    return ",".join(f"DC={part}" for part in domain.split("."))


def parse_lockout_state(entry: LdapEntry) -> LockoutState:
    """Build the lockout state of an account from an entry read with LOCKOUT_ATTRIBUTES."""
    bad_pwd_filetime = entry.get_int("badPasswordTime")
    return LockoutState(
        bad_pwd_count=entry.get_int("badPwdCount"),
        bad_pwd_filetime=bad_pwd_filetime,
        bad_pwd_time=filetime_to_datetime(bad_pwd_filetime),
        lockout_time=filetime_to_datetime(entry.get_int("lockoutTime")),
        locked=bool(entry.get_int("msDS-User-Account-Control-Computed") & UF_LOCKOUT),
        pwd_last_set=filetime_to_datetime(entry.get_int("pwdLastSet")),
        disabled=bool(entry.get_int("userAccountControl") & UF_ACCOUNTDISABLE),
    )


def _to_entry(result: ldapasn1.SearchResultEntry) -> LdapEntry:
    attributes = {
        str(attribute["type"]).lower(): [bytes(value) for value in attribute["vals"]]
        for attribute in result["attributes"]
    }
    return LdapEntry(str(result["objectName"]), attributes)


def _check_port(host: str, port: int, timeout: float) -> None:
    """Fail fast on an unreachable port: impacket connects without any timeout."""
    with socket.create_connection((host, port), timeout=timeout):
        pass


class LdapClient:
    """Authenticated LDAP connection to one domain controller. Not thread-safe."""

    def __init__(
        self,
        host: str,
        domain: str,
        credentials: Credentials,
        schemes: Sequence[str] = ("ldap", "ldaps"),
        timeout: float = 5,
    ):
        """
        Args:
            host: Domain controller IP or hostname
            domain: Domain to query (FQDN)
            credentials: Account to bind with
            schemes: Schemes to try in order ("ldap", "ldaps")
            timeout: Network timeout, in seconds
        """
        self.host = host
        self.domain = domain
        self.base_dn = domain_to_dn(domain)
        self.credentials = credentials
        self.schemes = tuple(schemes)
        self.timeout = timeout
        self.scheme: str | None = None  # scheme of the established connection
        self._connection: ldap.LDAPConnection | None = None

    def connect(self) -> None:
        """
        Connect and bind, trying each scheme in turn.

        Raises:
            ConnectionFailedError: If the credentials are refused or no scheme works
        """
        self.close()
        failures = []
        for scheme in self.schemes:
            try:
                self._connection = self._bind(scheme)
            except ldap.LDAPSessionError as e:
                if "invalidCredentials" in str(e):
                    msg = (
                        f"{self.host} refused the credentials of {self.credentials.domain}\\{self.credentials.username}"
                    )
                    raise ConnectionFailedError(msg) from e
                failures.append(f"{scheme}: {e}")
            except Exception as e:  # network or TLS failure
                failures.append(f"{scheme}: {type(e).__name__} {e}")
            else:
                self.scheme = scheme
                debug(f"Connected to {self.host} over {scheme}")
                return
        msg = f"Could not connect to {self.host} over LDAP ({'; '.join(failures)})"
        raise ConnectionFailedError(msg)

    def _bind(self, scheme: str) -> ldap.LDAPConnection:
        _check_port(self.host, SCHEME_PORTS[scheme], self.timeout)
        connection = ldap.LDAPConnection(f"{scheme}://{self.host}", self.base_dn, self.host)
        if scheme == "ldap":
            # Only for plain sockets: pyOpenSSL does not support socket timeouts
            connection._socket.settimeout(self.timeout)  # noqa: SLF001
        credentials = self.credentials
        connection.login(
            credentials.username,
            credentials.password,
            credentials.domain,
            credentials.lm_hash,
            credentials.nt_hash,
        )
        return connection

    def close(self) -> None:
        if self._connection:
            try:
                self._connection.close()
            except Exception as e:
                debug(f"Error while closing the LDAP connection to {self.host}: {e}")
        self._connection = None

    # ----- generic queries -----

    def search(
        self,
        base: str,
        search_filter: str,
        attributes: Sequence[str],
        scope: str = "wholeSubtree",
        paged: bool = False,
    ) -> list[LdapEntry]:
        """
        Search the directory.

        Args:
            base: Base DN
            search_filter: LDAP filter
            attributes: Attributes to return
            scope: "baseObject", "singleLevel" or "wholeSubtree"
            paged: Use the paged results control (needed above 1000 results)
        """
        entries: list[LdapEntry] = []

        def collect(result) -> None:
            if isinstance(result, ldapasn1.SearchResultEntry):
                entries.append(_to_entry(result))

        controls = [ldapasn1.SimplePagedResultsControl(criticality=True, size=PAGE_SIZE)] if paged else None
        self._connection.search(
            searchBase=base,
            scope=ldapasn1.Scope(scope),
            searchFilter=search_filter,
            attributes=list(attributes),
            searchControls=controls,
            perRecordCallback=collect,
        )
        return entries

    def read(self, dn: str, attributes: Sequence[str]) -> LdapEntry | None:
        """Read one object, None if it does not exist."""
        try:
            entries = self.search(dn, "(objectClass=*)", attributes, scope="baseObject")
        except ldap.LDAPSearchError as e:
            if e.getErrorCode() == LDAP_NO_SUCH_OBJECT:
                return None
            raise
        return entries[0] if entries else None

    # ----- domain information -----

    def find_pdc_hostname(self) -> str | None:
        """
        Hostname of the PDC Emulator.

        fSMORoleOwner, on the domain object, points to the NTDS Settings object of
        the role owner, whose parent (the server object) carries its dNSHostName.
        """
        domain = self.read(self.base_dn, ["fSMORoleOwner"])
        owner = domain.get_str("fSMORoleOwner") if domain else None
        if not owner:
            return None
        server = self.read(owner.split(",", 1)[1], ["dNSHostName"])
        return server.get_str("dNSHostName") if server else None

    def domain_controller_hostnames(self) -> list[str]:
        """Hostnames of all domain controllers of the domain."""
        entries = self.search(
            self.base_dn,
            f"(userAccountControl:{MATCHING_RULE_BIT_AND}:={UF_SERVER_TRUST_ACCOUNT})",
            ["dNSHostName"],
        )
        return [name for entry in entries if (name := entry.get_str("dNSHostName"))]

    def default_policy(self) -> PasswordPolicy:
        """
        Password policy set on the domain object.

        Raises:
            ConnectionFailedError: If the domain object cannot be read
        """
        entry = self.read(
            self.base_dn,
            [
                "lockoutThreshold",
                "lockoutDuration",
                "lockOutObservationWindow",
                "minPwdLength",
                "pwdHistoryLength",
                "maxPwdAge",
                "minPwdAge",
                "pwdProperties",
            ],
        )
        if entry is None or not entry.attributes:
            msg = (
                f"Could not read the domain object {self.base_dn}: check the domain name (-d), "
                f"and that the account can read it (DOMAIN\\user to authenticate in another domain)"
            )
            raise ConnectionFailedError(msg)
        return PasswordPolicy(
            name=DEFAULT_POLICY_NAME,
            lockout_threshold=entry.get_int("lockoutThreshold"),
            lockout_window_seconds=interval_to_seconds(entry.get_int("lockOutObservationWindow")),
            lockout_duration_seconds=interval_to_seconds(entry.get_int("lockoutDuration")),
            min_pwd_length=entry.get_int("minPwdLength"),
            pwd_history_length=entry.get_int("pwdHistoryLength"),
            max_pwd_age_days=interval_to_seconds(entry.get_int("maxPwdAge")) // 86400,
            min_pwd_age_days=interval_to_seconds(entry.get_int("minPwdAge")) // 86400,
            complexity_enabled=bool(entry.get_int("pwdProperties") & DOMAIN_PASSWORD_COMPLEX),
        )

    def password_settings_objects(self) -> list[PasswordPolicy]:
        """
        Fine-grained password policies (PSOs) readable by the account.

        By default only administrators can read them: an empty list does not mean
        that none exists.
        """
        try:
            entries = self.search(
                f"CN=Password Settings Container,CN=System,{self.base_dn}",
                "(objectClass=msDS-PasswordSettings)",
                [
                    "name",
                    "msDS-LockoutThreshold",
                    "msDS-LockoutObservationWindow",
                    "msDS-LockoutDuration",
                    "msDS-MinimumPasswordLength",
                    "msDS-PasswordHistoryLength",
                    "msDS-MaximumPasswordAge",
                    "msDS-MinimumPasswordAge",
                    "msDS-PasswordComplexityEnabled",
                ],
                scope="singleLevel",
            )
        except ldap.LDAPSearchError as e:
            debug(f"Password Settings Container not readable: {e}")
            return []
        return [
            PasswordPolicy(
                name=entry.get_str("name") or entry.dn,
                lockout_threshold=entry.get_int("msDS-LockoutThreshold"),
                lockout_window_seconds=interval_to_seconds(entry.get_int("msDS-LockoutObservationWindow")),
                lockout_duration_seconds=interval_to_seconds(entry.get_int("msDS-LockoutDuration")),
                min_pwd_length=entry.get_int("msDS-MinimumPasswordLength"),
                pwd_history_length=entry.get_int("msDS-PasswordHistoryLength"),
                max_pwd_age_days=interval_to_seconds(entry.get_int("msDS-MaximumPasswordAge")) // 86400,
                min_pwd_age_days=interval_to_seconds(entry.get_int("msDS-MinimumPasswordAge")) // 86400,
                complexity_enabled=entry.get_bool("msDS-PasswordComplexityEnabled"),
            )
            for entry in entries
        ]

    def enabled_users(self) -> list[LdapEntry]:
        """Enabled user accounts, with their resultant PSO and lockout attributes."""
        return self.search(
            self.base_dn,
            ENABLED_USERS_FILTER,
            ["sAMAccountName", "msDS-ResultantPSO", *LOCKOUT_ATTRIBUTES],
            paged=True,
        )

    def read_user_state(self, dn: str) -> LockoutState | None:
        """
        Read the lockout state of an account, reconnecting once if the connection dropped.

        Returns:
            The lockout state, None if the account no longer exists
        """
        try:
            entry = self.read(dn, LOCKOUT_ATTRIBUTES)
        except ldap.LDAPSearchError:
            raise
        except Exception as e:
            debug(f"LDAP read failed on {self.host} ({type(e).__name__} {e}), reconnecting")
            self.connect()
            entry = self.read(dn, LOCKOUT_ATTRIBUTES)
        return parse_lockout_state(entry) if entry else None

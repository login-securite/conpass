import socket
import ssl

from ldap3 import ALL, BASE, NONE, NTLM, SUBTREE, TLS_CHANNEL_BINDING, Connection, Server, Tls
from ldap3.core.exceptions import LDAPBindError, LDAPException
from rich.console import Console

from conpass.exceptions import LdapConnectionError
from conpass.models import Credentials, LockoutState, PasswordPolicy
from conpass.utils import filetime_to_datetime, find_pdc_hostname, format_hash_for_ldap, parse_hashes, resolve_hostname

UF_ACCOUNTDISABLE = 0x2
UF_LOCKOUT = 0x10

LOCKOUT_ATTRIBUTES = [
    'badPwdCount',
    'badPasswordTime',
    'lockoutTime',
    'pwdLastSet',
    'userAccountControl',
    'msDS-User-Account-Control-Computed',
]


def raw_attributes(response_entry: dict) -> dict[str, list[bytes]]:
    """Raw attribute values of a search result entry, keyed by lowercase name."""
    return {k.lower(): v for k, v in response_entry.get('raw_attributes', {}).items()}


def raw_int(raw: dict[str, list[bytes]], attribute: str) -> int:
    values = raw.get(attribute.lower())
    return int(values[0]) if values else 0


def raw_str(raw: dict[str, list[bytes]], attribute: str) -> str | None:
    values = raw.get(attribute.lower())
    return values[0].decode('utf-8', errors='replace') if values else None


def parse_lockout_state(raw: dict[str, list[bytes]]) -> LockoutState:
    """
    Build a LockoutState from raw attributes.

    Raw values are parsed directly so that no schema is needed and badPasswordTime
    keeps its exact FILETIME value.
    """
    bad_pwd_filetime = raw_int(raw, 'badPasswordTime')
    return LockoutState(
        bad_pwd_count=raw_int(raw, 'badPwdCount'),
        bad_pwd_filetime=bad_pwd_filetime,
        bad_pwd_time=filetime_to_datetime(bad_pwd_filetime),
        lockout_time=filetime_to_datetime(raw_int(raw, 'lockoutTime')),
        locked=bool(raw_int(raw, 'msDS-User-Account-Control-Computed') & UF_LOCKOUT),
        pwd_last_set=filetime_to_datetime(raw_int(raw, 'pwdLastSet')),
        disabled=bool(raw_int(raw, 'userAccountControl') & UF_ACCOUNTDISABLE),
    )


class LdapService:
    """Service for LDAP operations (connection, queries, policy retrieval)."""

    def __init__(
        self,
        credentials: Credentials,
        base_dn: str,
        dc_ip: str,
        use_ssl: bool = False,
        page_size: int = 1000,
        timeout: int = 3,
        dns_ip: str | None = None,
        console: Console | None = None,
        debug: bool = False,
        fetch_schema: bool = True,
    ):
        self.credentials = credentials
        self.base_dn = base_dn
        self.dc_ip = dc_ip
        self.use_ssl = use_ssl
        self.page_size = page_size
        self.timeout = timeout
        # Fall back to the target DC as DNS server: a DC is almost always a DNS
        # server for its domain, and the system resolver usually cannot resolve
        # the domain FQDNs needed for DC/PDC discovery.
        self.dns_ip = dns_ip if dns_ip else dc_ip
        self.console = console
        self.debug = debug
        # The schema is only needed to format policy attributes; workers only read
        # raw values, so they skip downloading it.
        self.fetch_schema = fetch_schema

        self._connection: Connection | None = None
        self._can_read_psos = False

    def _debug(self, message: str) -> None:
        if self.debug and self.console:
            self.console.print(f"[cyan][DEBUG] {message}[/cyan]")

    def connect(self) -> None:
        """
        Connect to the configured domain controller.

        Raises:
            LdapConnectionError: If unable to connect
        """
        self._debug(f"Connecting to {self.dc_ip} via LDAP (timeout={self.timeout}s)")
        self._connection = self._create_connection(self.dc_ip)
        if not self._connection:
            raise LdapConnectionError(f"Could not connect to {self.dc_ip} via LDAP")

    def close(self) -> None:
        if self._connection:
            try:
                self._connection.unbind()
            except Exception:
                pass
        self._connection = None

    def _create_ldap_server(self, dc_ip: str, use_ssl: bool) -> Server:
        """Create an LDAP server object."""
        get_info = ALL if self.fetch_schema else NONE
        if use_ssl:
            tls = Tls(validate=ssl.CERT_NONE)
            return Server(dc_ip, use_ssl=True, tls=tls, get_info=get_info, connect_timeout=self.timeout)
        return Server(dc_ip, get_info=get_info, connect_timeout=self.timeout)

    def _bind_password(self) -> str:
        if self.credentials.has_hash:
            lm_hash, nt_hash = parse_hashes(self.credentials.hashes)
            return format_hash_for_ldap(lm_hash, nt_hash)
        return self.credentials.password

    def _create_connection(self, dc_ip: str) -> Connection | None:
        """
        Create a connection to a domain controller.

        First tries with SSL and channel binding, falls back to no SSL if needed.
        Supports both password and NT hash authentication.

        Returns:
            Connection object if successful, None otherwise
        """
        password = self._bind_password()
        try:
            try:
                self._debug(f"Trying SSL connection with channel binding to {dc_ip}")
                conn = Connection(
                    self._create_ldap_server(dc_ip, True),
                    user=self.credentials.user_principal,
                    password=password,
                    authentication=NTLM,
                    auto_referrals=False,
                    channel_binding=TLS_CHANNEL_BINDING,
                    receive_timeout=self.timeout,
                )
                if not conn.bind():
                    raise LDAPBindError("Channel binding failed")
                return conn
            except (ssl.SSLError, socket.error, LDAPBindError) as e:
                self._debug(f"SSL failed for {dc_ip} ({type(e).__name__}), trying non-SSL")
                conn = Connection(
                    self._create_ldap_server(dc_ip, False),
                    user=self.credentials.user_principal,
                    password=password,
                    authentication=NTLM,
                    auto_referrals=False,
                    receive_timeout=self.timeout,
                )
                return conn if conn.bind() else None
        except Exception as e:
            self._debug(f"Connection failed to {dc_ip}: {type(e).__name__}")
            return None

    def find_pdc_emulator(self) -> tuple[str | None, str | None]:
        """
        Find the Domain Controller holding the PDC Emulator FSMO role.

        Reads fSMORoleOwner on the domain naming context root: it points to the NTDS
        Settings object of the role owner, whose parent server object carries the
        dNSHostName. Falls back to the _ldap._tcp.pdc._msdcs DNS SRV record.

        Returns:
            (fqdn, ip), or (None, None) if the PDC could not be identified
        """
        pdc_fqdn = None
        try:
            pdc_fqdn = self._find_pdc_fqdn_ldap()
        except Exception as e:
            self._debug(f"Error finding PDC Emulator via LDAP ({type(e).__name__}: {e})")

        if not pdc_fqdn:
            domain = '.'.join(part.split('=')[1] for part in self.base_dn.split(','))
            pdc_fqdn = find_pdc_hostname(domain, self.dns_ip)
            self._debug(f"PDC Emulator from DNS SRV record: {pdc_fqdn}")

        if not pdc_fqdn:
            return None, None
        try:
            pdc_ip = resolve_hostname(pdc_fqdn, self.dns_ip)
        except socket.gaierror as e:
            self._debug(f"Could not resolve PDC Emulator {pdc_fqdn}: {e}")
            return pdc_fqdn, None
        self._debug(f"PDC Emulator: {pdc_fqdn} -> {pdc_ip}")
        return pdc_fqdn, pdc_ip

    def _find_pdc_fqdn_ldap(self) -> str | None:
        conn = self._connection
        conn.search(self.base_dn, "(objectClass=domainDNS)", search_scope=BASE, attributes=['fSMORoleOwner'])
        if not conn.entries or not conn.entries[0].fSMORoleOwner:
            return None
        owner_dn = conn.entries[0].fSMORoleOwner.value
        self._debug(f"PDC fSMORoleOwner DN: {owner_dn}")

        # owner_dn = CN=NTDS Settings,CN=<SERVER>,CN=Servers,CN=<SITE>,...
        server_dn = ','.join(owner_dn.split(',')[1:])
        conn.search(server_dn, "(objectClass=server)", search_scope=BASE, attributes=['dNSHostName'])
        if conn.entries and conn.entries[0].dNSHostName:
            return conn.entries[0].dNSHostName.value
        return None

    def get_dc_ips(self) -> list[str]:
        """Discover all domain controller IPs (connected DC first)."""
        dc_ips = [self.dc_ip]
        self._connection.search(
            self.base_dn,
            "(userAccountControl:1.2.840.113556.1.4.803:=8192)",
            search_scope=SUBTREE,
            attributes=['dNSHostName'],
        )
        for entry in self._connection.entries:
            dns_name = entry.dNSHostName.value
            if not dns_name:
                continue
            try:
                ip_address = resolve_hostname(dns_name, self.dns_ip)
            except socket.gaierror:
                continue
            if ip_address not in dc_ips:
                dc_ips.append(ip_address)
        return dc_ips

    def get_default_domain_policy(self) -> PasswordPolicy:
        """
        Retrieve the default domain password policy.

        Returns:
            PasswordPolicy object with default domain policy
        """
        conn = self._connection
        attributes = [
            'lockoutThreshold', 'lockoutDuration', 'lockOutObservationWindow',
            'minPwdLength', 'pwdHistoryLength', 'maxPwdAge', 'minPwdAge', 'pwdProperties'
        ]
        conn.search(self.base_dn, "(objectClass=domain)", search_scope=BASE, attributes=attributes)

        if not conn.entries:
            domain_name = '.'.join([part.split('=')[1] for part in self.base_dn.split(',') if part.startswith('dc=')])
            raise LdapConnectionError(
                f"Could not find domain object at '{self.base_dn}'. "
                f"This usually means:\n"
                f"  - The domain name provided (-d {domain_name}) is incorrect\n"
                f"  - Your credentials belong to a different domain\n"
                f"  - You don't have permission to read the domain object"
            )

        entry = conn.entries[0]

        def seconds(attribute) -> int:
            return int(abs(attribute.value.total_seconds())) if attribute else 0

        pwd_properties = entry.pwdProperties.value if entry.pwdProperties else 0
        return PasswordPolicy(
            name='Default Domain Policy',
            lockout_threshold=entry.lockoutThreshold.value if entry.lockoutThreshold else 0,
            lockout_window_seconds=seconds(entry.lockOutObservationWindow),
            lockout_duration_seconds=seconds(entry.lockoutDuration),
            min_pwd_length=entry.minPwdLength.value if entry.minPwdLength else 0,
            pwd_history_length=entry.pwdHistoryLength.value if entry.pwdHistoryLength else 0,
            max_pwd_age_days=seconds(entry.maxPwdAge) // 86400,
            min_pwd_age_days=seconds(entry.minPwdAge) // 86400,
            complexity_enabled=bool(pwd_properties & 0x1),  # DOMAIN_PASSWORD_COMPLEX
        )

    def get_password_setting_objects(self) -> list[PasswordPolicy]:
        """
        Retrieve all Password Settings Objects (PSOs).

        Returns:
            List of PasswordPolicy objects for each PSO
        """
        conn = self._connection
        pso_base_dn = f"CN=Password Settings Container,CN=System,{self.base_dn}"
        pso_attributes = [
            'name', 'msDS-LockoutThreshold', 'msDS-LockoutObservationWindow', 'msDS-LockoutDuration',
            'msDS-MinimumPasswordLength', 'msDS-PasswordHistoryLength',
            'msDS-MaximumPasswordAge', 'msDS-MinimumPasswordAge', 'msDS-PasswordComplexityEnabled'
        ]

        try:
            if not conn.search(pso_base_dn, "(objectClass=msDS-PasswordSettings)", attributes=pso_attributes):
                return []
        except Exception:
            return []

        self._can_read_psos = True
        if len(conn.entries) == 0:
            if self.console:
                self.console.print(
                    "[yellow]No PSO readable: either none exists, or this account cannot read them "
                    "(users under a PSO are then skipped when msDS-ResultantPSO is visible).[/yellow]"
                )
            return []

        def value(entry, attribute, default=0):
            return entry[attribute].value if entry[attribute] else default

        def seconds(entry, attribute) -> int:
            # PSO time attributes are negative FILETIME intervals (int)
            return int(-(value(entry, attribute) / 10000000))

        return [
            PasswordPolicy(
                name=entry.name.value if entry.name else "Unknown",
                lockout_threshold=value(entry, 'msDS-LockoutThreshold'),
                lockout_window_seconds=seconds(entry, 'msDS-LockoutObservationWindow'),
                lockout_duration_seconds=seconds(entry, 'msDS-LockoutDuration'),
                min_pwd_length=value(entry, 'msDS-MinimumPasswordLength'),
                pwd_history_length=value(entry, 'msDS-PasswordHistoryLength'),
                max_pwd_age_days=seconds(entry, 'msDS-MaximumPasswordAge') // 86400,
                min_pwd_age_days=seconds(entry, 'msDS-MinimumPasswordAge') // 86400,
                complexity_enabled=value(entry, 'msDS-PasswordComplexityEnabled', False),
            )
            for entry in conn.entries
        ]

    def can_read_pso(self) -> bool:
        """Check if we have permission to read PSO details."""
        return self._can_read_psos

    def search_users(self, search_filter: str, attributes: list[str]) -> list[dict]:
        """
        Paged search on the connected DC.

        Returns:
            List of search result entries (dicts with 'dn' and 'raw_attributes')
        """
        from rich.progress import Progress, SpinnerColumn, TextColumn

        entries = []
        cookie = None
        conn = self._connection

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=self.console,
            transient=True,
            disable=self.console is None,
        ) as progress:
            task = progress.add_task("Loading users from LDAP...", total=None)
            while True:
                conn.search(
                    self.base_dn,
                    search_filter,
                    attributes=attributes,
                    paged_size=self.page_size,
                    paged_cookie=cookie
                )
                entries.extend(e for e in conn.response if e.get('type') == 'searchResEntry')
                progress.update(task, description=f"Loading users from LDAP... {len(entries)} loaded")

                cookie = conn.result['controls']['1.2.840.113556.1.4.319']['value']['cookie']
                if not cookie:
                    break

        if self.console:
            self.console.print(f"[green]✓ Loaded {len(entries)} enabled users from LDAP")

        return entries

    def read_user_state(self, dn: str) -> LockoutState | None:
        """
        Read the lockout state of a user with a single BASE search.

        Returns:
            LockoutState, or None if the object could not be read
        """
        for attempt in range(2):
            try:
                self._connection.search(dn, "(objectClass=*)", search_scope=BASE, attributes=LOCKOUT_ATTRIBUTES)
                break
            except LDAPException:
                if attempt:
                    raise
                self.connect()

        for entry in self._connection.response:
            if entry.get('type') == 'searchResEntry':
                return parse_lockout_state(raw_attributes(entry))
        return None

    def get_user_status_per_dc(self, dn: str) -> list[dict]:
        """
        Read badPwdCount, badPasswordTime and lockoutTime of a user on every DC.

        Debug helper: these attributes are not replicated, each DC has its own view.
        """
        results = []
        for dc_ip in self.get_dc_ips():
            dc_service = LdapService(
                self.credentials, self.base_dn, dc_ip, self.use_ssl,
                timeout=self.timeout, dns_ip=self.dns_ip, fetch_schema=False,
            )
            try:
                dc_service.connect()
                state = dc_service.read_user_state(dn)
            except Exception:
                continue
            finally:
                dc_service.close()
            if state:
                results.append({'dc_ip': dc_ip, 'state': state})
        return results

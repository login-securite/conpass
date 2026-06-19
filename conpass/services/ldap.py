import socket
import ssl
from datetime import datetime, timezone

from ldap3 import ALL, NTLM, Connection, Server, SUBTREE, BASE, Tls, TLS_CHANNEL_BINDING
from ldap3.core.exceptions import LDAPBindError, LDAPSocketReceiveError
from rich.console import Console

from conpass.exceptions import LdapConnectionError, PdcNotFoundError
from conpass.models import Credentials, PasswordPolicy
from conpass.utils import resolve_hostname, parse_hashes, format_hash_for_ldap


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
        debug: bool = False
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

        self._connections: list[Connection] = []
        self._all_dc_ips: list[str] = []
        self._can_read_psos = False
        self._pdc_dc_ip: str | None = None
        self._pdc_discovered: bool = False
        self._pdc_fqdn: str | None = None

    def connect(self) -> None:
        """
        Connect to the PDC Emulator domain controller only.

        Raises:
            LdapConnectionError: If unable to connect to any DC
        """
        from rich.progress import Progress, TextColumn, BarColumn, MofNCompleteColumn

        if not self._all_dc_ips:
            if self.debug and self.console:
                self.console.print(f"[cyan][DEBUG] Discovering domain controllers from {self.dc_ip}[/cyan]")
            self._discover_domain_controllers()
            if self.debug and self.console:
                self.console.print(f"[cyan][DEBUG] Discovered {len(self._all_dc_ips)} DC(s): {', '.join(self._all_dc_ips)}[/cyan]")

        # Find PDC Emulator and use only that DC
        self._pdc_dc_ip = self._find_pdc_emulator()
        if self._pdc_dc_ip:
            if self._pdc_discovered:
                if self.console:
                    label = f"{self._pdc_fqdn} ({self._pdc_dc_ip})" if self._pdc_fqdn else self._pdc_dc_ip
                    self.console.print(f"[green]PDC Emulator identified: {label}[/green]")
            else:
                # Fell back to the provided DC: the PDC Emulator could not be
                # identified, so badPwdCount may not be the authoritative value
                # and the lockout risk is higher. Let the user decide whether to go on.
                if self.console:
                    self.console.print(
                        f"[yellow]Warning: could not identify the PDC Emulator, falling back to {self._pdc_dc_ip}. "
                        f"badPwdCount may be out of sync with the PDC, increasing the risk of account lockout.[/yellow]"
                    )
                if not self._confirm_continue_without_pdc():
                    raise PdcNotFoundError(
                        "Aborted: PDC Emulator could not be identified and the user chose not to continue."
                    )
            # Filter to only the PDC DC
            pdc_ip = self._pdc_dc_ip
            if pdc_ip not in self._all_dc_ips:
                if self.debug and self.console:
                    self.console.print(f"[cyan][DEBUG] PDC Emulator ({pdc_ip}) not in discovered DCs, using it anyway[/cyan]")
                self._all_dc_ips = [pdc_ip]
            else:
                # Move PDC to first position
                self._all_dc_ips = [pdc_ip] + [ip for ip in self._all_dc_ips if ip != pdc_ip]
        else:
            # PDC not found - raise to exit the tool
            raise PdcNotFoundError(
                f"PDC Emulator FSMO role holder not found. "
                f"Cannot proceed without the PDC Emulator."
            )

        # Use progress bar if console is available
        if self.console:
            with Progress(
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                MofNCompleteColumn(),
                console=self.console,
                transient=True
            ) as progress:
                task = progress.add_task("Connecting to PDC...", total=len(self._all_dc_ips))

                for dc_ip in self._all_dc_ips:
                    if self.debug:
                        self.console.print(f"[cyan][DEBUG] Attempting connection to DC: {dc_ip} (timeout={self.timeout}s)[/cyan]")
                    conn = self._create_connection(dc_ip)
                    if conn and self.debug:
                        self.console.print(f"[cyan][DEBUG] Successfully connected to DC: {dc_ip}[/cyan]")
                    elif not conn and self.debug:
                        self.console.print(f"[cyan][DEBUG] Failed to connect to DC: {dc_ip}[/cyan]")
                    self._connections.append(conn)
                    progress.update(task, advance=1)
        else:
            # No console - connect without progress bar
            for dc_ip in self._all_dc_ips:
                conn = self._create_connection(dc_ip)
                self._connections.append(conn)

        # Check if we have at least one successful connection
        if not any(self._connections):
            raise LdapConnectionError("Could not connect to the PDC Emulator")

        # Filter out failed connections
        if not all(self._connections):
            failed_dcs = [
                dc_ip for dc_ip, conn in zip(self._all_dc_ips, self._connections) if not conn
            ]
            if self.console:
                self.console.print(
                    f"[yellow]Could not bind to some Domain Controllers (Failed for {', '.join(failed_dcs)})[/yellow]"
                )
            self._all_dc_ips = [dc_ip for dc_ip, conn in zip(self._all_dc_ips, self._connections) if conn]
            self._connections = [conn for conn in self._connections if conn]

    def _confirm_continue_without_pdc(self) -> bool:
        """
        Ask the user whether to continue when the PDC Emulator could not be identified.

        Returns True to continue (or when no console is available to prompt),
        False if the user declines.
        """
        if not self.console:
            return True
        from rich.prompt import Confirm
        return Confirm.ask(
            "[yellow]Continue anyway despite the higher lockout risk?[/yellow]",
            console=self.console,
            default=False,
        )

    def _create_ldap_server(self, dc_ip: str, use_ssl: bool) -> Server:
        """Create an LDAP server object."""
        if use_ssl:
            tls = Tls(validate=ssl.CERT_NONE)
            return Server(dc_ip, use_ssl=True, tls=tls, get_info=ALL, connect_timeout=self.timeout)
        return Server(dc_ip, get_info=ALL, connect_timeout=self.timeout)

    def _create_connection(self, dc_ip: str) -> Connection | None:
        """
        Create a connection to a domain controller.

        First tries with SSL and channel binding, falls back to no SSL if needed.
        Supports both password and NT hash authentication.

        Returns:
            Connection object if successful, None otherwise
        """
        # Determine the password to use (cleartext or hash)
        if self.credentials.has_hash:
            # Parse and format hash for LDAP3
            lm_hash, nt_hash = parse_hashes(self.credentials.hashes)
            password = format_hash_for_ldap(lm_hash, nt_hash)
        else:
            password = self.credentials.password

        try:
            # Try with SSL and channel binding first
            try:
                if self.debug and self.console:
                    self.console.print(f"[cyan][DEBUG] Trying SSL connection with channel binding to {dc_ip}[/cyan]")
                server = self._create_ldap_server(dc_ip, True)
                conn = Connection(
                    server,
                    user=self.credentials.user_principal,
                    password=password,
                    authentication=NTLM,
                    auto_referrals=False,
                    channel_binding=TLS_CHANNEL_BINDING,
                    receive_timeout=self.timeout,
                )
                if not conn.bind():
                    raise LDAPBindError("Channel binding failed")
                if self.debug and self.console:
                    self.console.print(f"[cyan][DEBUG] SSL connection successful to {dc_ip}[/cyan]")
                return conn
            except (ssl.SSLError, socket.error, LDAPBindError) as e:
                # Fall back to non-SSL
                if self.debug and self.console:
                    self.console.print(f"[cyan][DEBUG] SSL failed for {dc_ip} ({type(e).__name__}), trying non-SSL[/cyan]")
                server = self._create_ldap_server(dc_ip, False)
                conn = Connection(
                    server,
                    user=self.credentials.user_principal,
                    password=password,
                    authentication=NTLM,
                    receive_timeout=self.timeout,
                )
                if conn.bind():
                    if self.debug and self.console:
                        self.console.print(f"[cyan][DEBUG] Non-SSL connection successful to {dc_ip}[/cyan]")
                    return conn
                return None
        except Exception as e:
            if self.debug and self.console:
                self.console.print(f"[cyan][DEBUG] Connection failed to {dc_ip}: {type(e).__name__}[/cyan]")
            return None

    def _find_pdc_emulator(self) -> str | None:
        """
        Find the IP address of the Domain Controller holding the PDC Emulator FSMO role.

        Reads the fSMORoleOwner attribute on the domain naming context root. That DN
        points to the NTDS Settings object of the role owner; its parent is the server
        object, whose dNSHostName is resolved to an IP.

        Returns:
            PDC Emulator IP address string, or the provided DC IP as a fallback.
            None only if no connection could be established.
        """
        conn = self._create_connection(self.dc_ip)
        if not conn:
            if self.debug and self.console:
                self.console.print("[yellow][DEBUG] Could not create connection for PDC detection[/yellow]")
            return None

        try:
            conn.search(
                search_base=self.base_dn,
                search_filter="(objectClass=domainDNS)",
                search_scope=BASE,
                attributes=['fSMORoleOwner']
            )

            owner_dn = None
            if conn.entries and conn.entries[0].fSMORoleOwner:
                owner_dn = conn.entries[0].fSMORoleOwner.value

            if owner_dn:
                if self.debug and self.console:
                    self.console.print(f"[cyan][DEBUG] PDC fSMORoleOwner DN: {owner_dn}[/cyan]")

                # owner_dn = CN=NTDS Settings,CN=<SERVER>,CN=Servers,CN=<SITE>,...
                # The server object is the parent of the NTDS Settings object.
                server_dn = ','.join(owner_dn.split(',')[1:])

                conn.search(
                    search_base=server_dn,
                    search_filter="(objectClass=server)",
                    search_scope=BASE,
                    attributes=['dNSHostName']
                )

                if conn.entries and conn.entries[0].dNSHostName:
                    pdc_fqdn = conn.entries[0].dNSHostName.value
                    pdc_ip = resolve_hostname(pdc_fqdn, self.dns_ip)
                    if self.debug and self.console:
                        self.console.print(f"[cyan][DEBUG] PDC Emulator: {pdc_fqdn} -> {pdc_ip}[/cyan]")
                    self._pdc_discovered = True
                    self._pdc_fqdn = pdc_fqdn
                    return pdc_ip

            # Could not determine the PDC from LDAP: fall back to the provided DC
            if self.debug and self.console:
                self.console.print(
                    f"[yellow][DEBUG] Could not determine PDC Emulator from LDAP, "
                    f"falling back to provided DC {self.dc_ip}[/yellow]"
                )
            return self.dc_ip

        except Exception as e:
            if self.debug and self.console:
                self.console.print(
                    f"[yellow][DEBUG] Error finding PDC Emulator ({type(e).__name__}: {e}), "
                    f"falling back to provided DC {self.dc_ip}[/yellow]"
                )
            return self.dc_ip
        finally:
            try:
                conn.unbind()
            except Exception:
                pass

    def _discover_domain_controllers(self) -> None:
        """Discover all domain controllers via LDAP query."""
        conn = self._create_connection(self.dc_ip)
        if not conn:
            raise LdapConnectionError(f"Could not connect to {self.dc_ip}")

        # Always include the initial DC first (it's the one we can reach)
        self._all_dc_ips.append(self.dc_ip)

        search_filter = "(userAccountControl:1.2.840.113556.1.4.803:=8192)"
        attributes = ['dNSHostName']

        conn.search(
            search_base=self.base_dn,
            search_filter=search_filter,
            search_scope=SUBTREE,
            attributes=attributes
        )

        for entry in conn.entries:
            dns_name = entry.dNSHostName.value
            if dns_name:
                try:
                    ip_address = resolve_hostname(dns_name, self.dns_ip)
                    # Avoid duplicates - don't add if it's the same as the initial DC
                    if ip_address != self.dc_ip and ip_address not in self._all_dc_ips:
                        self._all_dc_ips.append(ip_address)
                except socket.gaierror:
                    pass

        if not self._all_dc_ips:
            raise LdapConnectionError("No domain controllers found")

    def get_dc_ips(self) -> list[str]:
        """Get list of all domain controller IPs."""
        return self._all_dc_ips

    def get_default_domain_policy(self) -> PasswordPolicy:
        """
        Retrieve the default domain password policy.

        Returns:
            PasswordPolicy object with default domain policy
        """
        conn = self._connections[0]
        search_filter = "(objectClass=domain)"
        attributes = [
            'lockoutThreshold', 'lockoutDuration', 'lockOutObservationWindow',
            'minPwdLength', 'pwdHistoryLength', 'maxPwdAge', 'minPwdAge', 'pwdProperties'
        ]

        conn.search(self.base_dn, search_filter, search_scope=BASE, attributes=attributes)

        if not conn.entries:
            # Reconstruct domain name from base_dn for error message
            domain_name = '.'.join([part.split('=')[1] for part in self.base_dn.split(',') if part.startswith('dc=')])
            raise LdapConnectionError(
                f"Could not find domain object at '{self.base_dn}'. "
                f"This usually means:\n"
                f"  - The domain name provided (-d {domain_name}) is incorrect\n"
                f"  - Your credentials belong to a different domain\n"
                f"  - You don't have permission to read the domain object"
            )

        entry = conn.entries[0]

        lockout_threshold = entry.lockoutThreshold.value if entry.lockoutThreshold else 0

        # lockOutObservationWindow is a timedelta
        if entry.lockOutObservationWindow:
            lockout_window = int(abs(entry.lockOutObservationWindow.value.total_seconds()))
        else:
            lockout_window = 0

        # lockoutDuration is a timedelta
        if entry.lockoutDuration:
            lockout_duration = int(abs(entry.lockoutDuration.value.total_seconds()))
        else:
            lockout_duration = 0

        # minPwdLength
        min_pwd_length = entry.minPwdLength.value if entry.minPwdLength else 0

        # pwdHistoryLength
        pwd_history_length = entry.pwdHistoryLength.value if entry.pwdHistoryLength else 0

        # maxPwdAge is a timedelta (convert to days)
        if entry.maxPwdAge:
            max_pwd_age_days = int(abs(entry.maxPwdAge.value.total_seconds()) / 86400)
        else:
            max_pwd_age_days = 0

        # minPwdAge is a timedelta (convert to days)
        if entry.minPwdAge:
            min_pwd_age_days = int(abs(entry.minPwdAge.value.total_seconds()) / 86400)
        else:
            min_pwd_age_days = 0

        # pwdProperties bit flag (DOMAIN_PASSWORD_COMPLEX = 0x1)
        pwd_properties = entry.pwdProperties.value if entry.pwdProperties else 0
        complexity_enabled = bool(pwd_properties & 0x1)

        return PasswordPolicy(
            name='Default Domain Policy',
            lockout_threshold=lockout_threshold,
            lockout_window_seconds=lockout_window,
            lockout_duration_seconds=lockout_duration,
            min_pwd_length=min_pwd_length,
            pwd_history_length=pwd_history_length,
            max_pwd_age_days=max_pwd_age_days,
            min_pwd_age_days=min_pwd_age_days,
            complexity_enabled=complexity_enabled
        )

    def get_password_setting_objects(self) -> list[PasswordPolicy]:
        """
        Retrieve all Password Settings Objects (PSOs).

        Returns:
            List of PasswordPolicy objects for each PSO
        """
        conn = self._connections[0]
        pso_base_dn = f"CN=Password Settings Container,CN=System,{self.base_dn}"
        pso_filter = "(objectClass=msDS-PasswordSettings)"
        pso_attributes = [
            'name', 'msDS-LockoutThreshold', 'msDS-LockoutObservationWindow', 'msDS-LockoutDuration',
            'msDS-MinimumPasswordLength', 'msDS-PasswordHistoryLength',
            'msDS-MaximumPasswordAge', 'msDS-MinimumPasswordAge', 'msDS-PasswordComplexityEnabled'
        ]

        try:
            if not conn.search(pso_base_dn, pso_filter, attributes=pso_attributes):
                return []
        except Exception:
            return []

        self._can_read_psos = True

        if len(conn.entries) == 0:
            if self.console:
                self.console.print("[yellow]No PSO found[/yellow]")
            return []

        psos = []
        for entry in conn.entries:
            lockout_threshold = entry['msDS-LockoutThreshold'].value if entry['msDS-LockoutThreshold'] else 0

            # msDS-LockoutObservationWindow is a FILETIME (int), not timedelta
            if entry['msDS-LockoutObservationWindow']:
                lockout_window = int(-(entry['msDS-LockoutObservationWindow'].value / 10000000))
            else:
                lockout_window = 0

            # msDS-LockoutDuration is a FILETIME (int), not timedelta
            if entry['msDS-LockoutDuration']:
                lockout_duration = int(-(entry['msDS-LockoutDuration'].value / 10000000))
            else:
                lockout_duration = 0

            # msDS-MinimumPasswordLength
            min_pwd_length = entry['msDS-MinimumPasswordLength'].value if entry['msDS-MinimumPasswordLength'] else 0

            # msDS-PasswordHistoryLength
            pwd_history_length = entry['msDS-PasswordHistoryLength'].value if entry['msDS-PasswordHistoryLength'] else 0

            # msDS-MaximumPasswordAge is a FILETIME (convert to days)
            if entry['msDS-MaximumPasswordAge']:
                max_pwd_age_days = int(-(entry['msDS-MaximumPasswordAge'].value / 10000000) / 86400)
            else:
                max_pwd_age_days = 0

            # msDS-MinimumPasswordAge is a FILETIME (convert to days)
            if entry['msDS-MinimumPasswordAge']:
                min_pwd_age_days = int(-(entry['msDS-MinimumPasswordAge'].value / 10000000) / 86400)
            else:
                min_pwd_age_days = 0

            # msDS-PasswordComplexityEnabled is a boolean
            complexity_enabled = entry['msDS-PasswordComplexityEnabled'].value if entry['msDS-PasswordComplexityEnabled'] else False

            psos.append(PasswordPolicy(
                name=entry.name.value if entry.name else "Unknown",
                lockout_threshold=lockout_threshold,
                lockout_window_seconds=lockout_window,
                lockout_duration_seconds=lockout_duration,
                min_pwd_length=min_pwd_length,
                pwd_history_length=pwd_history_length,
                max_pwd_age_days=max_pwd_age_days,
                min_pwd_age_days=min_pwd_age_days,
                complexity_enabled=complexity_enabled
            ))

        return psos

    def can_read_pso(self) -> bool:
        """Check if we have permission to read PSO details."""
        return self._can_read_psos

    def search_users(self, search_filter: str, attributes: list[str]) -> list:
        """
        Search for users on the PDC Emulator DC only.

        Args:
            search_filter: LDAP search filter
            attributes: List of attributes to retrieve

        Returns:
            List of LDAP entries from the PDC Emulator
        """
        from rich.progress import Progress, SpinnerColumn, TextColumn

        entries = []
        cookie = None

        # Only use the first connection (PDC Emulator)
        conn = self._connections[0]

        # Use spinner to show progress if console available
        if self.console:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=self.console,
                transient=True
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

                    for entry in conn.entries:
                        entries.append(entry)

                    # Update progress
                    progress.update(task, description=f"Loading users from LDAP... {len(entries)} loaded")

                    cookie = conn.result['controls']['1.2.840.113556.1.4.319']['value']['cookie']
                    if not cookie:
                        break
        else:
            # No console - load without progress display
            while True:
                conn.search(
                    self.base_dn,
                    search_filter,
                    attributes=attributes,
                    paged_size=self.page_size,
                    paged_cookie=cookie
                )

                for entry in conn.entries:
                    entries.append(entry)

                cookie = conn.result['controls']['1.2.840.113556.1.4.319']['value']['cookie']
                if not cookie:
                    break

        if self.console:
            self.console.print(f"[green]✓ Loaded {len(entries)} users from LDAP")

        return entries

    def get_user_password_status(self, samaccountname: str) -> tuple[int, datetime, datetime]:
        """
        Get user's bad password count, time, and lockout time from all DCs (returns max).

        Args:
            samaccountname: User's SAM account name

        Returns:
            Tuple of (bad_password_count, bad_password_time, lockout_time)
        """
        search_filter = f"(&(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(sAMAccountName={samaccountname}))"
        attributes = ['samAccountName', 'badPwdCount', 'badPasswordTime', 'lockoutTime']

        entries = self.search_users(search_filter, attributes)

        if not entries:
            epoch = datetime(1970, 1, 1, tzinfo=timezone.utc)
            return (0, epoch, epoch)

        entry = entries[0]
        bad_password_count = entry.badPwdCount.value if entry.badPwdCount.value is not None else 0
        bad_password_time = entry.badPasswordTime.value if entry.badPasswordTime.value else datetime(1970, 1, 1, tzinfo=timezone.utc)
        lockout_time = entry.lockoutTime.value if entry.lockoutTime and entry.lockoutTime.value else datetime(1970, 1, 1, tzinfo=timezone.utc)

        return (bad_password_count, bad_password_time, lockout_time)

    def get_user_password_status_per_dc(self, samaccountname: str) -> list[dict]:
        """
        Get user's bad password count, lockout time, and bad password time from each DC individually.

        Args:
            samaccountname: User's SAM account name

        Returns:
            List of dicts with keys: dc_ip, bad_pwd_count, bad_pwd_time, lockout_time
        """
        search_filter = f"(&(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(sAMAccountName={samaccountname}))"
        attributes = ['samAccountName', 'badPwdCount', 'badPasswordTime', 'lockoutTime']

        results = []
        for dc_ip, conn in zip(self._all_dc_ips, self._connections):
            if not conn:
                continue

            try:
                conn.search(
                    self.base_dn,
                    search_filter,
                    attributes=attributes,
                    search_scope=SUBTREE
                )

                if conn.entries:
                    entry = conn.entries[0]
                    bad_pwd_count = entry.badPwdCount.value if entry.badPwdCount.value is not None else 0
                    bad_pwd_time = entry.badPasswordTime.value if entry.badPasswordTime.value else datetime(1970, 1, 1, tzinfo=timezone.utc)
                    lockout_time = entry.lockoutTime.value if entry.lockoutTime and entry.lockoutTime.value else datetime(1970, 1, 1, tzinfo=timezone.utc)

                    results.append({
                        'dc_ip': dc_ip,
                        'bad_pwd_count': bad_pwd_count,
                        'bad_pwd_time': bad_pwd_time,
                        'lockout_time': lockout_time
                    })
            except Exception:
                # If query fails on this DC, skip it
                continue

        return results


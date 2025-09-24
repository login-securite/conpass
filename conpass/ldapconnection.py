import socket
import ssl
from datetime import datetime, timezone

from ldap3 import ALL, NTLM, Connection, Server, SUBTREE, Tls, TLS_CHANNEL_BINDING
from ldap3.core.exceptions import LDAPBindError

from conpass.passwordpolicy import PasswordPolicy
from conpass.user import User


class LdapConnection:
    def __init__(self, dc_ip, base_dn, domain, username=None, password=None, use_ssl=False, page_size=200, timeout=3, console=None):
        self.__dc_ip = dc_ip
        self.__all_dc_ips = []
        self.__base_dn = base_dn
        self.__domain = domain
        self.__username = username
        self.__password = password
        self.__use_ssl = use_ssl
        self.__console = console
        self.__page_size = page_size
        self.__timeout = timeout
        self.__can_read_psos = False
        self.__conns = []
        self.__users_statistic = {'enabled': 0, 'disabled': 0, 'locked': 0, 'psos': {}}

    
    def create_ldap_server(self, dc_ip, use_ssl):
        if use_ssl:
            tls = Tls(validate=ssl.CERT_NONE)
            return Server(dc_ip, use_ssl=True, tls=tls, get_info=ALL, connect_timeout=self.__timeout)
        return Server(dc_ip, get_info=ALL, connect_timeout=self.__timeout)

    def get_connection(self, dc_ip):
        conn = None
        try:
            try:
                server = self.create_ldap_server(dc_ip, True)
                conn = Connection(
                    server,
                    user=f"{self.__domain}\\{self.__username}",
                    password=self.__password,
                    authentication=NTLM,
                    auto_referrals=False,
                    channel_binding=TLS_CHANNEL_BINDING,
                )
                if not conn.bind():
                    raise LDAPBindError("Channel binding failed")
            except (ssl.SSLError, socket.error, LDAPBindError) as e:
                server = self.create_ldap_server(dc_ip, False)
                conn = Connection(
                    server,
                    user=f"{self.__domain}\\{self.__username}",
                    password=self.__password,
                    authentication=NTLM
                )
                if not conn.bind():
                    return None
        except Exception as e:
            return None
        return conn

    def login(self):
        if len(self.__conns) == 0:
            if len(self.__all_dc_ips) == 0:
                try:
                    self.get_dc_ips()
                except Exception as e:
                    self.__console.print(f"An error occurred while retrieving domain controller IPs: {e!s}")
                    return False
            for dc_ip in self.__all_dc_ips:
                self.__conns.append(self.get_connection(dc_ip))
        
        if not any(self.__conns):
            return False

        if not all(self.__conns):
            self.__console.print(f"Could not bind to all Domain Controllers (Failed for {', '.join(dc_ip for dc_ip, conn in zip(self.__all_dc_ips, self.__conns) if not conn)})")
            self.__all_dc_ips = [dc_ip for dc_ip, conn in zip(self.__all_dc_ips, self.__conns) if conn]
            self.__conns = [conn for conn in self.__conns if conn]
        return True

    def get_dc_ips(self):
        if len(self.__all_dc_ips) > 0:
            return self.__all_dc_ips
        conn = self.get_connection(self.__dc_ip)
        if not conn:
            raise Exception(f"Couldn't bind to {self.__dc_ip}")
        search_base = self.__base_dn
        search_filter = "(userAccountControl:1.2.840.113556.1.4.803:=8192)"
        attributes = [
            'dNSHostName'
        ]

        conn.search(search_base=search_base, search_filter=search_filter, search_scope=SUBTREE, attributes=attributes)
        for entry in conn.entries:
            dns_name = entry.dNSHostName.value
            if dns_name:
                try:
                    ip_address = socket.gethostbyname(dns_name)
                    self.__all_dc_ips.append(ip_address)
                except socket.gaierror as e:
                    pass
        return self.__all_dc_ips

    def get_default_domain_policy(self):
        conn = self.__conns[0]
        search_base = self.__base_dn
        search_filter = "(objectClass=domain)"
        attributes = [
            'lockoutThreshold',
            'lockoutDuration',
            'lockOutObservationWindow'
        ]

        try:
            conn.search(search_base, search_filter, attributes=attributes)
        except Exception as e:
            self.__console.print(f"[red]An error occurred while retrieving default domain policy: {e!s}[/red]")
            self.__console.print_exception()
            raise
        entry = conn.entries[0]
        return PasswordPolicy(
            'Default Domain Policy',
            entry.lockoutThreshold.value if entry.lockoutThreshold else None,
            entry.lockOutObservationWindow.value.total_seconds() if entry.lockOutObservationWindow else None
        )

    def get_psos_details(self):
        conn = self.__conns[0]
        pso_base_dn = f"CN=Password Settings Container,CN=System,{self.__base_dn}"
        pso_filter = "(objectClass=msDS-PasswordSettings)"
        pso_attributes = [
            'name',
            'msDS-LockoutThreshold',
            'msDS-LockoutObservationWindow'
        ]

        try:
            if not conn.search(pso_base_dn, pso_filter, attributes=pso_attributes):
                return False
        except Exception as e:
            self.__console.error(f"[red]An error occurred while retrieving PSO details: {e!s}[/red]")
            return False
        self.__can_read_psos = True

        if len(conn.entries) == 0:
            self.__console.print("No PSO found")
        return [
            PasswordPolicy(
                name=entry.name.value if entry.name else None,
                lockout_window=self.get_window_seconds(entry['msDS-LockoutObservationWindow'].value) if entry['msDS-LockoutObservationWindow'] else None,
                lockout_threshold=entry['msDS-LockoutThreshold'].value if entry['msDS-LockoutThreshold'] else None,
            )
            for entry in conn.entries
        ]

    def can_read_pso(self):
        return self.__can_read_psos

    def search_users(self, search_filter, attributes, page_size=100, custom_processing=None):
        search_base = self.__base_dn
        cookie = None
        entries = []
        for conn in self.__conns:
            try:
                while True:
                    conn.search(
                        search_base,
                        search_filter,
                        attributes=attributes,
                        paged_size=page_size,
                        paged_cookie=cookie
                    )
                    
                    for entry in conn.entries:
                        new_entry = True
                        for key, ex_entry in enumerate(entries):
                            if ex_entry.samAccountName == entry.samAccountName:
                                new_entry = False
                                if ex_entry.badPwdCount.value is None or (entry.badPwdCount.value is not None and ex_entry.badPwdCount.value < entry.badPwdCount.value):
                                    entries[key] = entry
                                break
                        if new_entry:
                            entries.append(entry)
                    cookie = conn.result['controls']['1.2.840.113556.1.4.319']['value']['cookie']
                    if not cookie:
                        break
            except Exception as e:
                self.__console.print(f"[red]An error occurred during LDAP search: {e!s}[/red]")
                raise

        if custom_processing:
            return [custom_processing(entry) for entry in entries]

        return entries

    def get_user_password_status(self, samaccountname):
        search_filter = f"(&(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(sAMAccountName={samaccountname}))"
        attributes = ['samAccountName', 'badPwdCount', 'badPasswordTime']

        def process_entry(entry):
            return (
                entry.badPwdCount.value,
                entry.badPasswordTime.value if entry.badPasswordTime.value is not None else datetime(1970, 1, 1,
                                                                                                     tzinfo=timezone.utc)
            )

        results = self.search_users(search_filter, attributes, page_size=100, custom_processing=process_entry)
        return results[0] if results else None

    def get_active_users(self, psos, domain_policy, time_delta, security_threshold, file_users):
        search_filter = "(&(objectClass=user)(!(sAMAccountName=*$)))"
        attributes = [
            'samAccountName',
            'badPwdCount',
            'badPasswordTime',
            'distinguishedName',
            'msDS-ResultantPSO',
            'userAccountControl'
        ]

        def process_entry(entry):
            # Check if entry is an enabled or disabled account
            if entry.userAccountControl.value & 2:
                self.__users_statistic['disabled'] += 1
                return None

            self.__users_statistic['enabled'] += 1

            # Check if entry is locked
            if entry.userAccountControl.value & 16:
                self.__users_statistic['locked'] += 1
                return None

            # Add 1 to this user's PSO count if it has one but don't process the user if the user has a PSO and the tool can't read PSOs
            if entry['msDS-ResultantPSO']:
                pso_name = entry['msDS-ResultantPSO'].value.split(',')[0][3:]
                if pso_name in self.__users_statistic['psos']:
                    self.__users_statistic['psos'][pso_name] += 1
                else:
                    self.__users_statistic['psos'][pso_name] = 1
                if not self.__can_read_psos:
                    return None

            # Check if the user is the one running the tool
            if entry.samAccountName.value.lower() == self.__username.lower():
                return None

            # Check if the user is in the file  (if the file is provided)
            if len(file_users) > 0 and entry.samAccountName.value not in file_users:
                return None

            # Check if the user has a PSO and get its lockout threshold and lockout window
            if entry['msDS-ResultantPSO']:
                pso_name = entry['msDS-ResultantPSO'].value.split(',')[0][3:]
                pso = self.get_pso(pso_name, psos) if self.__can_read_psos else None
                lockout_threshold = pso.lockout_threshold if pso else domain_policy.lockout_threshold
                lockout_window = pso.lockout_window if pso else domain_policy.lockout_window
            else:
                pso = None
                lockout_threshold = domain_policy.lockout_threshold
                lockout_window = domain_policy.lockout_window

            # Check if the lockout threshold is lower than the security threshold
            if 0 < lockout_threshold <= security_threshold:
                self.__console.print(
                    f"{entry.samAccountName.value} is discarded: Lockout threshold ({lockout_threshold}) is lower than security threshold ({security_threshold})")
                return None

            return User(
                samaccountname=entry.samAccountName.value,
                dn=entry.distinguishedName.value,
                bad_password_time=entry.badPasswordTime.value if entry.badPasswordTime.value is not None else datetime(
                    1970, 1, 1, tzinfo=timezone.utc),
                bad_password_count=entry.badPwdCount.value,
                lockout_window=lockout_window,
                lockout_threshold=lockout_threshold,
                pso=pso,
                time_delta=time_delta,
                security_threshold=security_threshold,
                console=self.__console
            )

        results = self.search_users(search_filter, attributes, page_size=1000, custom_processing=process_entry)
        return [user for user in results if user]

    def get_pso(self, name, psos):
        for pso in psos:
            if pso.name == name:
                return pso
        self.__console.print(f"[yellow]PSO [blue]{name}[/blue] details couldn't be found")
        return None

    def get_enabled_users(self):
        return self.__users_statistic['enabled']

    def get_disabled_users(self):
        return self.__users_statistic['disabled']

    def get_locked_users(self):
        return self.__users_statistic['locked']

    def get_pso_users(self):
        return self.__users_statistic['psos']

    @staticmethod
    def get_window_seconds(t):
        return -(t / 10000000)

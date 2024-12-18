from datetime import datetime, timezone

from ldap3 import ALL, NTLM, Connection, Server

from conpass.passwordpolicy import PasswordPolicy
from conpass.user import User


class LdapConnection:
    def __init__(self, dc_ips, base_dn, domain, username=None, password=None, use_ssl=False, page_size=200, console=None):
        self.__dc_ips = dc_ips
        self.__base_dn = base_dn
        self.__domain = domain
        self.__username = username
        self.__password = password
        self.__use_ssl = use_ssl
        self.__console = console
        self.__page_size = page_size
        self.__can_read_psos = False
        self.__conns = []

    def get_connection(self):
        for dc_ip in self.__dc_ips:
            if not self.__use_ssl:
                server = Server(dc_ip, get_info=ALL)
            else:
                server = Server(dc_ip, port=636, use_ssl=True, get_info=ALL)
            self.__conns.append(Connection(
                server,
                user=f"{self.__domain}\\{self.__username}",
                password=self.__password,
                authentication=NTLM
            ))
        return self

    def login(self):
        if len(self.__conns) == 0:
            self.get_connection()
        return all(conn.bind() for conn in self.__conns)

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
                                if ex_entry.badPwdCount.value < entry.badPwdCount.value:
                                    entries[key] = entry
                                break
                        if new_entry:
                            entries.append(entry)
                        #entries
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
        search_filter = "(&(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(!(sAMAccountName=*$)))"
        attributes = [
            'samAccountName',
            'badPwdCount',
            'badPasswordTime',
            'distinguishedName',
            'msDS-ResultantPSO'
        ]

        def process_entry(entry):
            if entry.samAccountName.value == self.__username:
                return None

            if len(file_users) > 0 and entry.samAccountName.value not in file_users:
                return None

            if entry['msDS-ResultantPSO']:
                pso_name = entry['msDS-ResultantPSO'].value.split(',')[0][3:]
                pso = self.get_pso(pso_name, psos) if self.__can_read_psos else None
                lockout_threshold = pso.lockout_threshold if pso else domain_policy.lockout_threshold
                lockout_window = pso.lockout_window if pso else domain_policy.lockout_window
            else:
                pso = None
                lockout_threshold = domain_policy.lockout_threshold
                lockout_window = domain_policy.lockout_window

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
        users = [user for user in results if user]
        statistics = {'total_users': len(users), 'pso': {}}  # Ajuster si nécessaire

        return {'users': users, 'stats': statistics}

    def get_pso(self, name, psos):
        for pso in psos:
            if pso.name == name:
                return pso
        self.__console.print(f"[yellow]PSO [blue]{name}[/blue] details couldn't be found")
        return None


    @staticmethod
    def get_window_seconds(t):
        return -(t / 10000000)

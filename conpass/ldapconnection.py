from ldap3 import ALL, NTLM, Connection, Server

from conpass.passwordpolicy import PasswordPolicy
from conpass.user import User


class LdapConnection:
    def __init__(self, dc_ip, base_dn, domain, username=None, password=None, page_size=200, console=None):
        self.__dc_ip = dc_ip
        self.__base_dn = base_dn
        self.__domain = domain
        self.__username = username
        self.__password = password
        self.__console = console
        self.__page_size = page_size
        self.__can_read_psos = False
        self.__conn = None

    def get_connection(self):
        server = Server(self.__dc_ip, get_info=ALL)
        self.__conn = Connection(
            server,
            user=f"{self.__domain}\\{self.__username}",
            password=self.__password,
            authentication=NTLM
        )
        return self

    def login(self):
        if self.__conn is None:
            self.get_connection()
        return self.__conn.bind()

    def get_default_domain_policy(self):
        search_base = self.__base_dn
        search_filter = "(objectClass=domain)"
        attributes = [
            'lockoutThreshold',
            'lockoutDuration',
            'lockOutObservationWindow'
        ]

        try:
            self.__conn.search(search_base, search_filter, attributes=attributes)
        except Exception as e:
            self.__console.print(f"[red]An error occurred while retrieving default domain policy: {e!s}[/red]")
            self.__console.print_exception()
            raise
        entry = self.__conn.entries[0]
        return PasswordPolicy(
            'Default Domain Policy',
            entry.lockoutThreshold.value if entry.lockoutThreshold else None,
            entry.lockOutObservationWindow.value.total_seconds() if entry.lockOutObservationWindow else None
        )

    def get_psos_details(self):
        pso_base_dn = f"CN=Password Settings Container,CN=System,{self.__base_dn}"
        pso_filter = "(objectClass=msDS-PasswordSettings)"
        pso_attributes = [
            'name',
            'msDS-LockoutThreshold',
            'msDS-LockoutObservationWindow'
        ]

        try:
            if not self.__conn.search(pso_base_dn, pso_filter, attributes=pso_attributes):
                return False
        except Exception as e:
            self.__console.error(f"[red]An error occurred while retrieving PSO details: {e!s}[/red]")
            return False
        self.__can_read_psos = True

        if len(self.__conn.entries) == 0:
            self.__console.print("No PSO found")
        return [
            PasswordPolicy(
                name=entry.name.value if entry.name else None,
                lockout_window=self.get_window_seconds(entry['msDS-LockoutObservationWindow'].value) if entry['msDS-LockoutObservationWindow'] else None,
                lockout_threshold=entry['msDS-LockoutThreshold'].value if entry['msDS-LockoutThreshold'] else None,
            )
            for entry in self.__conn.entries
        ]

    def can_read_pso(self):
        return self.__can_read_psos

    def get_user_password_status(self, samaccountname):
        search_base = self.__base_dn
        search_filter = f"(&(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(sAMAccountName={samaccountname}))"
        attributes = [
            'samAccountName',
            'badPwdCount',
            'badPasswordTime'
        ]
        page_size = 100
        cookie = None
        entries = []
        try:
            while True:
                self.__conn.search(
                    search_base,
                    search_filter,
                    attributes=attributes,
                    paged_size=page_size,
                    paged_cookie=cookie
                )
                entries.extend(self.__conn.entries)
                cookie = self.__conn.result['controls']['1.2.840.113556.1.4.319']['value']['cookie']
                if not cookie:
                    break
        except Exception as e:
            self.__console.print(f"[red]An error occurred while retrieving {samaccountname}: {e!s}[/red]")
            raise

        return entries[0].badPwdCount.value, entries[0].badPasswordTime.value

    def get_active_users(self, psos, domain_policy, time_delta, security_threshold, file_users):
        search_base = self.__base_dn
        search_filter = "(&(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(!(sAMAccountName=*$)))"
        attributes = [
            'samAccountName',
            'badPwdCount',
            'badPasswordTime',
            'distinguishedName',
            'msDS-ResultantPSO'
        ]
        page_size = 1000
        cookie = None
        entries = []
        try:
            while True:
                self.__conn.search(
                    search_base,
                    search_filter,
                    attributes=attributes,
                    paged_size=page_size,
                    paged_cookie=cookie
                )
                entries.extend(self.__conn.entries)
                cookie = self.__conn.result['controls']['1.2.840.113556.1.4.319']['value']['cookie']
                if not cookie:
                    break
        except Exception as e:
            self.__console.print(f"[red]An error occurred while retrieving active users: {e!s}[/red]")
            raise

        users = []
        statistics = {'total_users': len(entries),
                      'pso': {}}
        for entry in entries:
            if entry.samAccountName.value == self.__username:
                continue

            # User file provided, discard all users not in that list
            if len(file_users) > 0 and entry.samAccountName.value not in file_users:
                continue
            if entry['msDS-ResultantPSO']:
                pso_name = entry['msDS-ResultantPSO'].value.split(',')[0][3:]
                if pso_name not in statistics['pso']:
                    statistics['pso'][pso_name] = 1
                else:
                    statistics['pso'][pso_name] += 1

                if not self.__can_read_psos:
                    continue

                pso = self.get_pso(pso_name, psos)
                if pso is None:
                    continue
                lockout_threshold = pso.lockout_threshold
                lockout_window = pso.lockout_window
            else:
                pso = None
                lockout_threshold = domain_policy.lockout_threshold
                lockout_window = domain_policy.lockout_window

            # TODO Check if < or <= here, depending on further tests. <= to be sure
            if 0 < lockout_threshold <= security_threshold:
                self.__console.print(f"{entry.samAccountName} is discarded: Lockout threshold ({lockout_threshold}) is lower than security threshold ({security_threshold})")
                continue

            user = User(
                samaccountname=entry.samAccountName.value,
                dn=entry.distinguishedName.value,
                bad_password_time=entry.badPasswordTime.value,
                bad_password_count=entry.badPwdCount.value,
                lockout_window=lockout_window,
                lockout_threshold=lockout_threshold,
                pso=pso,
                time_delta=time_delta,
                security_threshold=security_threshold,
                console=self.__console
            )

            users.append(user)

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

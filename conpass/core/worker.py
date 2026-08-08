"""Worker thread for password spraying with thread-safe anti-lockout logic."""

import queue
import threading
import time
from dataclasses import dataclass

from rich.console import Console

from conpass.core.status import AuthStatus
from conpass.exceptions import SmbConnectionError, UserLockedOutError
from conpass.models import User, UserStatus
from conpass.services.database import DatabaseService
from conpass.services.ldap import LdapService
from conpass.services.smb import SmbService


@dataclass
class WorkItem:
    """Work item containing a user and password to test."""

    user: User
    password: str


class Worker(threading.Thread):
    """
    Worker thread for password spraying with proper anti-lockout protection.

    Key safety features:
    - Acquires user lock BEFORE checking if password can be tested
    - All state checks happen while holding the lock
    - Proper error handling and cleanup
    """

    def __init__(
        self,
        worker_id: int,
        work_queue: queue.Queue,
        ldap_service: LdapService | None,
        smb_service: SmbService,
        console: Console,
        online_mode: bool,
        stop_event: threading.Event,
        lockout_event: threading.Event,
        database_service: DatabaseService | None = None,
        completed_count_ref: tuple = None,
        connected_workers_ref: tuple = None,
        debug: bool = False
    ):
        super().__init__(daemon=True)
        self.worker_id = worker_id
        self.work_queue = work_queue
        self.ldap_service = ldap_service
        self.smb_service = smb_service
        self.database_service = database_service
        self.console = console
        self.online_mode = online_mode
        self.stop_event = stop_event
        self.lockout_event = lockout_event
        self.debug = debug

        # Progress tracking
        if completed_count_ref:
            self.orchestrator, self.count_attr, self.lock_attr = completed_count_ref
        else:
            self.orchestrator = None

        # Connection tracking
        if connected_workers_ref:
            self.conn_orchestrator, self.conn_count_attr, self.conn_lock_attr = connected_workers_ref
        else:
            self.conn_orchestrator = None

    def run(self) -> None:
        """Main worker loop - process work items from queue."""
        # Connect services
        try:
            if self.online_mode and self.ldap_service:
                self.ldap_service.connect()
            self.smb_service.connect()
        except Exception as e:
            self.console.print(f"[red]Worker {self.worker_id} failed to connect: {e}[/red]")
            return

        # Increment connected workers counter
        if self.conn_orchestrator:
            lock = getattr(self.conn_orchestrator, self.conn_lock_attr)
            with lock:
                current = getattr(self.conn_orchestrator, self.conn_count_attr)
                setattr(self.conn_orchestrator, self.conn_count_attr, current + 1)

        # Process work items
        while not self.stop_event.is_set() and not self.lockout_event.is_set():
            try:
                # Get work item with timeout
                work_item = self.work_queue.get(timeout=0.1)
            except queue.Empty:
                continue

            try:
                self._process_work_item(work_item)
            except UserLockedOutError:
                # Signal all workers to stop
                self.lockout_event.set()
                break
            except SmbConnectionError:
                # Signal all workers to stop
                self.stop_event.set()
                break
            except Exception as e:
                self.console.print(f"[red]Worker {self.worker_id} error: {e}[/red]")
            finally:
                self.work_queue.task_done()
                # Small delay to avoid hammering the DC
                time.sleep(0.1)

    def _process_work_item(self, work_item: WorkItem) -> None:
        """
        Process a single work item (test password for user).

        CRITICAL: This method implements the thread-safe anti-lockout logic.

        Flow:
        1. Try to acquire user lock (non-blocking)
        2. If can't acquire, requeue and return
        3. While holding lock:
           a. Update from LDAP (if online)
           b. Check if can test password
           c. If need to wait, requeue and return
           d. Test password
           e. Update user state

        Args:
            work_item: WorkItem containing user and password to test

        Raises:
            UserLockedOutError: If user gets locked out
            SmbConnectionError: If SMB connection fails
        """
        user = work_item.user
        password = work_item.password

        # CRITICAL: Try to acquire lock (non-blocking to avoid deadlock)
        # If we can't get the lock, another worker is testing this user
        if not user.try_acquire_lock(blocking=False):
            # Can't acquire lock - requeue for later
            if self.debug:
                self.console.print(f"[magenta]🔒 Worker {self.worker_id}: Lock busy for {user.samaccountname}/{password} - REQUEUE[/magenta]")
            self.work_queue.put(work_item)
            return

        try:
            # Now we hold the lock - safe to check and modify state
            if self.debug:
                self.console.print(f"[cyan]✓ Worker {self.worker_id}: Lock acquired for {user.samaccountname}/{password}[/cyan]")

            before_bad_count = None

            # Update user's bad password info from LDAP (if online)
            if self.online_mode and self.ldap_service:
                self._update_user_from_ldap(user)

                # Capture badPwdCount before authentication attempt
                before_bad_count = user.get_bad_password_count()

            # Check if we can test this password
            can_test, reason = user.can_test_password(password)
            remaining = user.get_remaining_attempts()
            bad_count = user.get_bad_password_count()

            if self.debug:
                self.console.print(
                    f"[blue]🔍 Worker {self.worker_id}: Check {user.samaccountname}/{password} - "
                    f"can_test={can_test}, reason={reason}, bad_count={bad_count}, remaining={remaining}[/blue]"
                )

            if not can_test:
                if reason == "no_remaining_attempts":
                    # Check if we should wait for observation window
                    wait_time = user.get_wait_time_for_next_attempt(password)
                    if self.debug:
                        self.console.print(
                            f"[yellow]⏱️  Worker {self.worker_id}: No remaining attempts for {user.samaccountname}/{password} - "
                            f"wait_time={wait_time:.1f}s[/yellow]"
                        )
                    if wait_time > 0:
                        # Requeue for later (after observation window)
                        if self.debug:
                            self.console.print(f"[yellow]↻ Worker {self.worker_id}: REQUEUE {user.samaccountname}/{password} (wait {wait_time:.1f}s)[/yellow]")
                        self.work_queue.put(work_item)
                        return
                # Otherwise, skip this password (already tested, password found, etc.)
                # Record in database if account is restricted to avoid retesting in future runs
                if reason == "account_restricted" and self.database_service:
                    try:
                        self.database_service.record_test(user.samaccountname, password, False)
                        if self.debug:
                            self.console.print(f"[cyan]💾 Worker {self.worker_id}: Recorded restricted account {user.samaccountname}/{password} in DB[/cyan]")
                    except Exception as e:
                        if self.debug:
                            self.console.print(f"[red]⚠️  Worker {self.worker_id}: Failed to record restricted account in database: {e}[/red]")
                # Increment completed count since we're not retrying this item
                if self.debug:
                    self.console.print(f"[yellow]⊘ Worker {self.worker_id}: SKIP {user.samaccountname}/{password} (reason: {reason})[/yellow]")
                self._increment_completed()
                return

            # Test the password
            if self.debug:
                self.console.print(f"[green]🔑 Worker {self.worker_id}: TESTING {user.samaccountname}/{password}[/green]")

            try:
                status = self.smb_service.test_credentials(user.samaccountname, password)
            except UserLockedOutError:
                # Lockout detected during SMB auth - add comprehensive debug info
                from datetime import datetime, timezone
                current_dc_time = datetime.now(timezone.utc) - user.time_delta
                obs_window_end = user.get_observation_window_end()
                obs_window_passed = user.is_observation_window_passed(current_dc_time)
                time_since_last_bad = (current_dc_time - user._bad_password_time).total_seconds()

                # Query all DCs for badPwdCount and lockoutTime (online mode only)
                dc_status_info = ""
                if self.online_mode and self.ldap_service:
                    dc_statuses = self.ldap_service.get_user_password_status_per_dc(user.samaccountname)
                    if dc_statuses:
                        dc_status_info = "\n[cyan]STATUS PER DC:[/cyan]\n"
                        for dc_status in dc_statuses:
                            dc_status_info += (
                                f"  DC {dc_status['dc_ip']}:\n"
                                f"    badPwdCount: {dc_status['bad_pwd_count']}\n"
                                f"    badPasswordTime: {dc_status['bad_pwd_time'].isoformat()}\n"
                                f"    lockoutTime: {dc_status['lockout_time'].isoformat()}\n"
                            )

                self.console.print(
                    f"[red]═══════════════════════════════════════════════════════════[/red]\n"
                    f"[red bold]LOCKOUT DETECTED - FULL DEBUG INFO[/red bold]\n"
                    f"[red]═══════════════════════════════════════════════════════════[/red]\n"
                    f"[yellow]Detection source:[/yellow] SMB_AUTH_RESPONSE\n"
                    f"[yellow]Worker ID:[/yellow] {self.worker_id}\n"
                    f"[yellow]Online mode:[/yellow] {self.online_mode}\n"
                    f"\n"
                    f"[cyan]USER STATE:[/cyan]\n"
                    f"  Username: {user.samaccountname}\n"
                    f"  DN: {user.dn}\n"
                    f"  Bad password count (before test): {user._bad_password_count}\n"
                    f"  Remaining attempts (calculated before test): {user.get_remaining_attempts()}\n"
                    f"  Tested passwords count (before this test): {len(user._tested_passwords)}\n"
                    f"  Tested passwords: {', '.join(user._tested_passwords[-5:])} "
                    f"{'(showing last 5)' if len(user._tested_passwords) > 5 else ''}\n"
                    f"  Current password being tested: {password}\n"
                    f"  Found password: {user._found_password}\n"
                    f"  Is restricted: {user._is_restricted}\n"
                    f"  Status: {user._status.value}\n"
                    f"\n"
                    f"[cyan]PASSWORD POLICY:[/cyan]\n"
                    f"  Policy name: {user.policy.name}\n"
                    f"  Lockout threshold: {user.policy.lockout_threshold}\n"
                    f"  Observation window (seconds): {user.policy.lockout_window_seconds}\n"
                    f"  Allows spraying: {user.policy.allows_spraying}\n"
                    f"\n"
                    f"[cyan]CONFIGURATION:[/cyan]\n"
                    f"  Security threshold: {user.security_threshold}\n"
                    f"  Max allowed attempts: {user.policy.lockout_threshold - user.security_threshold}\n"
                    f"\n"
                    f"[cyan]TIMING:[/cyan]\n"
                    f"  Current DC time: {current_dc_time.isoformat()}\n"
                    f"  Last bad password time: {user._bad_password_time.isoformat()}\n"
                    f"  Time since last bad password: {time_since_last_bad:.2f}s\n"
                    f"  Observation window end: {obs_window_end.isoformat()}\n"
                    f"  Observation window passed: {obs_window_passed}\n"
                    f"  Time until window end: {(obs_window_end - current_dc_time).total_seconds():.2f}s\n"
                    f"\n"
                    f"[cyan]ANTI-LOCKOUT CHECKS (before this test):[/cyan]\n"
                    f"  can_test_password() returned: {can_test}\n"
                    f"  can_test reason: {reason}\n"
                    f"  Remaining attempts reported: {remaining}\n"
                    f"  Bad count before test: {bad_count}\n"
                    f"  LDAP update performed: {self.online_mode}\n"
                    f"{dc_status_info}"
                    f"\n"
                    f"[red]═══════════════════════════════════════════════════════════[/red]\n"
                    f"[red bold]ANALYSIS:[/red bold]\n"
                    f"  Expected max attempts: {user.policy.lockout_threshold - user.security_threshold}\n"
                    f"  Actual tested count (before this): {len(user._tested_passwords)}\n"
                    f"  Bad password count before this test: {user._bad_password_count}\n"
                    f"  [red]This indicates a potential race condition or policy miscalculation![/red]\n"
                    f"  [red]The SMB server reported account lockout status.[/red]\n"
                    f"[red]═══════════════════════════════════════════════════════════[/red]"
                )
                # Re-raise to trigger worker shutdown
                raise

            # Convert AuthStatus to UserStatus
            user_status = self._auth_status_to_user_status(status)

            # Mark password as tested
            success = status.is_success
            user.mark_password_tested(password, success, user_status)

            # Record passwords that fail authentication without increasing badPwdCount
            if (
                self.online_mode and
                self.ldap_service and
                status == AuthStatus.INVALID_PASSWORD
            ):
                self._update_user_from_ldap(user)
                after_bad_count = user.get_bad_password_count()

                if (
                    before_bad_count is not None and
                    after_bad_count == before_bad_count
                ):
                    user.add_history_candidate(password)

                    self.console.print(
                        f"[yellow]{user.samaccountname} - {password}[/yellow]"
                        f"[bright_black] (potential history match)[/bright_black]"
                    )

                    if self.debug:
                        self.console.print(
                            f"[cyan]History candidate detected: "
                            f"{user.samaccountname}/{password} "
                            f"(badPwdCount {before_bad_count} -> {after_bad_count}, "
                            f"policy={user.policy.name})[/cyan]"
                        )
                else:
                    if self.debug:
                        self.console.print(
                            f"[bright_black]Invalid password increased badPwdCount: "
                            f"{user.samaccountname}/{password} "
                            f"({before_bad_count} -> {after_bad_count})[/bright_black]"
                        )

            # Record in database if enabled
            if self.database_service:
                try:
                    self.database_service.record_test(user.samaccountname, password, success)
                except Exception as e:
                    if self.debug:
                        self.console.print(f"[red]⚠️  Worker {self.worker_id}: Failed to record test in database: {e}[/red]")

            # Display result (while still holding lock to ensure consistent state)
            if success:
                if self.debug:
                    self.console.print(f"[bold green]✓✓✓ Worker {self.worker_id}: SUCCESS {user.samaccountname}/{password}[/bold green]")
                self._display_success(user, password, user_status)
            else:
                if self.debug:
                    self.console.print(f"[red]✗ Worker {self.worker_id}: FAILED {user.samaccountname}/{password} - status={user_status.value}[/red]")
                if user_status == UserStatus.ACCOUNT_RESTRICTED:
                    # Account has restrictions - likely in Protected Users group
                    self.console.print(
                        f"[bright_black]Account {user.samaccountname} has restrictions "
                        f"(likely Protected Users) - DISCARDING from further tests[/bright_black]"
                    )
                elif user_status == UserStatus.LOCKED_OUT:
                    # CRITICAL: Capture full state for debugging
                    from datetime import datetime, timezone
                    current_dc_time = datetime.now(timezone.utc) - user.time_delta
                    obs_window_end = user.get_observation_window_end()
                    obs_window_passed = user.is_observation_window_passed(current_dc_time)
                    time_since_last_bad = (current_dc_time - user._bad_password_time).total_seconds()

                    # Query all DCs for badPwdCount and lockoutTime (online mode only)
                    dc_status_info = ""
                    if self.online_mode and self.ldap_service:
                        dc_statuses = self.ldap_service.get_user_password_status_per_dc(user.samaccountname)
                        if dc_statuses:
                            dc_status_info = "\n[cyan]STATUS PER DC:[/cyan]\n"
                            for dc_status in dc_statuses:
                                dc_status_info += (
                                    f"  DC {dc_status['dc_ip']}:\n"
                                    f"    badPwdCount: {dc_status['bad_pwd_count']}\n"
                                    f"    badPasswordTime: {dc_status['bad_pwd_time'].isoformat()}\n"
                                    f"    lockoutTime: {dc_status['lockout_time'].isoformat()}\n"
                                )

                    self.console.print(
                        f"[red]═══════════════════════════════════════════════════════════[/red]\n"
                        f"[red bold]LOCKOUT DETECTED - FULL DEBUG INFO[/red bold]\n"
                        f"[red]═══════════════════════════════════════════════════════════[/red]\n"
                        f"[yellow]Detection source:[/yellow] LDAP_STATUS_UPDATE\n"
                        f"[yellow]Worker ID:[/yellow] {self.worker_id}\n"
                        f"[yellow]Online mode:[/yellow] {self.online_mode}\n"
                        f"\n"
                        f"[cyan]USER STATE:[/cyan]\n"
                        f"  Username: {user.samaccountname}\n"
                        f"  DN: {user.dn}\n"
                        f"  Bad password count: {user._bad_password_count}\n"
                        f"  Remaining attempts (calculated): {user.get_remaining_attempts()}\n"
                        f"  Tested passwords count: {len(user._tested_passwords)}\n"
                        f"  Tested passwords: {', '.join(user._tested_passwords[-5:])} "
                        f"{'(showing last 5)' if len(user._tested_passwords) > 5 else ''}\n"
                        f"  Current password being tested: {password}\n"
                        f"  Found password: {user._found_password}\n"
                        f"  Is restricted: {user._is_restricted}\n"
                        f"  Status: {user._status.value}\n"
                        f"\n"
                        f"[cyan]PASSWORD POLICY:[/cyan]\n"
                        f"  Policy name: {user.policy.name}\n"
                        f"  Lockout threshold: {user.policy.lockout_threshold}\n"
                        f"  Observation window (seconds): {user.policy.lockout_window_seconds}\n"
                        f"  Allows spraying: {user.policy.allows_spraying}\n"
                        f"\n"
                        f"[cyan]CONFIGURATION:[/cyan]\n"
                        f"  Security threshold: {user.security_threshold}\n"
                        f"  Max allowed attempts: {user.policy.lockout_threshold - user.security_threshold}\n"
                        f"\n"
                        f"[cyan]TIMING:[/cyan]\n"
                        f"  Current DC time: {current_dc_time.isoformat()}\n"
                        f"  Last bad password time: {user._bad_password_time.isoformat()}\n"
                        f"  Time since last bad password: {time_since_last_bad:.2f}s\n"
                        f"  Observation window end: {obs_window_end.isoformat()}\n"
                        f"  Observation window passed: {obs_window_passed}\n"
                        f"  Time until window end: {(obs_window_end - current_dc_time).total_seconds():.2f}s\n"
                        f"\n"
                        f"[cyan]ANTI-LOCKOUT CHECKS (before this test):[/cyan]\n"
                        f"  can_test_password() returned: {can_test}\n"
                        f"  can_test reason: {reason}\n"
                        f"  Remaining attempts reported: {remaining}\n"
                        f"  Bad count before test: {bad_count}\n"
                        f"{dc_status_info}"
                        f"\n"
                        f"[red]═══════════════════════════════════════════════════════════[/red]\n"
                        f"[red bold]ANALYSIS:[/red bold]\n"
                        f"  Expected max attempts: {user.policy.lockout_threshold - user.security_threshold}\n"
                        f"  Actual tested count: {len(user._tested_passwords)}\n"
                        f"  Bad password count at lockout: {user._bad_password_count}\n"
                        f"  [red]This indicates a potential race condition or policy miscalculation![/red]\n"
                        f"[red]═══════════════════════════════════════════════════════════[/red]"
                    )
                    # This will raise UserLockedOutError
                    raise UserLockedOutError(user.samaccountname)

            # Increment completed count since this item is done
            self._increment_completed()

        finally:
            user.release_lock()

    def _increment_completed(self) -> None:
        """Increment the completed work items counter (thread-safe)."""
        if self.orchestrator:
            lock = getattr(self.orchestrator, self.lock_attr)
            with lock:
                current = getattr(self.orchestrator, self.count_attr)
                setattr(self.orchestrator, self.count_attr, current + 1)

    def _update_user_from_ldap(self, user: User) -> None:
        """
        Update user's bad password info and lockout status from LDAP.

        MUST be called while holding the user lock.
        """
        if not self.ldap_service:
            return

        bad_pwd_count, bad_pwd_time, lockout_time = self.ldap_service.get_user_password_status(user.samaccountname)

        # Update user state (always update to get latest lockout_time)
        user.update_from_ldap(bad_pwd_count, bad_pwd_time, lockout_time)

    def _auth_status_to_user_status(self, auth_status: AuthStatus) -> UserStatus:
        """Convert AuthStatus to UserStatus."""
        mapping = {
            AuthStatus.SUCCESS: UserStatus.PASSWORD_FOUND,
            AuthStatus.PASSWORD_EXPIRED: UserStatus.PASSWORD_EXPIRED,
            AuthStatus.PASSWORD_MUST_CHANGE: UserStatus.PASSWORD_EXPIRED,
            AuthStatus.ACCOUNT_EXPIRED: UserStatus.ACCOUNT_EXPIRED,
            AuthStatus.ACCOUNT_RESTRICTION: UserStatus.ACCOUNT_RESTRICTED,
            AuthStatus.INVALID_PASSWORD: UserStatus.INVALID_PASSWORD,
            AuthStatus.ACCOUNT_LOCKOUT: UserStatus.LOCKED_OUT,
            AuthStatus.INVALID_WORKSTATION: UserStatus.ACCOUNT_RESTRICTED,
            AuthStatus.INVALID_LOGON_HOURS: UserStatus.ACCOUNT_RESTRICTED,
        }
        return mapping.get(auth_status, UserStatus.INVALID_PASSWORD)

    def _display_success(self, user: User, password: str, status: UserStatus) -> None:
        """
        Display successful password find with appropriate message.

        MUST be called while holding the user lock.
        """
        # Don't display restricted accounts
        if status == UserStatus.ACCOUNT_RESTRICTED:
            return

        message = f"[yellow]{user.samaccountname} - {password}[/yellow]"

        if status == UserStatus.PASSWORD_EXPIRED:
            message += "[bright_black] (Password expired or must be changed)[/bright_black]"
        elif status == UserStatus.ACCOUNT_EXPIRED:
            message += "[bright_black] (Account expired)[/bright_black]"

        self.console.print(message)

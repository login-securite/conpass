"""
End-to-end spraying against a simulated PDC applying the samsrv / msv1_0 rules.

The simulated DC:
- counts a failure only within the observation window of the previous one,
  otherwise restarts at 1 (nothing is reset by a timer);
- locks the account out at the threshold, for the lockout duration;
- does not count the two previous passwords (N-1 / N-2);
- accepts N-1 over NTLM for 5 minutes after a password change;
- optionally receives failures from the users themselves, and drops connections.

Workers must never lock an account out when the policy is right, and must stop
at the first lockout when it is wrong.
"""

import random
import threading
import time
from datetime import timedelta

import pytest

from conpass import lockout, worker
from conpass.errors import AuthAttemptLostError
from conpass.lockout import LockoutState, PasswordPolicy, User
from conpass.protocols.kerberos import KerberosVerdict
from conpass.protocols.smb import AuthStatus
from conpass.scheduler import Scheduler
from conpass.timeutils import filetime_to_datetime
from conpass.worker import SprayContext, Worker

THRESHOLD = 5
WINDOW = 1  # seconds
DURATION = 3  # seconds
FILETIME_UNIX_EPOCH = 116444736000000000
UNITS_PER_SECOND = 10_000_000


def filetime(timestamp: float | None = None) -> int:
    return int((timestamp or time.time()) * UNITS_PER_SECOND) + FILETIME_UNIX_EPOCH


class SimulatedDC:
    """PDC Emulator holding the authoritative lockout state of each account."""

    def __init__(self, user_count: int):
        self.lock = threading.Lock()
        self.accounts = {
            f"u{i}": {
                "count": 0,
                "bad_time": 0,
                "lockout_time": 0,
                "password": f"pw{i}",
                "history": [f"old1_{i}", f"old2_{i}"],
                "pwd_last_set": filetime(time.time() - 86400 * 10),
            }
            for i in range(user_count)
        }
        # u0 changed its password a minute ago: NTLM still accepts the previous one
        self.accounts["u0"]["pwd_last_set"] = filetime(time.time() - 60)
        self.lockouts = 0
        self.attempts = 0
        self._running: set[str] = set()

    def _in_window(self, account, now: int) -> bool:
        return account["count"] and now <= account["bad_time"] + WINDOW * UNITS_PER_SECOND

    def _locked(self, account, now: int) -> bool:
        return account["lockout_time"] and now < account["lockout_time"] + DURATION * UNITS_PER_SECOND

    def fail(self, account) -> None:
        now = filetime()
        if self._locked(account, now):
            return
        account["count"] = account["count"] + 1 if self._in_window(account, now) else 1
        account["bad_time"] = now
        if account["count"] >= THRESHOLD:
            account["lockout_time"] = now
            self.lockouts += 1

    def authenticate(self, name: str, password: str) -> AuthStatus:
        with self.lock:
            assert name not in self._running, "two attempts on the same account at the same time"
            self._running.add(name)
        try:
            time.sleep(random.uniform(0.001, 0.005))
            return self._check(name, password)
        finally:
            with self.lock:
                self._running.discard(name)

    def _check(self, name: str, password: str) -> AuthStatus:
        with self.lock:
            self.attempts += 1
            account = self.accounts[name]
            now = filetime()
            if self._locked(account, now):
                return AuthStatus.ACCOUNT_LOCKED_OUT
            grace = now - account["pwd_last_set"] < 300 * UNITS_PER_SECOND
            if password == account["password"] or (grace and password == account["history"][0]):
                account["count"] = 0
                return AuthStatus.SUCCESS
            if password not in account["history"]:
                self.fail(account)
            return AuthStatus.INVALID_PASSWORD

    def state(self, name: str) -> LockoutState:
        with self.lock:
            account = self.accounts[name]
            return LockoutState(
                bad_pwd_count=account["count"],
                bad_pwd_filetime=account["bad_time"],
                bad_pwd_time=filetime_to_datetime(account["bad_time"]),
                lockout_time=filetime_to_datetime(account["lockout_time"]),
                locked=bool(self._locked(account, filetime())),
                pwd_last_set=filetime_to_datetime(account["pwd_last_set"]),
            )

    def user_failures(self, stop: threading.Event) -> None:
        """Users mistyping their password, at most once per window each."""
        while not stop.is_set():
            with self.lock:
                account = random.choice(list(self.accounts.values()))
                if not self._in_window(account, filetime()):
                    self.fail(account)
            time.sleep(0.02)


class FakeLdap:
    def __init__(self, dc: SimulatedDC):
        self.dc = dc

    def connect(self) -> None:
        pass

    def read_user_state(self, dn: str) -> LockoutState:
        return self.dc.state(dn)

    def domain_controller_hostnames(self) -> list[str]:
        return []


class FakeSmb:
    def __init__(self, dc: SimulatedDC, drop_rate: float):
        self.dc = dc
        self.drop_rate = drop_rate
        self.last_error = ""

    def connect(self) -> None:
        pass

    def authenticate(self, name: str, password: str) -> AuthStatus:
        status = self.dc.authenticate(name, password)
        if random.random() < self.drop_rate:
            raise AuthAttemptLostError("simulated connection drop")
        return status


class FakeKerberos:
    """The KDC rejects N-1 (PREAUTH_FAILED) even when NTLM accepts it."""

    def __init__(self, dc: SimulatedDC):
        self.dc = dc

    def verify(self, name: str, password: str) -> KerberosVerdict:
        if password == self.dc.accounts[name]["history"][0]:
            return KerberosVerdict.PREVIOUS
        return KerberosVerdict.CURRENT


class Recorder:
    def __init__(self):
        self.rows = []

    def record(self, username, password, success, note=None):
        self.rows.append((username, password, success, note))


@pytest.fixture(autouse=True)
def fast_timings(monkeypatch):
    monkeypatch.setattr(lockout, "TIME_MARGIN", timedelta(milliseconds=300))
    monkeypatch.setattr(worker, "UNCOUNTED_CONFIRM_DELAY", 0.05)
    random.seed(1)


def spray(
    *,
    believed_threshold=THRESHOLD,
    user_count=30,
    password_count=9,
    threads=8,
    user_failures=False,
    drop_rate=0.0,
    online=True,
):
    """Spray the simulated DC until done or locked out. Returns (dc, lockout_event, recorder, users)."""
    dc = SimulatedDC(user_count)
    policy = PasswordPolicy("Default Domain Policy", believed_threshold, WINDOW, DURATION)
    users = [User(name, name if online else None, policy, 2, dc.state(name)) for name in dc.accounts]
    scheduler = Scheduler(users)
    recorder = Recorder()
    context = SprayContext(
        scheduler=scheduler,
        time_delta=timedelta(0),
        stop_event=threading.Event(),
        lockout_event=threading.Event(),
        kerberos=FakeKerberos(dc),
        database=recorder,
    )
    workers = [
        Worker(i, context, FakeLdap(dc) if online else None, FakeSmb(dc, drop_rate), lambda _: None)
        for i in range(threads)
    ]
    for thread in workers:
        thread.start()

    passwords = [f"guess{i}" for i in range(password_count)]
    passwords[2], passwords[4], passwords[6], passwords[8] = "old2_5", "old1_0", "pw7", "old1_9"
    scheduler.add_passwords(passwords)
    stop_users = threading.Event()
    if user_failures:
        threading.Thread(target=dc.user_failures, args=(stop_users,), daemon=True).start()

    deadline = time.monotonic() + 60
    while not scheduler.is_done() and not context.lockout_event.is_set() and time.monotonic() < deadline:
        time.sleep(0.05)
    stop_users.set()
    scheduler.close()
    context.stop_event.set()
    for thread in workers:
        thread.join(2)
    return dc, context.lockout_event, recorder, scheduler


def found(recorder: Recorder) -> dict[str, str]:
    return {username: password for username, password, success, _ in recorder.rows if success}


def previous(recorder: Recorder) -> set[tuple[str, str]]:
    return {(username, password) for username, password, _, note in recorder.rows if note == "previous"}


def test_no_lockout_and_everything_tested():
    dc, lockout_event, recorder, scheduler = spray()
    assert dc.lockouts == 0
    assert not lockout_event.is_set()
    assert scheduler.is_done()
    assert found(recorder) == {"u7": "pw7"}
    # N-2 detected from badPasswordTime, N-1 within the NTLM grace period through Kerberos
    assert previous(recorder) == {("u5", "old2_5"), ("u0", "old1_0"), ("u9", "old1_9")}


def test_no_lockout_with_users_failing_too():
    dc, lockout_event, recorder, _ = spray(user_failures=True)
    assert dc.lockouts == 0
    assert not lockout_event.is_set()
    assert found(recorder) == {"u7": "pw7"}


def test_no_lockout_with_dropped_connections():
    dc, lockout_event, recorder, _ = spray(drop_rate=0.05)
    assert dc.lockouts == 0
    assert not lockout_event.is_set()
    pairs = [(username, password) for username, password, *_ in recorder.rows]
    assert len(pairs) == len(set(pairs)), "a test was recorded twice"


def test_no_lockout_offline():
    dc, lockout_event, recorder, _ = spray(online=False, user_count=15)
    assert dc.lockouts == 0
    assert not lockout_event.is_set()
    assert found(recorder) == {"u7": "pw7"}


def test_wrong_policy_stops_at_first_lockout():
    # conpass believes the threshold is 8, the DC locks out at 5
    threads = 8
    dc, lockout_event, _, _ = spray(believed_threshold=8, threads=threads)
    assert lockout_event.is_set()
    # Attempts already running when the lockout is seen may lock one account each
    assert 1 <= dc.lockouts <= threads

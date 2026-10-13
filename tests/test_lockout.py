"""Lockout model: effective counter, safe attempt time, lockout end."""

from datetime import datetime, timedelta, timezone

from conpass.lockout import LOCKED_RECHECK_DELAY, TIME_MARGIN, LockoutState, PasswordPolicy, User

NOW = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
POLICY = PasswordPolicy(
    "Default Domain Policy", lockout_threshold=5, lockout_window_seconds=600, lockout_duration_seconds=900
)


def make_user(**state) -> User:
    return User("alice", "CN=alice", POLICY, security_threshold=2, state=LockoutState(**state))


def test_counter_ignored_once_window_elapsed():
    # Nothing resets badPwdCount: the DC restarts at 1 when the window has elapsed
    user = make_user(bad_pwd_count=4, bad_pwd_time=NOW - timedelta(seconds=601) - TIME_MARGIN)
    assert user.effective_bad_count(NOW) == 0
    assert user.attempts_left(NOW) == 3


def test_counter_used_within_window():
    user = make_user(bad_pwd_count=2, bad_pwd_time=NOW - timedelta(seconds=10))
    assert user.attempts_left(NOW) == 1
    assert user.next_attempt_time(NOW) == NOW


def test_wait_for_window_when_no_attempt_left():
    last_failure = NOW - timedelta(seconds=10)
    user = make_user(bad_pwd_count=3, bad_pwd_time=last_failure)
    assert user.attempts_left(NOW) == 0
    assert user.next_attempt_time(NOW) == last_failure + timedelta(seconds=600) + TIME_MARGIN


def test_local_estimate_is_a_floor():
    # The PDC read lags behind: our own failures still count
    user = make_user(bad_pwd_count=0)
    for _ in range(3):
        user.record_failure(NOW)
    assert user.effective_bad_count(NOW) == 3
    assert user.next_attempt_time(NOW) > NOW


def test_cancel_last_failure():
    user = make_user()
    user.record_failure(NOW)
    user.record_failure(NOW)
    user.cancel_last_failure()
    assert user.effective_bad_count(NOW) == 1


def test_lockout_end_uses_duration():
    user = make_user(lockout_time=NOW - timedelta(seconds=100), locked=True)
    assert user.lockout_end(NOW) == NOW - timedelta(seconds=100) + timedelta(seconds=900) + TIME_MARGIN


def test_lockout_over_although_lockout_time_kept():
    # lockoutTime keeps its value until the next successful logon
    user = make_user(lockout_time=NOW - timedelta(seconds=1000))
    assert user.lockout_end(NOW) is None


def test_lockout_until_admin_unlock():
    policy = PasswordPolicy("pso", lockout_threshold=5, lockout_window_seconds=600, lockout_duration_seconds=0)
    user = User("bob", "CN=bob", policy, 2, LockoutState(lockout_time=NOW - timedelta(days=3), locked=True))
    assert user.lockout_end(NOW) == NOW + LOCKED_RECHECK_DELAY


def test_no_lockout_policy():
    policy = PasswordPolicy("none", lockout_threshold=0, lockout_window_seconds=0)
    user = User("carol", "CN=carol", policy, 2, LockoutState(bad_pwd_count=100, bad_pwd_time=NOW))
    assert user.attempts_left(NOW) is None
    assert user.next_attempt_time(NOW) == NOW

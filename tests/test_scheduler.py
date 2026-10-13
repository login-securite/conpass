"""Scheduler: spray order, exclusive ownership, waiting users, progress."""

from conpass.lockout import PasswordPolicy, User
from conpass.scheduler import Scheduler

POLICY = PasswordPolicy("Default Domain Policy", lockout_threshold=5, lockout_window_seconds=60)


def make_users(count: int) -> list[User]:
    return [User(f"user{i}", f"CN=user{i}", POLICY, 2) for i in range(count)]


def drain(scheduler: Scheduler) -> list[tuple[str, str]]:
    tested = []
    while (item := scheduler.acquire(timeout=0.01)) is not None:
        user, password = item
        tested.append((user.samaccountname, password))
        scheduler.release(user, consumed=True)
    return tested


def test_each_password_sprayed_on_all_users_before_the_next():
    scheduler = Scheduler(make_users(3))
    scheduler.add_passwords(["first", "second"])
    passwords = [password for _, password in drain(scheduler)]
    assert passwords == ["first"] * 3 + ["second"] * 3
    assert scheduler.progress() == (6, 6)
    assert scheduler.is_done()


def test_user_specific_passwords_first():
    users = make_users(2)
    scheduler = Scheduler(users)
    scheduler.add_user_password(users[1], "user1")
    scheduler.add_passwords(["shared"])
    tested = drain(scheduler)
    assert tested[0] == ("user1", "user1")
    assert tested.index(("user1", "user1")) < tested.index(("user1", "shared"))


def test_user_owned_by_one_worker_at_a_time():
    scheduler = Scheduler(make_users(1))
    scheduler.add_passwords(["a", "b"])
    assert scheduler.acquire(timeout=0.01) is not None
    assert scheduler.acquire(timeout=0.01) is None


def test_waiting_user_comes_back_after_delay():
    scheduler = Scheduler(make_users(1))
    scheduler.add_passwords(["a"])
    user, _ = scheduler.acquire(timeout=0.01)
    scheduler.release(user, delay=0.2)
    assert scheduler.waiting_count() == 1
    assert scheduler.acquire(timeout=0.05) is None
    assert scheduler.acquire(timeout=0.5) is not None


def test_already_tested_passwords_skipped():
    scheduler = Scheduler(make_users(2), is_tested=lambda user, _password: user.samaccountname == "user0")
    scheduler.add_passwords(["a"])
    assert drain(scheduler) == [("user1", "a")]


def test_finished_user_completes_its_progress():
    scheduler = Scheduler(make_users(1))
    scheduler.add_passwords(["a", "b", "c"])
    user, _ = scheduler.acquire(timeout=0.01)
    user.finished = True
    scheduler.release(user, consumed=True)
    assert scheduler.progress() == (3, 3)
    assert scheduler.is_done()

"""Scheduler handing users to workers only when they can be tested safely."""

import heapq
import itertools
import threading
import time
from collections.abc import Callable

from conpass.models import User


class Scheduler:
    """
    Hands users out to workers, one at a time, together with their next password.

    - A user is owned by a single worker between acquire() and release(), so two
      attempts on the same account can never run concurrently.
    - A user that must wait (observation window, lockout) sleeps in a time-ordered
      heap and costs nothing until it is due: no polling, no LDAP query.
    - Due users are served by password index, so every password is sprayed on all
      users before the next one.
    - Passwords are stored once and each user only keeps a cursor, so memory does not
      grow with users x passwords.
    """

    def __init__(self, users: list[User], is_tested: Callable[[User, str], bool] | None = None):
        self._cond = threading.Condition()
        self._is_tested = is_tested or (lambda _user, _password: False)
        self._passwords: list[str] = []
        self._seq = itertools.count()
        self._ready: list[tuple[int, int, User]] = []
        self._waiting: list[tuple[float, int, User]] = []
        self._idle: set[User] = set()
        self._busy = 0
        self._active = 0
        self._closed = False
        self.total = 0
        self.completed = 0

        for user in users:
            if user.finished:
                continue
            self._active += 1
            self._idle.add(user)

    # ----- feeding -----

    def add_passwords(self, passwords: list[str]) -> None:
        """Append passwords to spray on every active user."""
        with self._cond:
            self._passwords.extend(passwords)
            self.total += len(passwords) * self._active
            self._wake_idle()

    def add_user_password(self, user: User, password: str) -> None:
        """Queue a password for a single user, tested before the shared ones."""
        with self._cond:
            if user.finished:
                return
            user.extra.append(password)
            self.total += 1
            if user in self._idle:
                self._idle.discard(user)
                self._push_ready(user)
            self._cond.notify_all()

    def _wake_idle(self) -> None:
        for user in self._idle:
            self._push_ready(user)
        self._idle.clear()
        self._cond.notify_all()

    # ----- workers -----

    def acquire(self, timeout: float) -> tuple[User, str] | None:
        """
        Get a due user and the next password to test on it.

        Returns:
            (user, password), or None if nothing is due before the timeout
        """
        deadline = time.monotonic() + timeout
        with self._cond:
            while not self._closed:
                item = self._pop_ready()
                if item:
                    self._busy += 1
                    return item
                now = time.monotonic()
                wait = deadline - now
                if self._waiting:
                    wait = min(wait, self._waiting[0][0] - now)
                if deadline <= now:
                    return None
                self._cond.wait(max(wait, 0.01))
        return None

    def release(self, user: User, delay: float = 0.0, consumed: bool = False) -> None:
        """
        Give a user back.

        Args:
            user: User returned by acquire()
            delay: Seconds before the user can be tested again
            consumed: True if the password returned by acquire() is done with
        """
        with self._cond:
            self._busy -= 1
            if consumed:
                self._consume(user)
            if user.finished:
                self._finish(user)
            elif delay > 0:
                heapq.heappush(self._waiting, (time.monotonic() + delay, next(self._seq), user))
            else:
                self._push_ready(user)
            self._cond.notify_all()

    def close(self) -> None:
        """Stop handing out work."""
        with self._cond:
            self._closed = True
            self._cond.notify_all()

    # ----- state -----

    def progress(self) -> tuple[int, int]:
        with self._cond:
            return self.completed, self.total

    def is_done(self) -> bool:
        """True when no test is running, due or waiting."""
        with self._cond:
            return self._busy == 0 and not self._ready and not self._waiting

    def waiting_count(self) -> int:
        with self._cond:
            return len(self._waiting)

    # ----- internals (lock held) -----

    def _push_ready(self, user: User) -> None:
        rank = -1 if user.extra else user.cursor
        heapq.heappush(self._ready, (rank, next(self._seq), user))

    def _promote_due(self) -> None:
        now = time.monotonic()
        while self._waiting and self._waiting[0][0] <= now:
            _, _, user = heapq.heappop(self._waiting)
            self._push_ready(user)

    def _pop_ready(self) -> tuple[User, str] | None:
        self._promote_due()
        while self._ready:
            _, _, user = heapq.heappop(self._ready)
            password = self._next_password(user)
            if password is not None:
                return user, password
            self._idle.add(user)
        return None

    def _peek(self, user: User) -> str | None:
        if user.extra:
            return user.extra[0]
        if user.cursor < len(self._passwords):
            return self._passwords[user.cursor]
        return None

    def _consume(self, user: User) -> None:
        user.tested.add(self._peek(user))
        self._skip(user)

    def _next_password(self, user: User) -> str | None:
        """Next password to test, skipping those already tested (completed)."""
        while (password := self._peek(user)) is not None:
            if password not in user.tested and not self._is_tested(user, password):
                return password
            self._skip(user)
        return None

    def _skip(self, user: User) -> None:
        if user.extra:
            user.extra.popleft()
        else:
            user.cursor += 1
        self.completed += 1

    def _finish(self, user: User) -> None:
        """Account for the passwords a finished user will never be tested with."""
        self._active -= 1
        self.completed += len(user.extra) + len(self._passwords) - user.cursor
        user.extra.clear()
        user.cursor = len(self._passwords)

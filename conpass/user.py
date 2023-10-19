from enum import Enum
from datetime import datetime, timedelta


class USER_STATUS(Enum):
    FOUND = 0
    THRESHOLD = 1
    PSO = 2
    UNREADABLE_PSO = 2
    TESTED = 4
    TEST = 5


class User:
    def __init__(self, samaccountname, dn, last_password_test, bad_password_count, lockout_reset, lockout_threshold, pso):
        self.samaccountname = samaccountname
        self.dn = dn
        self.password = None
        self.last_password_test = last_password_test
        self.bad_password_count = bad_password_count
        self.lockout_reset = lockout_reset
        self.lockout_threshold = lockout_threshold
        self.pso = pso
        self.first_attempt = True

    def should_test_password(self):
        for pso in self.pso.values():
            if not pso.readable:
                return USER_STATUS.UNREADABLE_PSO
            self.lockout_threshold, self.lockout_reset = pso.lockout_threshold, pso.lockout_window
        if self.password is not None:
            return USER_STATUS.FOUND
        if self.lockout_threshold > 0 and self.bad_password_count >= self.lockout_threshold-1 and (self.first_attempt or self.last_password_test + timedelta(minutes=self.lockout_reset) > datetime.now()):
            self.first_attempt = False
            return USER_STATUS.THRESHOLD

        self.first_attempt = False

        return USER_STATUS.TEST

    def readable_pso(self):
        for pso in self.pso.values():
            if not pso.readable:
                return -1
        return 1 if self.pso != {} else 0

    def test_password(self, password, conn):
        self.last_password_test = datetime.now()
        if not conn.test_credentials(self.samaccountname, password):
            self.bad_password_count += 1
            return False
        self.password = password
        return True

    def __eq__(self, other):
        return isinstance(other, self.__class__) and self.samaccountname == other.samaccountname

    def __str__(self):
        return self.__repr__()

    def __repr__(self):
        return f"User(samAccountName={self.samaccountname}, password={self.password}, last_password_test={self.last_password_test}, bad_password_count={self.bad_password_count}, lockout_reset={self.lockout_reset}, lockout_threshold={self.lockout_threshold}, pso={self.pso})"
from enum import Enum
from datetime import datetime, timedelta


class USER_STATUS(Enum):
    FOUND = 0
    THRESHOLD = 1
    TESTED = 2
    TEST = 3


class User:
    def __init__(self, samaccountname, last_password_test, bad_password_count, lockout_reset, lockout_threshold):
        self.samaccountname = samaccountname
        self.password = None
        self.last_password_test = last_password_test
        self.bad_password_count = bad_password_count
        self.lockout_reset = lockout_reset
        self.lockout_threshold = lockout_threshold

        self.first_attempt = True

    def should_test_password(self):
        if self.password is not None:
            return USER_STATUS.FOUND
        if self.lockout_threshold > 0 and self.bad_password_count >= self.lockout_threshold-1 and (self.first_attempt or self.last_password_test + timedelta(minutes=self.lockout_reset) > datetime.now()):
            self.first_attempt = False
            return USER_STATUS.THRESHOLD
        self.first_attempt = False
        return USER_STATUS.TEST

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
        return f"User(sampleaccountname={self.samaccountname}, password={self.password}, last_password_test={self.last_password_test}, bad_password_count={self.bad_password_count}, lockout_reset={self.lockout_reset}, lockout_threshold={self.lockout_threshold})"
from datetime import timedelta, datetime, timezone


class User:
    def __init__(self, samaccountname, dn, bad_password_count, bad_password_time, lockout_window=None, lockout_threshold=None, pso=None, time_delta=None, security_threshold=None, console=None):
        self.samaccountname = samaccountname
        self.dn = dn
        self.password = None
        self.password_expired = False
        self.account_expired = False
        self.bad_password_time = bad_password_time
        self.bad_password_count = bad_password_count
        self.lockout_window = lockout_window
        self.lockout_threshold = lockout_threshold
        self.pso = pso
        self.tested_passwords = []
        self.time_delta = time_delta
        self.security_threshold = security_threshold
        self.console = console

        # Is this user already in the testing queue
        self.__cp_lock = False

    def can_be_tested(self, password, ldap_connection, online):
        # Password already tried
        if password in self.tested_passwords:
            return False

        if self.password:
            self.tested_passwords.append(password)
            return False

        # Already being tested
        if self.is_locked():
            return False

        if self.lockout_threshold > 0:
            online and self.update(ldap_connection)
            self.apply_observation_window()

            # Lockout risk
            if not self.check_lockout(online):
                return False

        self.tested_passwords.append(password)
        return True

    def update(self, ldap_connection):
        bad_password_count, bad_password_time = ldap_connection.get_user_password_status(self.samaccountname)
        if bad_password_count != self.bad_password_count:
            update_text = f"'badPwdCount' changed from {self.bad_password_count} to {bad_password_count}"

            if self.bad_password_time > bad_password_time and len(self.tested_passwords) > 0:
                self.console.log(f"[yellow]{self.samaccountname}[/yellow] old password may have been [yellow]{self.tested_passwords[-1]}[/yellow] ({update_text})")
            self.bad_password_count = bad_password_count

        self.bad_password_time = bad_password_time

    def is_locked(self):
        return self.__cp_lock

    def lock(self):
        self.__cp_lock = True

    def unlock(self):
        self.__cp_lock = False

    def apply_observation_window(self):
        # Observation window has passed
        if self.bad_password_time + timedelta(seconds=self.lockout_window) + timedelta(seconds=1) <= datetime.now(timezone.utc) - self.time_delta:
            self.bad_password_count = 0

    def check_lockout(self, online):
        if not online:
            return self.bad_password_count == 0
        return self.bad_password_count < (self.lockout_threshold - self.security_threshold)

    def test_password(self, password, smb_connection, locked_out_users):
        self.bad_password_time = datetime.now(timezone.utc) - self.time_delta
        res = smb_connection.test_credentials(self.samaccountname, password, locked_out_users)
        if res < 0:
            self.bad_password_count += 1
            return False
        elif res == 1:
            self.password_expired = True
        elif res == 2:
            self.account_expired = True

        self.password = password
        self.bad_password_count = 0
        return True

    def __eq__(self, other):
        return isinstance(other, self.__class__) and self.samaccountname == other.samaccountname

    def __str__(self):
        return self.__repr__()

    def __repr__(self):
        return f"User(samAccountName={self.samaccountname}, password={self.password}, bad_password_time={self.bad_password_time}, bad_password_count={self.bad_password_count}, lockout_window={self.lockout_window}, lockout_threshold={self.lockout_threshold}, pso={self.pso})"
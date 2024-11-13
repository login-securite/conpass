from datetime import timedelta, datetime, timezone


class User:
    def __init__(self, samaccountname, dn, bad_password_count, bad_password_time, lockout_window=None, lockout_threshold=None, pso=None, time_delta=None, security_threshold=None):
        self.samaccountname = samaccountname
        self.dn = dn
        self.password = None
        self.bad_password_time = bad_password_time
        self.bad_password_count = bad_password_count
        self.lockout_window = lockout_window
        self.lockout_threshold = lockout_threshold
        self.pso = pso
        self.tested_passwords = []
        self.time_delta = time_delta
        self.security_threshold = security_threshold

        # Is this user already in the testing queue
        self.__cp_lock = False

    def can_be_tested(self, password, ldap_connection, console):
        # Password already found
        if self.password:
            return False

        # Password already tried
        if password in self.tested_passwords:
            return False

        # Already being tested
        if self.is_locked():
            return False

        # TODO try and implement this properly
        #if not self.update(ldap_connection, console):
        #    return False

        # Lockout risk
        if not self.check_lockout():
            return False

        self.tested_passwords.append(password)
        return True

    def update(self, ldap_connection, console):
        bad_password_count, bad_password_time = ldap_connection.get_user_password_status(self.samaccountname)
        if bad_password_count != self.bad_password_count:
            update_text = f"{self.samaccountname} 'badPwdCount' changed from {self.bad_password_count} to {bad_password_count}"

            if self.bad_password_time > bad_password_time + timedelta(seconds=5) and len(self.tested_passwords) > 0:
                console.log(f"{update_text} - User's password may be {self.tested_passwords[-1]}{'or ' + self.tested_passwords[-2] if len(self.tested_passwords) > 1 else ''}")
            else:
                if self.bad_password_count > bad_password_count:
                    console.log(f"{update_text} - The user may have logged in")
                else:
                    console.log(f"{update_text} - The user may have entered a bad password")
            console.log(f"{self.bad_password_time} to {bad_password_time}")
            self.bad_password_count = bad_password_count

        self.bad_password_time = bad_password_time
        return True


    def is_locked(self):
        return self.__cp_lock

    def lock(self):
        self.__cp_lock = True

    def unlock(self):
        self.__cp_lock = False

    def check_lockout(self):
        if self.lockout_threshold == 0:
            return True
        # Observation window has passed
        if self.bad_password_time + timedelta(seconds=self.lockout_window) + timedelta(seconds=5) <= datetime.now(timezone.utc) - self.time_delta:
            #self.context.logger.debug(f"{self.samaccountname} - Reset {self.lockout_window} seconds have passed, bad_password_count reset")
            self.bad_password_count = 0
            return True
        elif self.bad_password_count >= (self.lockout_threshold - self.security_threshold):
            return False
        return True

    def test_password(self, password, smb_connection):
        res = smb_connection.test_credentials(self.samaccountname, password)
        if not res:
            self.bad_password_time = datetime.now(timezone.utc) - self.time_delta
            self.bad_password_count += 1
            return False
        self.password = password
        self.bad_password_count = 0
        return True

    def __eq__(self, other):
        return isinstance(other, self.__class__) and self.samaccountname == other.samaccountname

    def __str__(self):
        return self.__repr__()

    def __repr__(self):
        return f"User(samAccountName={self.samaccountname}, password={self.password}, bad_password_time={self.bad_password_time}, bad_password_count={self.bad_password_count}, lockout_window={self.lockout_window}, lockout_threshold={self.lockout_threshold}, pso={self.pso})"
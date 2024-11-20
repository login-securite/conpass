from datetime import datetime, timedelta, timezone

from conpass.session import Session


class User:
    def __init__(self, samaccountname, dn, bad_password_count, bad_password_time, lockout_window=None, lockout_threshold=None, pso=None, time_delta=None, security_threshold=None, console=None):
        self.samaccountname = samaccountname
        self.dn = dn
        self.password = None
        self.password_expired = False
        self.account_expired = False
        self.account_restricted = False
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

        return True

    def update(self, ldap_connection):
        bad_password_count, bad_password_time = ldap_connection.get_user_password_status(self.samaccountname)
        if bad_password_count != self.bad_password_count:
            if self.bad_password_time > bad_password_time and self.bad_password_count > bad_password_count and len(self.tested_passwords) > 0:
                self.console.print(f"[yellow]{self.samaccountname}[/yellow] may have [yellow]{self.tested_passwords[-1]}[/yellow] in his password history")
            """
            else:
                self.console.print(f"[yellow]{self.samaccountname}[/yellow] ({update_text})")
            """
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
        if res == Session.STATUS.SMB_CLOSED:
            return False
        self.tested_passwords.append(password)
        if res in (Session.STATUS.INVALID_PASSWORD, Session.STATUS.ACCOUNT_LOCKOUT):
            self.bad_password_count += 1
            if res == Session.STATUS.ACCOUNT_LOCKOUT and self.bad_password_count < self.lockout_threshold:
                self.console.print(
                    f"[bright_black]Account appears locked out, likely due to synchronization issues between domain controllers. "
                    f"On the queried DC, 'badPwdCount' is {self.bad_password_count}, which is below the lockout threshold of {self.lockout_threshold}. "
                    f"This discrepancy suggests the account was locked on another DC where the threshold was reached. "
                    f"Exiting anyway.[/bright_black]"
                )
            return False
        elif res == Session.STATUS.PASSWORD_EXPIRED:
            self.password_expired = True
        elif res == Session.STATUS.ACCOUNT_EXPIRED:
            self.account_expired = True
        elif res == Session.STATUS.ACCOUNT_RESTRICTION:
            self.account_restricted = True
        self.password = password
        self.bad_password_count = 0
        return True

    def __eq__(self, other):
        return isinstance(other, self.__class__) and self.samaccountname == other.samaccountname

    def __str__(self):
        return self.__repr__()

    def __repr__(self):
        return (
            f"User Information:\n"
            f"------------------\n"
            f"SAM Account Name  : {self.samaccountname}\n"
            f"Distinguished Name: {self.dn}\n"
            f"Password           : {'Set' if self.password else 'Not Set'}\n"
            f"Password Expired   : {'Yes' if self.password_expired else 'No'}\n"
            f"Account Expired    : {'Yes' if self.account_expired else 'No'}\n"
            f"Account Restricted : {'Yes' if self.account_restricted else 'No'}\n"
            f"Bad Password Count : {self.bad_password_count}\n"
            f"Bad Password Time  : {self.bad_password_time}\n"
            f"Lockout Window     : {self.lockout_window if self.lockout_window else 'Not Configured'}\n"
            f"Lockout Threshold  : {self.lockout_threshold if self.lockout_threshold else 'Not Configured'}\n"
            f"Password Settings  : {self.pso if self.pso else 'Default Policy'}\n"
            f"Tested Passwords   : {len(self.tested_passwords)} tested\n"
            f"Time Delta         : {self.time_delta if self.time_delta else 'Not Calculated'}\n"
        )

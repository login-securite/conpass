import logging

from impacket.nmb import NetBIOSError
from impacket.smbconnection import SMBConnection, SessionError

from conpass.password import PASSWD_TYPE


class Session:
    """
    Custom impacket SMB session
    """
    def __init__(self, address, target_ip, domain, console, port=445, debug=False):
        self.console = console
        self.debug = debug
        self.address = address
        self.target_ip = target_ip
        self.domain = domain
        self.port = port
        self.username = ""
        self.password = ""
        self.domain = ""

        self.smb_session = None

    def get_session(self):
        try:
            self.smb_session = SMBConnection(self.address, self.target_ip, None, sess_port=self.port)
        except Exception:
            self.console.log("Coulnd't open SMB session")
            if self.debug:
                self.console.print_exception()
            self.smb_session = None
        return self

    def login(self, username, password):
        if self.smb_session is None:
            return False
        try:
            self.smb_session.login(username, password, self.domain)
        except Exception as e:
            if "STATUS_LOGON_FAILURE" in str(e):
                self.console.log("Invalid SMB credentials")
            self.smb_session = None
            if self.debug:
                self.console.print_exception()
            return False

        self.username = username
        self.password = password
        return True

    def test_credentials(self, username, password):
        nthash = ""

        if password.get_type() == PASSWD_TYPE.NT:
            nthash = password.value
            password_value = ""
        else:
            password_value = password.value

        try:
            self.smb_session.login(username, password_value, self.domain, "", nthash)
            return True
        except SessionError:
            return False
        except Exception as e:
            self.get_session()
            self.test_credentials(username, password)

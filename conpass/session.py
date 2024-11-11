from datetime import datetime, timezone
from impacket.smbconnection import SMBConnection
from conpass.utils.ntlminfo import NtlmInfo


class Session:
    def __init__(self, address, target_ip, domain, logger):
        self.address = address
        self.target_ip = target_ip
        self.domain = domain
        self.logger = logger

        self.ttl = 3

        self.smb_session = None

    def get_session(self):
        try:
            self.smb_session = SMBConnection(self.address, self.target_ip)
            self.ttl = 3
        except Exception as e:
            self.logger.error(f"Couldn't open SMB session: {str(e)}")
            self.smb_session = None
            return False
        return self

    def test_credentials(self, username, password):
        try:
            self.smb_session.login(user=username, password=password, domain=self.domain)
            return True
        except Exception as e:
            if 'Broken pipe' in str(e):
                if self.ttl == 0:
                    self.logger.debug(f"SMB Broken pipe. Quitting.")
                    return False
                self.ttl -= 1
                import time
                time.sleep(0.5)
                #self.logger.debug(f"SMB Broken pipe. Reconnecting... ({3-self.ttl}/3)")
                self.get_session()
                self.test_credentials(username, password)
            if 'STATUS_ACCOUNT_LOCKED_OUT' in str(e):
                self.logger.error(f"DANGER: {username} LOCKED OUT (Unlock-ADAccount -Identity {username})")
            return False

    @staticmethod
    def get_dc_details(domain):
        smb_connection = SMBConnection(domain, domain)
        smb_connection.login('', '', '')
        host = smb_connection.getServerName()
        ip = smb_connection.getNMBServer().get_socket().getpeername()[0]
        smb_connection.logoff()
        return host, ip

    @staticmethod
    def get_time_delta(dc_ip, dc_host):
        utc_remote_time = NtlmInfo(dc_ip, dc_host).get_server_time()
        utc_local_time = datetime.now(timezone.utc)
        return utc_local_time - utc_remote_time

"""SMB service for authentication testing and time synchronization."""

import socket
import time
from datetime import datetime, timedelta, timezone

from impacket.nmb import NetBIOSError, NetBIOSTimeout
from impacket.smbconnection import SMBConnection
from rich.console import Console

from conpass.core.status import AuthStatus
from conpass.exceptions import AuthAttemptLostError, SmbConnectionError, UserLockedOutError
from conpass.utils import NtlmInfo, is_nt_hash, resolve_hostname


class SmbService:
    """Service for SMB operations (authentication testing, time sync)."""

    def __init__(
        self,
        dc_ip: str,
        domain: str,
        console: Console | None = None,
        max_retries: int = 3,
        timeout: int = 5,
    ):
        self.dc_ip = dc_ip
        self.domain = domain
        self.console = console
        self.max_retries = max_retries
        self.timeout = timeout
        self.last_error = ""

        self._connection: SMBConnection | None = None

    def connect(self) -> None:
        """
        Establish SMB connection to the domain controller.

        Raises:
            SmbConnectionError: If unable to establish connection after retries
        """
        self.close()
        for attempt in range(self.max_retries):
            try:
                self._connection = SMBConnection(self.dc_ip, self.dc_ip, timeout=self.timeout)
                return
            except Exception as e:
                if attempt == self.max_retries - 1:
                    raise SmbConnectionError(f"Could not establish SMB connection: {e}") from e
                time.sleep(0.5)

    def close(self) -> None:
        """Close the SMB connection, ignoring errors."""
        if self._connection:
            try:
                self._connection.close()
            except Exception:
                pass
        self._connection = None

    def test_credentials(self, username: str, password: str) -> AuthStatus:
        """
        Test credentials via SMB login (NTLM network logon).

        Automatically detects NT hash format and uses hash authentication.
        An attempt is never replayed: when the connection drops, the DC may already
        have counted it, so the caller has to account for it before trying again.

        Args:
            username: Username to test
            password: Password to test (or NT hash)

        Returns:
            AuthStatus indicating the result of the authentication attempt

        Raises:
            UserLockedOutError: If account is locked out
            AuthAttemptLostError: If the connection dropped during the attempt
            SmbConnectionError: If the connection cannot be restored
        """
        if not self._connection:
            self.connect()

        try:
            if is_nt_hash(password):
                self._connection.login(user=username, password='', domain=self.domain, nthash=password)
            else:
                self._connection.login(user=username, password=password, domain=self.domain)
        except Exception as e:
            if self._is_connection_error(e):
                self.connect()
                raise AuthAttemptLostError(f"Connection lost while testing {username}: {e}") from e

            status = AuthStatus.from_exception(e)
            if status.is_lockout:
                if self.console:
                    self.console.print(
                        f"[red]DANGER: {username} LOCKED OUT - ABORTING "
                        f"(Unlock-ADAccount -Identity {username})[/red]"
                    )
                raise UserLockedOutError(username) from e
            self.last_error = str(e)
            return status

        self._safe_logoff()
        return AuthStatus.SUCCESS

    def _safe_logoff(self) -> None:
        """Logoff after a successful login, reconnecting if the session is unusable."""
        try:
            self._connection.logoff()
        except Exception:
            self.connect()

    @staticmethod
    def _is_connection_error(exception: Exception) -> bool:
        """Check if exception means the transport failed (not an authentication answer)."""
        if isinstance(exception, (OSError, NetBIOSError, NetBIOSTimeout)) and 'STATUS_' not in str(exception):
            return True
        error_str = str(exception)
        return any(msg in error_str for msg in [
            'Broken pipe',
            'Connection reset by peer',
            'Error occurs while reading from remote',
            'timed out',
        ])

    @staticmethod
    def get_dc_details(domain: str, dns_ip: str | None = None) -> tuple[str, str]:
        """
        Get domain controller hostname and IP from domain name.

        Args:
            domain: Domain name (FQDN)
            dns_ip: Optional DNS server IP to use for resolution

        Returns:
            Tuple of (hostname, ip_address)

        Raises:
            SmbConnectionError: If DNS resolution fails or connection cannot be established
        """
        try:
            # If custom DNS is provided, resolve domain first
            if dns_ip:
                try:
                    resolved_ip = resolve_hostname(domain, dns_ip)
                    smb_connection = SMBConnection(domain, resolved_ip)
                except socket.gaierror as e:
                    raise SmbConnectionError(
                        f"DNS resolution failed for domain '{domain}' using DNS server '{dns_ip}'. "
                        f"Please check the domain name and DNS server or use --dc-ip to specify a domain controller IP address."
                    ) from e
            else:
                smb_connection = SMBConnection(domain, domain)

            smb_connection.login('', '', '')
            host = smb_connection.getServerName()
            ip = smb_connection.getNMBServer().get_socket().getpeername()[0]
            smb_connection.logoff()
            return host, ip
        except SmbConnectionError:
            # Re-raise our custom errors as-is
            raise
        except Exception as e:
            error_message = str(e)
            if any(dns_error in error_message.lower() for dns_error in [
                'getaddrinfo failed',
                'name or service not known',
                'nodename nor servname provided',
                'no such host',
                'name resolution'
            ]):
                raise SmbConnectionError(
                    f"DNS resolution failed for domain '{domain}'. "
                    f"Please check the domain name or use --dc-ip to specify a domain controller IP address."
                ) from e
            raise SmbConnectionError(f"Could not connect to domain controller for '{domain}': {e}") from e

    @staticmethod
    def get_time_delta(dc_ip: str) -> timedelta:
        """
        Get time difference between local machine and domain controller.

        Args:
            dc_ip: Domain controller IP address

        Returns:
            timedelta representing the time difference
        """
        utc_remote_time = NtlmInfo(dc_ip, dc_ip).get_server_time()
        utc_local_time = datetime.now(timezone.utc)
        return utc_local_time - utc_remote_time

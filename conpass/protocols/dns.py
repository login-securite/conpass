"""Name resolution, through a chosen DNS server or the system resolver."""

import ipaddress
import socket

import dns.exception
import dns.resolver


class DnsResolver:
    """Resolve domain controller names, usually through a DC acting as DNS server."""

    def __init__(self, nameserver: str | None, timeout: float):
        """
        Args:
            nameserver: DNS server IP, None to use the system configuration
            timeout: Timeout of a query, in seconds
        """
        self.nameserver = nameserver
        self._resolver = dns.resolver.Resolver(configure=nameserver is None)
        if nameserver:
            self._resolver.nameservers = [nameserver]
        self._resolver.lifetime = timeout

    def resolve(self, hostname: str) -> str | None:
        """Return the IPv4 address of a host (an IP is returned unchanged), None if unknown."""
        try:
            return str(ipaddress.ip_address(hostname))
        except ValueError:
            pass
        try:
            return str(self._resolver.resolve(hostname, "A")[0])
        except dns.exception.DNSException:
            pass
        if self.nameserver is None:  # also honour /etc/hosts
            try:
                return socket.gethostbyname(hostname)
            except OSError:
                pass
        return None

    def find_pdc(self, domain: str) -> str | None:
        """Hostname of the PDC Emulator from its SRV record (_ldap._tcp.pdc._msdcs.<domain>)."""
        try:
            answer = self._resolver.resolve(f"_ldap._tcp.pdc._msdcs.{domain}", "SRV")
        except dns.exception.DNSException:
            return None
        return str(answer[0].target).rstrip(".")

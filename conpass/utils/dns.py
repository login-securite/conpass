"""DNS resolution utilities with custom DNS server support."""

import socket


def _resolver(dns_server: str):
    try:
        import dns.resolver
    except ImportError:
        raise ImportError(
            "dnspython is required for custom DNS resolution. "
            "Install it with: pip install dnspython"
        ) from None

    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = [dns_server]
    return resolver


def resolve_hostname(hostname: str, dns_server: str | None = None) -> str:
    """
    Resolve a hostname to an IP address.

    Args:
        hostname: The hostname to resolve
        dns_server: Optional DNS server IP to use for resolution

    Returns:
        The resolved IP address

    Raises:
        socket.gaierror: If hostname resolution fails
    """
    if not dns_server:
        return socket.gethostbyname(hostname)

    try:
        answers = _resolver(dns_server).resolve(hostname, 'A')
        return str(answers[0])
    except ImportError:
        raise
    except Exception as e:
        raise socket.gaierror(f"DNS resolution failed for {hostname} using DNS server {dns_server}: {e}") from e


def find_pdc_hostname(domain: str, dns_server: str) -> str | None:
    """
    Find the PDC Emulator through its DNS SRV record (_ldap._tcp.pdc._msdcs.<domain>).

    Needs no credentials, so it also works in offline mode.
    """
    try:
        answers = _resolver(dns_server).resolve(f"_ldap._tcp.pdc._msdcs.{domain}", 'SRV')
        return str(answers[0].target).rstrip('.')
    except Exception:
        return None

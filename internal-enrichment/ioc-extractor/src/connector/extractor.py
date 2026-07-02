import ipaddress
from dataclasses import dataclass

from ioc_finder import find_iocs


@dataclass
class ExtractedIOC:
    type: str
    value: str


def is_public_ip(ip: str) -> bool:
    """Check if an IP address is public (not private/reserved)."""
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_global
    except ValueError:
        return False


def extract_iocs(
    text: str,
    extract_hashes: bool = True,
    extract_ipv4: bool = True,
    extract_ipv6: bool = True,
    extract_domains: bool = True,
    extract_urls: bool = True,
    skip_private_ips: bool = True,
) -> list[ExtractedIOC]:
    """
    Extract IOCs from a text string using ioc-finder.

    Args:
        text: The text content to parse for IOCs.
        extract_hashes: Whether to extract MD5, SHA-1, SHA-256 hashes.
        extract_ipv4: Whether to extract IPv4 addresses.
        extract_ipv6: Whether to extract IPv6 addresses.
        extract_domains: Whether to extract domain names.
        extract_urls: Whether to extract URLs.
        skip_private_ips: Whether to skip private/reserved IPs.

    Returns:
        A list of ExtractedIOC with type and value.
    """
    if not text or not text.strip():
        return []

    raw = find_iocs(
        text=text,
        parse_domain_from_url=False,
        parse_from_url_path=False,
        parse_domain_from_email_address=False,
        parse_address_from_cidr=False,
        parse_domain_name_from_xmpp_address=False,
        parse_urls_without_scheme=True,
    )

    iocs: list[ExtractedIOC] = []

    if extract_hashes:
        for md5 in raw.get("md5s", []):
            iocs.append(ExtractedIOC(type="md5", value=md5))
        for sha1 in raw.get("sha1s", []):
            iocs.append(ExtractedIOC(type="sha1", value=sha1))
        for sha256 in raw.get("sha256s", []):
            iocs.append(ExtractedIOC(type="sha256", value=sha256))

    if extract_ipv4:
        for ip in raw.get("ipv4s", []):
            if not skip_private_ips or is_public_ip(ip):
                iocs.append(ExtractedIOC(type="ipv4", value=ip))

    if extract_ipv6:
        for ip in raw.get("ipv6s", []):
            if not skip_private_ips or is_public_ip(ip):
                iocs.append(ExtractedIOC(type="ipv6", value=ip))

    if extract_domains:
        for domain in raw.get("domains", []):
            iocs.append(ExtractedIOC(type="domain", value=domain))

    if extract_urls:
        for url in raw.get("urls", []):
            iocs.append(ExtractedIOC(type="url", value=url))

    return iocs

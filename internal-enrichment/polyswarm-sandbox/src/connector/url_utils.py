"""URL checks applied before a Url observable is sent to the PolySwarm sandbox.

The rules match the PolySwarm enrichment connector (polyswarm-enrichment),
copied here because the two connectors are separate packages:

- URLs whose host is private, loopback, link-local, shared (CGNAT, 100.64.0.0/10),
  reserved, multicast or unspecified, a non-canonical IPv4 form, or an internal
  name (single label, .local, .internal, .lan, .corp, .home.arpa, .localhost)
  are never sent.
- Hosts are normalised (NFKC, then IDNA) before they are classified, so
  full-width and other Unicode spellings of an address or name are caught.
  A host that is still percent-encoded or not plain ASCII afterwards, or
  that has characters outside the normal host set, is never sent.
- URLs with a backslash in the authority (before the first "/") are never
  sent: browsers read it as a path separator and other parsers do not, so
  the host is ambiguous (``http://127.0.0.1\\example.com/``,
  ``http://example.com\\@10.0.0.1/``).
- Names are not DNS-resolved here: the sandbox resolves them on PolySwarm's
  network, so the checks cover literal addresses and internal names.
- URLs with a username or password (userinfo) are never sent.
- The query string and fragment are removed before submission unless the
  operator opts in.
- Logs only ever show a URL's scheme and host.
"""

import ipaddress
import re
import socket
import unicodedata
from urllib.parse import urlparse, urlsplit, urlunsplit

# Suffixes of names that only resolve inside a private network
_INTERNAL_DOMAIN_SUFFIXES = (
    ".local",
    ".internal",
    ".lan",
    ".corp",
    ".home.arpa",
    ".localhost",
)

# RFC 6598 shared address space (carrier-grade NAT), not globally routable
_SHARED_ADDRESS_SPACE = ipaddress.ip_network("100.64.0.0/10")

# Characters of a legacy numeric IPv4 form (127.1, 0x7f.0.0.1, 2130706433)
_LEGACY_IPV4_CHARS = frozenset("0123456789abcdefx.")

# Characters a normalised URL host may contain (IPv6 brackets are removed by
# urlparse). Anything else, such as "%" or "\\", is refused.
_HOST_CHARS = re.compile(r"[a-z0-9._:-]+")


def _is_private_or_noise(ip_str: str) -> bool:
    """Private, multicast, loopback and link-local IPs."""
    try:
        addr = ipaddress.ip_address(ip_str)
        return (
            addr.is_private
            or addr.is_multicast
            or addr.is_loopback
            or addr.is_link_local
        )
    except ValueError:
        return False


def _is_non_public_ip(ip_str: str) -> bool:
    """Private or noise IPs, plus reserved, shared and unspecified, or not an IP."""
    value = ip_str.strip()
    # Exactly one pair of brackets ([2001:db8::1]); anything else is malformed
    if value.startswith("[") and value.endswith("]"):
        value = value[1:-1]
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        # CIDR ranges, legacy numeric forms and malformed values are never sent
        return True
    # IPv4-mapped IPv6 (::ffff:10.0.0.1) is checked as the IPv4 it carries
    if addr.version == 6 and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    return (
        _is_private_or_noise(str(addr))
        or addr.is_reserved
        or addr.is_unspecified
        or not addr.is_global
        or (addr.version == 4 and addr in _SHARED_ADDRESS_SPACE)
    )


def _is_legacy_ipv4(host: str) -> bool:
    """True for a numeric IPv4 host that is not a canonical dotted quad.

    Resolvers accept forms like ``127.1``, ``10.1``, ``0x7f.0.0.1`` and
    ``2130706433``; ``socket.inet_aton`` normalises them. They are never
    sent, whatever address they normalise to.
    """
    if not host or not set(host.lower()) <= _LEGACY_IPV4_CHARS:
        return False
    try:
        canonical = socket.inet_ntoa(socket.inet_aton(host))
    except (OSError, ValueError):
        return False
    return canonical != host


def _is_non_public_domain(domain: str) -> bool:
    """Single-label names and internal-only suffixes (.local, .corp, ...)."""
    name = domain.strip().rstrip(".").lower()
    if "." not in name:
        return True
    return f".{name}".endswith(_INTERNAL_DOMAIN_SUFFIXES)


def _normalise_host(host: str) -> str | None:
    """ASCII form of a URL host (NFKC, then IDNA), or None when it has none.

    NFKC maps full-width digits, letters and dots to ASCII (full-width
    "127.0.0.1" becomes "127.0.0.1"). A host that is still not ASCII is
    IDNA-encoded ("b\\u00fccher.de" becomes "xn--bcher-kva.de").
    """
    name = unicodedata.normalize("NFKC", host).strip()
    if not name.isascii():
        try:
            name = name.encode("idna").decode("ascii")
        except UnicodeError:
            return None
    name = name.rstrip(".").lower()
    if not name.isascii() or not _HOST_CHARS.fullmatch(name):
        # Percent-encoded, backslash or other characters outside a host
        return None
    return name


def _is_non_public_host(host: str) -> bool:
    """Check a URL host: IP literals as IPs, everything else as a name."""
    name = _normalise_host(host)
    if not name or _is_legacy_ipv4(name):
        return True
    if ":" in name or name.startswith("["):
        # IPv6 literal (brackets already removed by urlparse for URLs)
        return _is_non_public_ip(name)
    try:
        ipaddress.ip_address(name)
    except ValueError:
        return _is_non_public_domain(name)
    return _is_non_public_ip(name)


def _parse_url(value: str):
    """urlparse that also accepts a scheme-less URL (example.com/path)."""
    return urlparse(value if "://" in value else f"//{value}")


def _raw_authority(value: str) -> str:
    """The raw authority of a URL: after "://" up to the first "/", "?" or "#"."""
    rest = value.strip()
    if "://" in rest:
        rest = rest.split("://", 1)[1]
    return re.split(r"[/?#]", rest, maxsplit=1)[0]


def url_has_userinfo(value: str) -> bool:
    """True when a URL carries a username or password (user:pass@host)."""
    try:
        parsed = _parse_url(value)
        return bool(parsed.username or parsed.password or "@" in parsed.netloc)
    except ValueError:
        return False


def is_non_public_url(value: str) -> bool:
    """True when a URL's host must not be sent to PolySwarm (or has no host)."""
    if "\\" in _raw_authority(value):
        # Browsers and other parsers disagree on the host
        return True
    try:
        hostname = _parse_url(value).hostname
    except ValueError:
        return True
    if not hostname:
        return True
    return _is_non_public_host(hostname)


def url_for_submission(value: str, send_query: bool = False) -> str:
    """The URL sent to PolySwarm: without query string and fragment unless opted in."""
    if send_query:
        return value
    parts = urlsplit(value.strip())
    if not parts.scheme or not parts.netloc:
        return value.strip().split("#", 1)[0].split("?", 1)[0]
    return urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))


def url_has_query_or_fragment(value: str) -> bool:
    """True when a URL has a query string or fragment that would be removed."""
    return "?" in value or "#" in value


def loggable_url(value: str) -> str:
    """Value safe to log: a URL is reduced to its scheme and host."""
    try:
        parsed = _parse_url(value)
        host = parsed.hostname or ""
    except ValueError:
        return "<unparseable URL>"
    if ":" in host:
        host = f"[{host}]"
    return f"{parsed.scheme}://{host}" if parsed.scheme else host

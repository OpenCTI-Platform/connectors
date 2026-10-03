"""Extraction of observables from hunt result events.

A field is mapped to an observable type either explicitly (connector mapping)
or from the tokens of its name (``DestinationIp``, ``dns.question.name``,
``process.hash.sha256``...). Every value is validated for its type, and values
that only make sense inside the monitored network (private IP addresses,
internal domain suffixes) are never turned into observables.
"""

from __future__ import annotations

import ipaddress
import re
from collections import Counter
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from urllib.parse import urlsplit

from connectors_sdk.connectors.internal_hunt.analysis import value_strings
from connectors_sdk.connectors.internal_hunt.models import HuntEvent
from connectors_sdk.models import (
    URL,
    BaseObservableEntity,
    DomainName,
    EmailAddress,
    File,
    Hostname,
    IPV4Address,
    IPV6Address,
    MACAddress,
    Reference,
    TLPMarking,
    UserAccount,
)
from connectors_sdk.models.enums import HashAlgorithm

IPV4 = "IPv4-Addr"
IPV6 = "IPv6-Addr"
DOMAIN = "Domain-Name"
URL_TYPE = "Url"
FILE = "StixFile"
EMAIL = "Email-Addr"
HOSTNAME = "Hostname"
USER_ACCOUNT = "User-Account"
MAC = "Mac-Addr"

INTERNAL_DOMAIN_SUFFIXES: tuple[str, ...] = (
    ".local",
    ".lan",
    ".internal",
    ".intranet",
    ".corp",
    ".home",
    ".localdomain",
    ".private",
    ".arpa",
    ".localhost",
    ".test",
    ".invalid",
    ".example",
)
"""Domain suffixes that never designate internet infrastructure."""

_HASH_LENGTHS: dict[int, HashAlgorithm] = {
    32: HashAlgorithm.MD5,
    40: HashAlgorithm.SHA1,
    64: HashAlgorithm.SHA256,
    128: HashAlgorithm.SHA512,
}
_HASH_TOKENS: dict[str, HashAlgorithm | None] = {
    "md5": HashAlgorithm.MD5,
    "sha1": HashAlgorithm.SHA1,
    "sha256": HashAlgorithm.SHA256,
    "sha512": HashAlgorithm.SHA512,
    "hash": None,
    "hashes": None,
}
_HASH_PAIR_KEYS: dict[str, HashAlgorithm] = {
    "md5": HashAlgorithm.MD5,
    "sha1": HashAlgorithm.SHA1,
    "sha256": HashAlgorithm.SHA256,
    "sha512": HashAlgorithm.SHA512,
}
_URL_TOKENS = frozenset({"url", "uri"})
_EMAIL_TOKENS = frozenset({"email", "mail", "sender", "recipient", "smtp"})
_DOMAIN_TOKENS = frozenset(
    {"domain", "query", "queryname", "fqdn", "sni", "servername", "question"}
)
_IP_TOKENS = frozenset(
    {"ip", "ipv4", "ipv6", "ip4", "ip6", "ipaddr", "ipaddress", "srcip", "dstip"}
)
_PEER_FIELDS = frozenset(
    {"src", "dest", "dst", "source", "destination", "remote", "client"}
)
_HOSTNAME_TOKENS = frozenset(
    {
        "host",
        "hostname",
        "computer",
        "computername",
        "device",
        "devicename",
        "workstation",
        "machine",
    }
)
_USER_TOKENS = frozenset(
    {"user", "username", "account", "accountname", "upn", "userprincipalname"}
)
_MAC_TOKENS = frozenset({"mac", "macaddr", "macaddress"})

_HEX = re.compile(r"^[0-9a-fA-F]+$")
_IP_VERSION_ACRONYM = re.compile(r"IPv([46])")
_CAMEL_BOUNDARY = re.compile(r"(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])")
_NON_ALNUM = re.compile(r"[^0-9A-Za-z]+")
_DOMAIN = re.compile(
    r"^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]$"
)
_HOSTNAME = re.compile(
    r"^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$"
)
_EMAIL = re.compile(r"^[A-Za-z0-9._%+-]{1,64}@([A-Za-z0-9.-]{1,253})$")
_MAC_ADDRESS = re.compile(r"^[0-9a-f]{2}([:-])(?:[0-9a-f]{2}\1){4}[0-9a-f]{2}$")


@dataclass(frozen=True)
class ObservableValue:
    """An observable extracted from hunt results.

    Attributes:
        observable_type: OpenCTI observable type (e.g. ``IPv4-Addr``).
        value: Normalized value (hash value for ``StixFile``).
        hash_algorithm: Hash algorithm of a ``StixFile`` value.
        count: Number of occurrences in the results.
    """

    observable_type: str
    value: str
    hash_algorithm: HashAlgorithm | None = None
    count: int = 1


def field_tokens(field: str) -> set[str]:
    """Split a field name into lowercase tokens.

    ``DestinationIp`` gives ``{"destination", "ip"}``; the concatenation of the
    tokens of each dotted segment is added as well (``IpAddress`` also gives
    ``ipaddress``).

    Args:
        field: Field name.

    Returns:
        The tokens of the field name.
    """
    tokens: set[str] = set()
    for segment in field.split("."):
        segment = _IP_VERSION_ACRONYM.sub(r"Ipv\1", segment)
        parts = [
            part.lower()
            for chunk in _NON_ALNUM.split(segment)
            for part in _CAMEL_BOUNDARY.split(chunk)
            if part
        ]
        tokens.update(parts)
        if len(parts) > 1:
            tokens.add("".join(parts))
    return tokens


def is_public_ip(value: str) -> str | None:
    """Return the observable type of a globally routable IP address.

    Args:
        value: Candidate IP address.

    Returns:
        ``IPv4-Addr`` or ``IPv6-Addr``, or ``None`` if the value is not a public IP address.
    """
    try:
        address = ipaddress.ip_address(value.strip())
    except ValueError:
        return None
    if not address.is_global:
        return None
    return IPV4 if address.version == 4 else IPV6


def is_public_domain(value: str) -> bool:
    """Return whether a value is a domain name of the internet (not internal)."""
    domain = value.strip().lower().rstrip(".")
    if not _DOMAIN.match(domain) or is_public_ip(domain) is not None:
        return False
    return not domain.endswith(INTERNAL_DOMAIN_SUFFIXES)


def normalize_domain(value: str) -> str:
    """Return the normalized form of a domain name."""
    return value.strip().lower().rstrip(".")


def _public_host(host: str) -> bool:
    """Return whether the host part of a URL or email designates internet infrastructure."""
    return is_public_ip(host) is not None or is_public_domain(host)


def _url_value(value: str) -> str | None:
    """Validate a URL pointing to internet infrastructure."""
    text = value.strip()
    try:
        parts = urlsplit(text)
    except ValueError:
        return None
    if parts.scheme.lower() not in ("http", "https", "ftp", "ftps"):
        return None
    if not parts.hostname or not _public_host(parts.hostname):
        return None
    return text


def _email_value(value: str) -> str | None:
    """Validate an email address of an internet domain."""
    text = value.strip()
    match = _EMAIL.match(text)
    if match is None or not is_public_domain(match.group(1)):
        return None
    return text.lower()


def _hash_values(
    value: str, algorithm: HashAlgorithm | None
) -> list[tuple[HashAlgorithm, str]]:
    """Extract file hashes from a single hash or a ``ALG=hex,ALG=hex`` list."""
    text = value.strip()
    if "=" in text:
        hashes: list[tuple[HashAlgorithm, str]] = []
        for pair in re.split(r"[,;\s]+", text):
            key, _, digest = pair.partition("=")
            pair_algorithm = _HASH_PAIR_KEYS.get(_NON_ALNUM.sub("", key).lower())
            if pair_algorithm and _is_hash(digest, pair_algorithm):
                hashes.append((pair_algorithm, digest.lower()))
        return hashes
    resolved = algorithm or _HASH_LENGTHS.get(len(text))
    if resolved is not None and _is_hash(text, resolved):
        return [(resolved, text.lower())]
    return []


def _is_hash(value: str, algorithm: HashAlgorithm) -> bool:
    """Return whether a value is a hex digest of the given algorithm."""
    return bool(_HEX.match(value)) and _HASH_LENGTHS.get(len(value)) == algorithm


def _field_types(tokens: set[str]) -> list[str]:
    """Return the candidate observable types of a field from its name tokens."""
    candidates: list[str] = []
    if tokens & _HASH_TOKENS.keys():
        candidates.append(FILE)
    if tokens & _URL_TOKENS:
        candidates.append(URL_TYPE)
    if tokens & _EMAIL_TOKENS:
        candidates.append(EMAIL)
    if tokens & _DOMAIN_TOKENS:
        candidates.append(DOMAIN)
    if tokens & _IP_TOKENS or (len(tokens) == 1 and tokens <= _PEER_FIELDS):
        candidates.append(IPV4)
    if tokens & _HOSTNAME_TOKENS:
        candidates.append(HOSTNAME)
    if tokens & _USER_TOKENS:
        candidates.append(USER_ACCOUNT)
    if tokens & _MAC_TOKENS:
        candidates.append(MAC)
    return candidates


def _hash_algorithm_hint(tokens: set[str]) -> HashAlgorithm | None:
    """Return the hash algorithm named by the field, if any."""
    for token in sorted(tokens):
        algorithm = _HASH_TOKENS.get(token)
        if algorithm is not None:
            return algorithm
    return None


def _ip_observables(value: str, tokens: set[str]) -> list[ObservableValue]:
    """Validate a public IP address."""
    ip_type = is_public_ip(value)
    return [ObservableValue(ip_type, value.strip())] if ip_type else []


def _domain_observables(value: str, tokens: set[str]) -> list[ObservableValue]:
    """Validate an internet domain name."""
    if is_public_domain(value):
        return [ObservableValue(DOMAIN, normalize_domain(value))]
    return []


def _url_observables(value: str, tokens: set[str]) -> list[ObservableValue]:
    """Validate a URL of internet infrastructure."""
    url = _url_value(value)
    return [ObservableValue(URL_TYPE, url)] if url else []


def _email_observables(value: str, tokens: set[str]) -> list[ObservableValue]:
    """Validate an email address of an internet domain."""
    email = _email_value(value)
    return [ObservableValue(EMAIL, email)] if email else []


def _file_observables(value: str, tokens: set[str]) -> list[ObservableValue]:
    """Validate one or several file hashes."""
    hint = _hash_algorithm_hint(tokens)
    return [
        ObservableValue(FILE, digest, algorithm)
        for algorithm, digest in _hash_values(value, hint)
    ]


def _hostname_observables(value: str, tokens: set[str]) -> list[ObservableValue]:
    """Validate a host name."""
    hostname = value.strip().lower().rstrip(".")
    return [ObservableValue(HOSTNAME, hostname)] if _HOSTNAME.match(hostname) else []


def _user_observables(value: str, tokens: set[str]) -> list[ObservableValue]:
    """Validate a user account name."""
    user = value.strip()
    valid = 0 < len(user) <= 256 and "\n" not in user
    return [ObservableValue(USER_ACCOUNT, user)] if valid else []


def _mac_observables(value: str, tokens: set[str]) -> list[ObservableValue]:
    """Validate a MAC address."""
    mac = value.strip().lower()
    if _MAC_ADDRESS.match(mac):
        return [ObservableValue(MAC, mac.replace("-", ":"))]
    return []


_VALIDATORS: dict[str, Callable[[str, set[str]], list[ObservableValue]]] = {
    IPV4: _ip_observables,
    IPV6: _ip_observables,
    DOMAIN: _domain_observables,
    URL_TYPE: _url_observables,
    EMAIL: _email_observables,
    FILE: _file_observables,
    HOSTNAME: _hostname_observables,
    USER_ACCOUNT: _user_observables,
    MAC: _mac_observables,
}


def observables_from_value(
    observable_type: str, value: str, tokens: set[str] | None = None
) -> list[ObservableValue]:
    """Validate a value for an observable type.

    Args:
        observable_type: Candidate observable type (``IPv4-Addr`` stands for any IP).
        value: Raw value.
        tokens: Tokens of the field name (hash algorithm hints).

    Returns:
        The observables the value designates (several for a list of hashes).
    """
    validator = _VALIDATORS.get(observable_type)
    return validator(value, tokens or set()) if validator else []


def _first_match(
    text: str, candidates: Sequence[str], tokens: set[str]
) -> list[ObservableValue]:
    """Return the observables of the first candidate type the value is valid for."""
    for candidate in candidates:
        found = observables_from_value(candidate, text, tokens)
        if found:
            return found
    return []


def extract_observables(
    events: Iterable[HuntEvent],
    allowed_types: Iterable[str],
    explicit_fields: Mapping[str, str] | None = None,
    max_items: int = 100,
) -> list[ObservableValue]:
    """Extract the observables of the allowed types from result events.

    Args:
        events: Result events (after benign suppression).
        allowed_types: Observable types the run may create.
        explicit_fields: Field name to observable type mapping (case-insensitive)
            taking precedence over the field name heuristics.
        max_items: Maximum number of observables returned.

    Returns:
        The observables, the most frequent first.
    """
    allowed = set(allowed_types)
    if not allowed or max_items <= 0:
        return []
    explicit = {name.lower(): kind for name, kind in (explicit_fields or {}).items()}
    counts: Counter[tuple[str, str, HashAlgorithm | None]] = Counter()
    field_cache: dict[str, tuple[set[str], list[str]]] = {}
    for event in events:
        for field, raw in event.fields.items():
            if field not in field_cache:
                tokens = field_tokens(field)
                kind = explicit.get(field.lower())
                field_cache[field] = (tokens, [kind] if kind else _field_types(tokens))
            tokens, candidates = field_cache[field]
            for text in value_strings(raw) if candidates else []:
                counts.update(
                    (found.observable_type, found.value, found.hash_algorithm)
                    for found in _first_match(text, candidates, tokens)
                    if found.observable_type in allowed
                )
    ranked = sorted(counts.items(), key=lambda item: (-item[1], item[0][0], item[0][1]))
    return [
        ObservableValue(kind, value, algorithm, count)
        for (kind, value, algorithm), count in ranked[:max_items]
    ]


def to_observable_model(
    observable: ObservableValue,
    author: Reference | None,
    markings: Sequence[TLPMarking | Reference],
) -> BaseObservableEntity:
    """Build the connectors-sdk observable model of an extracted observable.

    Args:
        observable: Extracted observable.
        author: Author of the hunt, if any.
        markings: Markings of the hunt.

    Returns:
        The observable model.
    """
    marks: list[TLPMarking | Reference] | None = list(markings) or None
    kind, value = observable.observable_type, observable.value
    if kind == IPV4:
        return IPV4Address(value=value, author=author, markings=marks)
    if kind == IPV6:
        return IPV6Address(value=value, author=author, markings=marks)
    if kind == DOMAIN:
        return DomainName(value=value, author=author, markings=marks)
    if kind == URL_TYPE:
        return URL(value=value, author=author, markings=marks)
    if kind == EMAIL:
        return EmailAddress(value=value, author=author, markings=marks)
    if kind == FILE:
        algorithm = observable.hash_algorithm or HashAlgorithm.SHA256
        return File(hashes={algorithm: value}, author=author, markings=marks)
    if kind == HOSTNAME:
        return Hostname(value=value, author=author, markings=marks)
    if kind == USER_ACCOUNT:
        return UserAccount(user_id=value, author=author, markings=marks)
    if kind == MAC:
        return MACAddress(value=value, author=author, markings=marks)
    raise ValueError(f"Unsupported observable type '{kind}'.")

"""LogScale lookups of the values of indicator hunts.

Each observable type is looked up in the fields that hold it in the two kinds of
data a Falcon Next-Gen SIEM repository holds: the Falcon sensor events
(``RemoteAddressIP4``, ``DomainName``, ``SHA256HashData``...) and the third-party
events parsed to the CrowdStrike Parsing Standard (CPS), which follows the
Elastic Common Schema (``source.ip``, ``dns.question.name``, ``file.hash.sha256``...).
A type with no field is not looked up, and its values are reported not searched.

The boolean operators of LogScale do not combine functions such as ``in()``, so
every field is matched with a regular expression filter (``field = /.../``), the
filters joined with ``or``. Regular expressions also match a literal ``*``, which
a wildcard pattern cannot escape.
"""

import re
from dataclasses import dataclass

from connectors_sdk.connectors.internal_hunt import IocBatch

HASH_FIELDS: dict[str, tuple[str, ...]] = {
    "MD5": ("MD5HashData", "file.hash.md5", "process.hash.md5"),
    "SHA-1": ("file.hash.sha1", "process.hash.sha1"),
    "SHA-256": ("SHA256HashData", "file.hash.sha256", "process.hash.sha256"),
}
"""Fields of each hash algorithm, Falcon fields first (Falcon events hold no SHA-1 field)."""


@dataclass(frozen=True)
class LogScaleLookup:
    """How the values of one observable type are looked up.

    Attributes:
        fields: Fields holding the values.
        match: ``exact`` (the whole value), ``domain`` (the domain and its
            subdomains) or ``substring`` (the value within the field).
        ignore_case: Whether the comparison ignores the case.
    """

    fields: tuple[str, ...]
    match: str = "exact"
    ignore_case: bool = True


DOMAIN_FIELDS = ("DomainName", "dns.question.name", "destination.domain", "url.domain")
"""Fields holding a domain: the DNS requests of the Falcon sensor, then CPS."""

LOOKUPS: dict[str, LogScaleLookup] = {
    "IPv4-Addr": LogScaleLookup(
        ("RemoteAddressIP4", "source.ip", "destination.ip"), ignore_case=False
    ),
    "IPv6-Addr": LogScaleLookup(("RemoteAddressIP6", "source.ip", "destination.ip")),
    "Domain-Name": LogScaleLookup(DOMAIN_FIELDS, match="domain"),
    "Hostname": LogScaleLookup(DOMAIN_FIELDS),
    "Url": LogScaleLookup(
        ("url.original", "url.full"), match="substring", ignore_case=False
    ),
    "Email-Addr": LogScaleLookup(
        ("email.from.address", "email.to.address", "user.email")
    ),
    "Mac-Addr": LogScaleLookup(("source.mac", "destination.mac", "host.mac")),
}
"""Lookup of each observable type, file hashes aside."""

_REGEX_SPECIAL = re.compile(r"([\\.^$|?*+()\[\]{}/])")


def _regex_text(value: str) -> str:
    """Escape a value matched literally inside a LogScale regular expression.

    Only the metacharacters are escaped: LogScale refuses escape sequences it
    does not know.
    """
    return _REGEX_SPECIAL.sub(r"\\\1", value)


def batch_lookup(batch: IocBatch) -> LogScaleLookup | None:
    """Return the lookup of a batch, or ``None`` when no field holds its type.

    Args:
        batch: Values of one observable type (and hash algorithm).

    Returns:
        The lookup of its values.
    """
    if batch.observable_type == "StixFile":
        fields = HASH_FIELDS.get(batch.hash_algorithm or "")
        return LogScaleLookup(fields) if fields else None
    return LOOKUPS.get(batch.observable_type)


def build_logscale_lookup(batch: IocBatch, lookup: LogScaleLookup) -> str:
    """Build the LogScale query finding the events holding a value of a batch.

    Args:
        batch: Values of one observable type.
        lookup: How the type is looked up.

    Returns:
        The query, one regular expression filter per field joined with ``or``.
    """
    alternatives = "|".join(_regex_text(value) for value in batch.values)
    if lookup.match == "domain":
        pattern = f"(?:^|\\.)(?:{alternatives})$"
    elif lookup.match == "substring":
        pattern = f"(?:{alternatives})"
    else:
        pattern = f"^(?:{alternatives})$"
    flags = "i" if lookup.ignore_case else ""
    return " or ".join(f"{field} = /{pattern}/{flags}" for field in lookup.fields)

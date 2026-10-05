"""UDM search lookups of the values of indicator hunts.

Each observable type is looked up in the UDM fields that hold it, mostly through
the UDM grouped fields (``ip``, ``domain``, ``hostname``, ``email``), which
SecOps expands to every field of their kind. File hashes are looked up in the
file fields of their algorithm: the grouped ``hash`` field misses some of them
(``target.process.file.sha256``, the file of a launched process). A type with
no UDM field is not looked up, and its values are reported not searched.
"""

import re
from dataclasses import dataclass

from connectors_sdk.connectors.internal_hunt import IocBatch

FILE_NOUNS = (
    "target.process.file",
    "principal.process.file",
    "target.process.parent_process.file",
    "principal.process.parent_process.file",
    "target.file",
    "principal.file",
    "src.file",
    "about.file",
)
"""UDM fields holding a file, whose hashes are looked up."""

HASH_FIELDS = {"MD5": "md5", "SHA-1": "sha1", "SHA-256": "sha256"}
"""UDM field of each hash algorithm (UDM stores no other algorithm)."""


@dataclass(frozen=True)
class UdmLookup:
    """How the values of one observable type are looked up.

    Attributes:
        fields: UDM fields (or grouped fields) holding the values.
        match: ``exact`` (the whole value), ``domain`` (the domain and its
            subdomains) or ``substring`` (the value within the field).
        nocase: Whether the comparison ignores the case.
    """

    fields: tuple[str, ...]
    match: str = "exact"
    nocase: bool = True


LOOKUPS: dict[str, UdmLookup] = {
    "IPv4-Addr": UdmLookup(("ip",), nocase=False),
    "IPv6-Addr": UdmLookup(("ip",)),
    "Domain-Name": UdmLookup(("domain",), match="domain"),
    "Hostname": UdmLookup(("hostname",)),
    "Email-Addr": UdmLookup(("email",)),
    "Url": UdmLookup(
        ("target.url", "principal.url", "src.url", "network.http.referral_url"),
        match="substring",
        nocase=False,
    ),
    "Mac-Addr": UdmLookup(
        (
            "principal.mac",
            "target.mac",
            "src.mac",
            "observer.mac",
            "principal.asset.mac",
            "target.asset.mac",
        )
    ),
}
"""Lookup of each observable type, file hashes aside."""

_REGEX_SPECIAL = re.compile(r"([\\.^$|?*+()\[\]{}/])")


def udm_string(value: str) -> str:
    """Quote a value as a UDM search string literal."""
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def udm_regex(pattern: str) -> str:
    """Write a regular expression as a UDM search regex literal (RE2)."""
    return f"/{pattern}/"


def _regex_text(value: str) -> str:
    """Escape a value matched literally inside a regular expression."""
    return _REGEX_SPECIAL.sub(r"\\\1", value)


def batch_lookup(batch: IocBatch) -> UdmLookup | None:
    """Return the lookup of a batch, or ``None`` when UDM holds no field for its type.

    Args:
        batch: Values of one observable type (and hash algorithm).

    Returns:
        The lookup of its values.
    """
    if batch.observable_type == "StixFile":
        field = HASH_FIELDS.get(batch.hash_algorithm or "")
        if field is None:
            return None
        return UdmLookup(tuple(f"{noun}.{field}" for noun in FILE_NOUNS))
    return LOOKUPS.get(batch.observable_type)


def build_udm_lookup(batch: IocBatch, lookup: UdmLookup) -> str:
    """Build the UDM search finding the events holding a value of a batch.

    Args:
        batch: Values of one observable type.
        lookup: How the type is looked up.

    Returns:
        The UDM search, one comparison per value and field joined with ``OR``.
    """
    suffix = " nocase" if lookup.nocase else ""
    clauses = []
    for value in batch.values:
        if lookup.match == "domain":
            literal = udm_regex(f"(^|\\.){_regex_text(value)}$")
        elif lookup.match == "substring":
            literal = udm_regex(_regex_text(value))
        else:
            literal = udm_string(value)
        clauses.extend(f"{field} = {literal}{suffix}" for field in lookup.fields)
    return " OR ".join(clauses)

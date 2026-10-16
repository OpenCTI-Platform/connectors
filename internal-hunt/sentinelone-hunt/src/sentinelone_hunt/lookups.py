"""PowerQuery lookups of the values of indicator hunts.

Each observable type is looked up in the fields of the SentinelOne EDR
telemetry that hold it: network connections (``dst.ip.address``), DNS requests
(``event.dns.request``), URLs (``url.address``) and the hashes of files, of
process images (SHA-1 and SHA-256) and of loaded modules (SHA-256). A type no
field holds (email and MAC addresses) is not looked up, and its values are
reported not searched.
"""

from dataclasses import dataclass

from connectors_sdk.connectors.internal_hunt import IocBatch
from sentinelone_hunt.powerquery import quote_string

HASH_FIELDS: dict[str, tuple[str, ...]] = {
    "MD5": ("tgt.file.md5",),
    "SHA-1": (
        "tgt.file.sha1",
        "src.process.image.sha1",
        "src.process.parent.image.sha1",
    ),
    "SHA-256": (
        "tgt.file.sha256",
        "src.process.image.sha256",
        "src.process.parent.image.sha256",
        "module.sha256",
    ),
}
"""Fields of each hash algorithm: files, process images, loaded modules.

Only fields the SentinelOne queries use are listed: with the EDR schema check,
an unknown field fails the query."""


@dataclass(frozen=True)
class PowerQueryLookup:
    """How the values of one observable type are looked up.

    Attributes:
        fields: Fields holding the values.
        match: ``exact`` (the whole value), ``domain`` (the domain and its
            subdomains) or ``substring`` (the value within the field).
    """

    fields: tuple[str, ...]
    match: str = "exact"


LOOKUPS: dict[str, PowerQueryLookup] = {
    "IPv4-Addr": PowerQueryLookup(("dst.ip.address", "src.ip.address")),
    "IPv6-Addr": PowerQueryLookup(("dst.ip.address", "src.ip.address")),
    "Domain-Name": PowerQueryLookup(("event.dns.request",), match="domain"),
    "Hostname": PowerQueryLookup(("event.dns.request",)),
    "Url": PowerQueryLookup(("url.address",), match="substring"),
}
"""Lookup of each observable type, file hashes aside."""

LOOKUP_FIELDS: tuple[str, ...] = tuple(
    dict.fromkeys(
        field
        for lookup in (*LOOKUPS.values(), *map(PowerQueryLookup, HASH_FIELDS.values()))
        for field in lookup.fields
    )
)
"""Every field an indicator lookup reads, so that its results hold them."""


def batch_lookup(batch: IocBatch) -> PowerQueryLookup | None:
    """Return the lookup of a batch, or ``None`` when no field holds its type.

    Args:
        batch: Values of one observable type (and hash algorithm).

    Returns:
        The lookup of its values.
    """
    if batch.observable_type == "StixFile":
        fields = HASH_FIELDS.get(batch.hash_algorithm or "")
        return PowerQueryLookup(fields) if fields else None
    return LOOKUPS.get(batch.observable_type)


def build_powerquery_lookup(batch: IocBatch, lookup: PowerQueryLookup) -> str:
    """Build the PowerQuery filter of the events holding a value of a batch.

    Values compare without case: ``in:anycase`` for whole values,
    ``contains`` (case-insensitive) for substrings, ``ends_with`` for the
    subdomains of a domain.

    Args:
        batch: Values of one observable type.
        lookup: How the type is looked up.

    Returns:
        The filter, one condition per field joined with ``or``.
    """
    values = ",".join(quote_string(value) for value in batch.values)
    conditions = []
    for field in lookup.fields:
        if lookup.match == "substring":
            conditions.append(f"{field} contains ({values})")
            continue
        conditions.append(f"{field} in:anycase ({values})")
        if lookup.match == "domain":
            conditions.extend(
                f"{field} ends_with {quote_string('.' + value)}"
                for value in batch.values
            )
    return " or ".join(conditions)

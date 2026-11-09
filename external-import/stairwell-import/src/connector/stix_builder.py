from __future__ import annotations

import ipaddress
import json
import re
from datetime import datetime, timezone
from typing import Any, Iterable
from urllib.parse import urlsplit

from connectors_sdk.models import (
    URL,
    BaseIdentifiedObject,
    DomainName,
    ExternalReference,
    File,
    Indicator,
    IPV4Address,
    IPV6Address,
    Note,
    OrganizationAuthor,
    Reference,
    Relationship,
    Report,
    TLPMarking,
)
from pycti import Grouping

# Objects are built with the connectors-sdk models, which validate them and
# compute OpenCTI's canonical IDs, and are serialized to STIX dicts. The
# Grouping stays hand-built: the SDK has no model for it.

_TLP_LEVELS = ("clear", "white", "green", "amber", "amber+strict", "red")
_TLP_MODELS: dict[str, TLPMarking] = {
    level: TLPMarking(level=level) for level in _TLP_LEVELS
}


def _stix(model: BaseIdentifiedObject) -> dict[str, Any]:
    """The STIX 2.1 dict for an SDK model."""
    return json.loads(model.to_stix2_object().serialize())


# TLP marking definitions as the SDK builds them, keyed by level. Every bundle
# carries the definitions its objects reference.
_TLP_OBJECTS: dict[str, dict[str, Any]] = {
    level: _stix(model) for level, model in _TLP_MODELS.items()
}
TLP_IDS: dict[str, str] = {level: obj["id"] for level, obj in _TLP_OBJECTS.items()}
# TLP:CLEAR and TLP:WHITE share one ID; a bundle that references it carries
# the CLEAR definition, OpenCTI's current name for that level.
_TLP_BY_ID: dict[str, dict[str, Any]] = {
    obj["id"]: obj for level, obj in _TLP_OBJECTS.items() if level != "white"
}

# The author of every SDO and relationship this connector creates. Its ID is
# OpenCTI's for an organization named "Stairwell", so it is the same object
# everywhere. The SDK stamps `modified` with the build time; fixed values keep
# a restart from re-dating the stored identity.
_AUTHOR_DATE = datetime(2026, 1, 1, tzinfo=timezone.utc)
_AUTHOR_MODEL = OrganizationAuthor(
    name="Stairwell",
    description="Stairwell, Inc. — global file corpus and threat intelligence.",
    created=_AUTHOR_DATE,
)
_AUTHOR: dict[str, Any] = {
    **_stix(_AUTHOR_MODEL),
    "created": "2026-01-01T00:00:00.000Z",
    "modified": "2026-01-01T00:00:00.000Z",
}
STAIRWELL_IDENTITY_ID: str = _AUTHOR["id"]


def _parse_time(value: str) -> datetime:
    """An RFC 3339 timestamp as an aware datetime.

    Python 3.11+ parses the API's nanosecond fractions, truncating them to
    microseconds.
    """
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def tlp_marking(tlp: str) -> str:
    return TLP_IDS.get(tlp.lower(), TLP_IDS["amber"])


def _markings(tlp: str) -> list[TLPMarking]:
    return [_TLP_MODELS.get(tlp.lower(), _TLP_MODELS["amber"])]


def stairwell_identity() -> dict[str, Any]:
    return dict(_AUTHOR)


def make_external_reference(
    source_name: str, url: str, description: str | None = None
) -> dict[str, Any]:
    ref = ExternalReference(source_name=source_name, url=url, description=description)
    return ref.model_dump(exclude_none=True)


def _external_references(
    refs: Iterable[dict[str, Any]] | None,
) -> list[ExternalReference] | None:
    return [ExternalReference(**ref) for ref in refs] if refs else None


def make_note(
    abstract: str,
    content: str,
    object_refs: Iterable[str],
    tlp: str,
) -> dict[str, Any]:
    """Note whose ID derives from its abstract and content (never a timestamp).

    Content must name its subject (the hash, host, IP, or ASN), or identical
    notes about different observables would share one ID.
    """
    return _stix(
        Note(
            abstract=abstract,
            content=content,
            objects=[Reference(id=ref) for ref in object_refs],
            author=_AUTHOR_MODEL,
            markings=_markings(tlp),
        )
    )


def make_relationship(
    source_id: str,
    target_id: str,
    relationship_type: str = "related-to",
    tlp: str = "amber",
) -> dict[str, Any]:
    return _stix(
        Relationship(
            type=relationship_type,
            source=Reference(id=source_id),
            target=Reference(id=target_id),
            author=_AUTHOR_MODEL,
            markings=_markings(tlp),
        )
    )


def _observable(
    model: type[BaseIdentifiedObject],
    tlp: str,
    stix_id: str | None = None,
    labels: Iterable[str] | None = None,
    external_references: Iterable[dict[str, Any]] | None = None,
    **properties: Any,
) -> dict[str, Any]:
    """An observable's STIX dict, built and validated by its SDK model.

    `stix_id` replaces the computed ID (see `make_file`). Unset properties
    are left out, so an update never clears a stored value.
    """
    obj = _stix(
        model(
            markings=_markings(tlp),
            labels=list(labels) if labels else None,
            external_references=_external_references(external_references),
            **{k: v for k, v in properties.items() if v is not None},
        )
    )
    if stix_id:
        obj["id"] = stix_id
    return obj


def make_ipv4(value: str, tlp: str = "amber", **kwargs: Any) -> dict[str, Any]:
    return _observable(IPV4Address, tlp, value=value, **kwargs)


def make_ipv6(value: str, tlp: str = "amber", **kwargs: Any) -> dict[str, Any]:
    return _observable(IPV6Address, tlp, value=value, **kwargs)


# One DNS label: letters, digits, hyphens and underscores (SRV/DKIM names),
# not starting or ending with a hyphen.
_DNS_LABEL = re.compile(r"(?!-)[a-z0-9_-]{1,63}(?<!-)")
# A top-level domain: letters only, or an internationalised one in punycode.
_TLD = re.compile(r"[a-z]{2,63}|xn--[a-z0-9-]{1,59}")
# File extensions found in strings extracted from files that are not
# delegated top-level domains, so `kernel32.dll` is not a host name.
_FILE_EXTENSIONS = frozenset(
    {
        "apk",
        "asp",
        "aspx",
        "bak",
        "bat",
        "bin",
        "cer",
        "cfg",
        "cmd",
        "conf",
        "cpl",
        "crt",
        "css",
        "csv",
        "dat",
        "db",
        "dll",
        "dmg",
        "dmp",
        "doc",
        "docx",
        "drv",
        "dylib",
        "exe",
        "gz",
        "hta",
        "htm",
        "html",
        "img",
        "inf",
        "ini",
        "iso",
        "jar",
        "js",
        "jse",
        "json",
        "jsp",
        "lib",
        "lnk",
        "log",
        "msi",
        "ocx",
        "pdb",
        "pdf",
        "pem",
        "php",
        "plist",
        "ppt",
        "pptx",
        "rar",
        "rtf",
        "scr",
        "sql",
        "sys",
        "tar",
        "tmp",
        "txt",
        "vbe",
        "vbs",
        "wsf",
        "xls",
        "xlsm",
        "xlsx",
        "xml",
        "yaml",
        "yml",
    }
)


def normalize_domain(value: Any) -> str | None:
    """`value` as a well-formed DNS name of two or more labels, or None.

    Values come from file strings and DNS answers; one malformed
    `domain-name.value` makes OpenCTI reject the bundle it is in. A trailing
    root dot is dropped, and internationalised names are stored in their
    ASCII (punycode) form. A dotted string whose last label is not a
    top-level domain (an address, a version number, a file name) is not a
    host name.
    """
    if not isinstance(value, str):
        return None
    # DNS names are case-insensitive; one name must be one object.
    name = value.strip().rstrip(".").lower()
    # Only internationalised names go through the IDNA codec: it can reject
    # the underscore labels of service names (`_sip._tcp`), which are ASCII.
    if not name.isascii():
        try:
            name = name.encode("idna").decode("ascii")
        except UnicodeError:
            return None
    labels = name.split(".")
    if (
        len(name) > 253
        or len(labels) < 2
        or not all(_DNS_LABEL.fullmatch(label) for label in labels)
        or not _TLD.fullmatch(labels[-1])
        or labels[-1] in _FILE_EXTENSIONS
    ):
        return None
    return name


def make_domain(value: str, tlp: str = "amber", **kwargs: Any) -> dict[str, Any] | None:
    """Domain-Name SCO for a well-formed DNS name (see `normalize_domain`)."""
    name = normalize_domain(value)
    if name is None:
        return None
    return _observable(DomainName, tlp, value=name, **kwargs)


_HASH_LENGTHS = {"SHA-256": 64, "SHA-1": 40, "MD5": 32}
_HEX = re.compile(r"[0-9a-fA-F]+")


def valid_hash(algo: str, value: Any) -> bool:
    """True when `value` is a well-formed `algo` digest (hex of the right length).

    Hashes come from API responses; one malformed value in a File SCO makes
    OpenCTI reject the whole bundle it is in.
    """
    length = _HASH_LENGTHS.get(algo)
    return (
        length is not None
        and isinstance(value, str)
        and len(value) == length
        and bool(_HEX.fullmatch(value))
    )


def make_file(
    hashes: dict[str, str],
    tlp: str = "amber",
    **kwargs: Any,
) -> dict[str, Any]:
    """File SCO; hashes that are not well-formed digests are left out.

    With a SHA-256, the ID is the SDK's for that hash alone: the spec's File
    ID uses the first of MD5, SHA-1, SHA-256 present, so it would change
    whenever an optional hash appears or disappears.
    """
    valid = {algo: h.lower() for algo, h in hashes.items() if valid_hash(algo, h)}
    stix_id = (
        File(hashes={"SHA-256": valid["SHA-256"]}).id if "SHA-256" in valid else None
    )
    return _observable(File, tlp, stix_id=stix_id, hashes=valid or None, **kwargs)


def make_file_by_sha256(
    sha256: str,
    tlp: str = "amber",
    sha1: str | None = None,
    md5: str | None = None,
    **kwargs: Any,
) -> dict[str, Any]:
    """File SCO for a SHA-256; invalid optional hashes are left out."""
    if not valid_hash("SHA-256", sha256):
        raise ValueError(f"not a SHA-256 digest: {sha256!r}")
    hashes = {"SHA-256": sha256}
    for algo, value in (("SHA-1", sha1), ("MD5", md5)):
        if value is not None:
            hashes[algo] = value
    return make_file(hashes, tlp, **kwargs)


_URL_SCHEMES = {"http", "https", "ftp", "ftps"}
_URL_MAX_LENGTH = 2048


def make_url(value: str, tlp: str = "amber", **kwargs: Any) -> dict[str, Any] | None:
    """URL SCO for a well-formed http(s)/ftp(s) URL, or None.

    Values come from strings extracted from files; one malformed `url.value`
    makes OpenCTI reject the whole bundle it is in.
    """
    if (
        not isinstance(value, str)
        or len(value) > _URL_MAX_LENGTH
        or any(ch.isspace() or ord(ch) < 32 or ord(ch) == 127 for ch in value)
    ):
        return None
    try:
        parts = urlsplit(value)
        # `port` raises ValueError on a non-numeric or out-of-range port, and
        # port 0 is not one a URL can be fetched from.
        if parts.port == 0:
            return None
    except ValueError:
        return None
    if parts.scheme.lower() not in _URL_SCHEMES or not parts.hostname:
        return None
    return _observable(URL, tlp, value=value, **kwargs)


# The only IPv6 block IANA allocates as global unicast; `is_global` alone
# also passes deprecated site-local (fec0::/10), reserved (4000::/3) and,
# on some Python releases, IPv4-mapped forms of public IPv4 addresses
# (::ffff:8.8.8.8).
_IPV6_GLOBAL_UNICAST = ipaddress.ip_network("2000::/3")
# The IPv6 documentation prefix, inside 2000::/3; older Python releases
# count it as global.
_IPV6_DOCUMENTATION = ipaddress.ip_network("3fff::/20")


def make_ip(value: str, tlp: str = "amber", **kwargs: Any) -> dict[str, Any] | None:
    """IPv4/IPv6 SCO for a valid, publicly routable address (normalised), or None.

    Values come from strings extracted from files and from DNS answers, so
    `1.2.3.4:80` or free text must not become an address SCO. Loopback,
    private, link-local, reserved, unspecified and multicast addresses are
    left out: they are common in malware strings and sinkholed answers, and
    say nothing about the file or domain they would be related to.
    `ipaddress` counts multicast as global, so it is checked separately, and
    an IPv6 address must also be global unicast (2000::/3) and outside the
    documentation prefix (3fff::/20).
    """
    try:
        addr = ipaddress.ip_address(str(value).strip())
    except ValueError:
        return None
    if not addr.is_global or addr.is_multicast:
        return None
    if addr.version == 6 and (
        addr not in _IPV6_GLOBAL_UNICAST or addr in _IPV6_DOCUMENTATION
    ):
        return None
    if addr.version == 6:
        return make_ipv6(str(addr), tlp=tlp, **kwargs)
    return make_ipv4(str(addr), tlp=tlp, **kwargs)


def make_indicator(
    pattern: str,
    name: str,
    valid_from: str,
    valid_until: str | None = None,
    indicator_types: Iterable[str] = ("malicious-activity",),
    description: str | None = None,
    score: int | None = None,
    external_references: list[dict[str, Any]] | None = None,
    tlp: str = "amber",
) -> dict[str, Any]:
    return _stix(
        Indicator(
            name=name,
            pattern=pattern,
            pattern_type="stix",
            valid_from=_parse_time(valid_from),
            valid_until=_parse_time(valid_until) if valid_until else None,
            indicator_types=list(indicator_types),
            description=description,
            score=int(score) if score is not None else None,
            external_references=_external_references(external_references),
            created=_parse_time(valid_from),
            author=_AUTHOR_MODEL,
            markings=_markings(tlp),
        )
    )


def make_based_on_relationship(
    indicator_id: str, target_id: str, tlp: str = "amber"
) -> dict[str, Any]:
    return make_relationship(
        source_id=indicator_id,
        target_id=target_id,
        relationship_type="based-on",
        tlp=tlp,
    )


def make_grouping(
    name: str,
    object_refs: Iterable[str],
    created: str,
    description: str | None = None,
    context: str = "malware-analysis",
    tlp: str = "amber",
) -> dict[str, Any]:
    """Grouping whose ID derives from name, context, and `created`."""
    obj: dict[str, Any] = {
        "type": "grouping",
        "spec_version": "2.1",
        "id": Grouping.generate_id(name, context, created),
        "created_by_ref": STAIRWELL_IDENTITY_ID,
        "created": created,
        "modified": created,
        "object_marking_refs": [tlp_marking(tlp)],
        "name": name,
        "context": context,
        "object_refs": list(object_refs),
    }
    if description:
        obj["description"] = description
    return obj


def make_report(
    name: str,
    object_refs: Iterable[str],
    published: str,
    description: str | None = None,
    report_types: Iterable[str] = ("threat-report",),
    tlp: str = "amber",
) -> dict[str, Any]:
    return _stix(
        Report(
            name=name,
            publication_date=_parse_time(published),
            objects=[Reference(id=ref) for ref in object_refs],
            description=description,
            report_types=list(report_types),
            author=_AUTHOR_MODEL,
            markings=_markings(tlp),
        )
    )


def with_markings(objects: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """`objects` plus the TLP marking definitions they reference.

    Without the definition in the bundle, OpenCTI can reject the objects that
    reference it (MISSING_REFERENCE_ERROR).
    """
    out = [obj for obj in objects if obj]
    present = {obj["id"] for obj in out}
    for obj in list(out):
        for ref in obj.get("object_marking_refs") or []:
            if ref in _TLP_BY_ID and ref not in present:
                out.append(_TLP_BY_ID[ref])
                present.add(ref)
    return out

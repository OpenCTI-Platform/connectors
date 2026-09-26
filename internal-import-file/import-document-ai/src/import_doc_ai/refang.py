"""Refang the defanged observables of an extracted STIX bundle.

Threat reports defang their indicators so that nobody follows them by mistake
(``admin[at]filigran[dot]io``, ``hxxps://evil[.]com``, ``2001[:]db8[:][:]1``)
and the extraction keeps that spelling in the observable values. OpenCTI
rejects the values of the types it validates (``INCORRECT_OBSERVABLE_FORMAT``),
which in turn fails every container referencing them, and stores the others
(URLs) under a value no search or enrichment will ever match.
"""

import json
import re
import urllib.parse
from dataclasses import dataclass, field

import stix2
from import_doc_ai.util import merge_duplicate_objects, remap_references_in_bundle

REFANGABLE_OBSERVABLE_TYPES = frozenset(
    {"domain-name", "email-addr", "hostname", "ipv4-addr", "ipv6-addr", "url"}
)

# One separator wrapped in brackets, parentheses or braces, whitespace
# tolerated inside and around: "[.]", "(dot)", " [at] ", "{:}", "[://]", "[/]".
# A mismatched pair such as "[.}" is matched too, but only to be reported.
_BRACKETED_SEPARATOR_RE = re.compile(
    r"\s*(?P<open>[\[({])\s*(?P<token>://|\.|dot|@|at|:|/)\s*(?P<close>[\])}])\s*",
    re.IGNORECASE,
)
_CLOSING_BRACKETS = {"[": "]", "(": ")", "{": "}"}
_SPACED_DOT_RE = re.compile(r"\s+dot\s+", re.IGNORECASE)
_SPACED_AT_RE = re.compile(r"\s+at\s+", re.IGNORECASE)
_DEFANGED_SCHEME_RE = re.compile(r"^(?P<scheme>hxxps?|fxps?)(?=:)", re.IGNORECASE)

_SEPARATORS = {
    "://": "://",
    ".": ".",
    "dot": ".",
    "@": "@",
    "at": "@",
    ":": ":",
    "/": "/",
}
_SCHEMES = {"hxxp": "http", "hxxps": "https", "fxp": "ftp", "fxps": "ftps"}

# The separators a value of each type can hold: "[at]" in a domain name does
# not make a defanged domain name, so it is left for the validation to reject.
_SEPARATORS_BY_TYPE = {
    "domain-name": {"."},
    "hostname": {"."},
    "email-addr": {".", "@"},
    "ipv4-addr": {".", "/"},
    "ipv6-addr": {".", ":", "/"},
    "url": {".", "@", ":", "://", "/"},
}
# A value of these types never holds a space, so " dot " / " at " can only be
# a defanged separator.
_SPACED_DOT_TYPES = {"domain-name", "hostname", "email-addr", "ipv4-addr"}
_SPACED_AT_TYPES = {"email-addr"}

# The observable syntax checks of the OpenCTI platform
# (opencti-graphql/src/utils/syntax.js): a refanged value is only kept when the
# platform accepts it. OpenCTI does not check URLs.
_DOMAIN_NAME_RE = re.compile(
    r"(?=.{1,253}\Z)(?!-)(?:[^\s.](?:[^\s.]{0,61}[^\s.])?\.)+[^\s.]{2,63}"
)
_HOSTNAME_RE = re.compile(
    r"(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-_]*[a-zA-Z0-9])\.)*"
    r"([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-_]*[A-Za-z0-9])"
)
_EMAIL_ADDR_RE = re.compile(
    r"[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
    r"(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*"
)
_IPV4_ADDR_RE = re.compile(
    r"(?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}"
    r"(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])"
    r"(?:\/([0-9]|[1-2][0-9]|3[0-2]))?"
)
_IPV6_ADDR_RE = re.compile(
    r"(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}"
    r"|([0-9a-fA-F]{1,4}:){1,7}:"
    r"|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}"
    r"|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}"
    r"|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}"
    r"|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}"
    r"|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}"
    r"|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})"
    r"|:((:[0-9a-fA-F]{1,4}){1,7}|:)"
    r"|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}"
    r"|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}"
    r"(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])"
    r"|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}"
    r"(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))"
    r"(?:\/([0-9]|[1-9][0-9]|1[0-1][0-9]|12[0-8]))?"
)
_NETWORK_SCHEMES = {"http", "https", "ftp", "ftps"}


def _is_host(host: str | None) -> bool:
    return bool(host) and any(
        pattern.fullmatch(host)
        for pattern in (_HOSTNAME_RE, _DOMAIN_NAME_RE, _IPV4_ADDR_RE, _IPV6_ADDR_RE)
    )


def _is_url(value: str) -> bool:
    """Whether a URL is well-formed.

    A URL with an authority (``scheme://host``) or without a scheme
    (``host/path``) needs a valid host, a ``mailto:`` URL valid addresses, and
    a network scheme (http, https, ftp, ftps) an authority.
    """
    if any(character.isspace() for character in value):
        return False
    try:
        parts = urllib.parse.urlsplit(value)
        if parts.port is not None and not parts.hostname:
            return False
    except ValueError:  # an unbalanced IPv6 host or a non-numeric port
        return False
    scheme = parts.scheme.lower()
    if scheme == "mailto":
        return all(
            _EMAIL_ADDR_RE.fullmatch(address) for address in parts.path.split(",")
        )
    hierarchical_part = value[len(parts.scheme) + 1 :] if parts.scheme else value
    if hierarchical_part.startswith("//"):
        return _is_host(parts.hostname)
    if not scheme:
        return _is_host(parts.path.split("/", 1)[0])
    return scheme not in _NETWORK_SCHEMES


_VALIDATORS = {
    "domain-name": _DOMAIN_NAME_RE.fullmatch,
    "hostname": _HOSTNAME_RE.fullmatch,
    "email-addr": _EMAIL_ADDR_RE.fullmatch,
    "ipv4-addr": _IPV4_ADDR_RE.fullmatch,
    "ipv6-addr": _IPV6_ADDR_RE.fullmatch,
    "url": _is_url,
}


def _substitute_defang_notations(observable_type: str, value: str) -> str:
    separators = _SEPARATORS_BY_TYPE[observable_type]

    def refang_separator(match: re.Match) -> str:
        separator = _SEPARATORS[match.group("token").lower()]
        if (
            _CLOSING_BRACKETS[match.group("open")] != match.group("close")
            or separator not in separators
        ):
            return match.group(0)
        return separator

    refanged = _BRACKETED_SEPARATOR_RE.sub(refang_separator, value)
    if observable_type in _SPACED_DOT_TYPES:
        refanged = _SPACED_DOT_RE.sub(".", refanged)
    if observable_type in _SPACED_AT_TYPES:
        refanged = _SPACED_AT_RE.sub("@", refanged)
    if observable_type == "url":
        refanged = _DEFANGED_SCHEME_RE.sub(
            lambda match: _SCHEMES[match.group("scheme").lower()], refanged
        )
    return refanged.strip() if refanged != value else value


def _is_valid(observable_type: str, value: str) -> bool:
    if _BRACKETED_SEPARATOR_RE.search(value) or _DEFANGED_SCHEME_RE.match(value):
        return False
    return bool(_VALIDATORS[observable_type](value))


def refang_observable_value(observable_type: str, value: str) -> str:
    """Refang the value of a STIX cyber-observable.

    Handled notations, case-insensitive: ``[.]`` ``(.)`` ``{.}`` ``[dot]``
    ``(dot)`` ``{dot}`` and `` dot ``, ``[at]`` ``(at)`` ``{at}`` ``[@]`` and
    `` at `` (email addresses), ``[:]``, ``[://]``, ``[/]``, and the ``hxxp``,
    ``hxxps``, ``fxp`` and ``fxps`` schemes (URLs); brackets must pair up. Only
    the separators a value of the type can hold are refanged, and the refanged
    value is only returned when it is a valid value of the type: one OpenCTI
    accepts, and a well-formed URL for URLs, which OpenCTI does not check.

    Args:
        observable_type (str): The STIX type of the observable
            (domain-name, email-addr, hostname, ipv4-addr, ipv6-addr or url;
            any other type is returned as is).
        value (str): The value of the observable.

    Returns:
        (str): The refanged value, or ``value`` itself when it holds no defang
            notation or does not refang into a valid value.

    Examples:
        >>> refang_observable_value("email-addr", "admin[at]filigran[dot]io")
        'admin@filigran.io'
        >>> refang_observable_value("url", "hxxps://filigran[.]io/about")
        'https://filigran.io/about'
        >>> refang_observable_value("email-addr", "admin[at][dot]io")
        'admin[at][dot]io'
    """
    if observable_type not in REFANGABLE_OBSERVABLE_TYPES:
        return value
    candidate = _substitute_defang_notations(observable_type, value)
    if candidate != value and _is_valid(observable_type, candidate):
        return candidate
    return value


@dataclass(frozen=True)
class RefangedObservable:
    """An observable whose value was refanged."""

    observable_type: str
    original_id: str
    original_value: str
    refanged_id: str
    refanged_value: str


@dataclass(frozen=True)
class UnrefangedObservable:
    """An observable whose value looks defanged but does not refang."""

    observable_type: str
    observable_id: str
    value: str


@dataclass
class RefangSummary:
    """What refanging a STIX bundle changed."""

    refanged: list[RefangedObservable] = field(default_factory=list)
    unrefanged: list[UnrefangedObservable] = field(default_factory=list)
    merged_objects: int = 0


def _with_refanged_value(
    observable: stix2.v21._Observable, value: str
) -> stix2.v21._Observable:
    observable_dict = json.loads(observable.serialize())
    observable_dict["value"] = value
    observable_dict.pop("defanged", None)
    # Without an id, stix2 derives the deterministic one from the new value.
    del observable_dict["id"]
    return stix2.parse(observable_dict, allow_custom=True)


def _with_id(
    stix_object: stix2.v21._STIXBase21, object_id: str
) -> stix2.v21._STIXBase21:
    object_dict = json.loads(stix_object.serialize())
    object_dict["id"] = object_id
    return stix2.parse(object_dict, allow_custom=True)


def _merge_rewritten_relationships(
    bundle: stix2.Bundle, rewritten_ids: set[str]
) -> stix2.Bundle:
    """Give the relationships a rewrite made identical their first one's id.

    OpenCTI identifies a relationship by its type, endpoints and time frame:
    once two spellings of an observable are merged, their relationships to the
    same object are one relationship.
    """
    first_id_by_key: dict[tuple, str] = {}
    duplicate_ids: dict[str, str] = {}
    for obj in bundle.get("objects", []):
        if obj.get("type") != "relationship":
            continue
        key = (
            obj.get("relationship_type"),
            obj.get("source_ref"),
            obj.get("target_ref"),
            obj.get("start_time"),
            obj.get("stop_time"),
        )
        first_id = first_id_by_key.setdefault(key, obj["id"])
        if first_id != obj["id"] and rewritten_ids & {first_id, obj["id"]}:
            duplicate_ids[obj["id"]] = first_id
    if not duplicate_ids:
        return bundle
    objects = [
        _with_id(obj, duplicate_ids[obj["id"]]) if obj["id"] in duplicate_ids else obj
        for obj in bundle.get("objects", [])
    ]
    return remap_references_in_bundle(
        stix2.Bundle(type=bundle["type"], objects=objects, allow_custom=True),
        duplicate_ids,
    )


def refang_bundle_observables(
    bundle: stix2.Bundle,
) -> tuple[stix2.Bundle, RefangSummary]:
    """Refang the defanged observables of a STIX bundle.

    The value of each domain-name, email-addr, hostname, ipv4-addr, ipv6-addr
    and url observable is refanged (see ``refang_observable_value``). A
    refanged observable gets the id stix2 derives from its new value and drops
    its ``defanged`` flag, every reference to its former id is rewritten, and
    the objects that end up describing the same thing (two spellings of one
    address, their relationships to a same object) are merged. Any other
    object or property, free text included, is left untouched, and so is a
    value that does not refang into a valid one.

    Args:
        bundle (stix2.Bundle): The STIX bundle to process.

    Returns:
        (tuple[stix2.Bundle, RefangSummary]): The refanged bundle (``bundle``
            itself when none of its observables is refanged) and what changed.

    Examples:
        >>> import stix2
        >>> email = stix2.EmailAddress(value="admin[at]filigran[dot]io", defanged=True)
        >>> bundle = stix2.Bundle(objects=[email], allow_custom=True)
        >>> refanged_bundle, summary = refang_bundle_observables(bundle)
        >>> refanged_bundle.objects[0].value
        'admin@filigran.io'
    """
    summary = RefangSummary()
    refanged_objects: dict[str, stix2.v21._Observable] = {}
    id_mapping: dict[str, str] = {}
    for stix_object in bundle.get("objects", []):
        observable_type = stix_object.get("type")
        value = stix_object.get("value")
        if (
            observable_type not in REFANGABLE_OBSERVABLE_TYPES
            or not isinstance(stix_object, stix2.v21._Observable)
            or not isinstance(value, str)
        ):
            continue
        candidate = _substitute_defang_notations(observable_type, value)
        if candidate == value:
            continue
        if not _is_valid(observable_type, candidate):
            summary.unrefanged.append(
                UnrefangedObservable(observable_type, stix_object["id"], value)
            )
            continue
        refanged_object = _with_refanged_value(stix_object, candidate)
        refanged_objects[stix_object["id"]] = refanged_object
        if refanged_object["id"] != stix_object["id"]:
            id_mapping[stix_object["id"]] = refanged_object["id"]
        summary.refanged.append(
            RefangedObservable(
                observable_type=observable_type,
                original_id=stix_object["id"],
                original_value=value,
                refanged_id=refanged_object["id"],
                refanged_value=candidate,
            )
        )
    if not refanged_objects:
        return bundle, summary

    objects = [
        refanged_objects.get(obj["id"], obj) for obj in bundle.get("objects", [])
    ]
    rewritten_relationship_ids = {
        obj["id"]
        for obj in objects
        if obj.get("type") == "relationship"
        and (obj.get("source_ref") in id_mapping or obj.get("target_ref") in id_mapping)
    }
    refanged_bundle = remap_references_in_bundle(
        stix2.Bundle(type=bundle["type"], objects=objects, allow_custom=True),
        id_mapping,
    )
    refanged_bundle = _merge_rewritten_relationships(
        refanged_bundle, rewritten_relationship_ids
    )
    merged_bundle = merge_duplicate_objects(refanged_bundle)
    summary.merged_objects = len(refanged_bundle.get("objects", [])) - len(
        merged_bundle.get("objects", [])
    )
    return merged_bundle, summary

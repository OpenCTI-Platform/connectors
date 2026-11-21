"""
Transform stage: Luminar STIX 2.1 records -> OpenCTI-ready STIX objects.

Every supported object in a batch is considered on its own (not only objects
that hang off a relationship). Per batch the steps are:

    normalize/deduplicate -> expiration filter -> enrich -> validate
        -> derive observables -> reference integrity -> relationship schema

Failures are isolated per object: a malformed or unsupported record is
counted and skipped, the rest of the batch continues.
"""

import copy
import json
import re
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

import stix2
from pycti import (
    Campaign,
)
from pycti import Identity as OpenCTIIdentity
from pycti import (
    Infrastructure,
    IntrusionSet,
    Malware,
    StixCoreRelationship,
    Tool,
    Vulnerability,
)

from .expiration import is_expired, parse_stix_timestamp
from .luminar_manager import STIX_ID_PATTERN
from .relationship_schema import RelationshipSchema

AUTHOR_NAME = "Cognyte Luminar"
DEFAULT_SCORE = 80
KNOWN_MALICIOUS_IPS_SCORE = 90
USER_ACCOUNT_SCORE = 100
RELATIONSHIP_DESCRIPTION = "Relationship by Cognyte Luminar"

FEED_DEFAULT_DESCRIPTIONS = {
    "iocs": "Luminar IOC",
    "leakedrecords": "Luminar Leaked Credentials",
    "cyberfeeds": "Luminar Cyberfeeds",
}

# Luminar extension attributes. OpenCTI does not persist unknown custom
# properties or foreign STIX extensions, so every attribute that is not mapped
# onto a native OpenCTI attribute is exported as a label
# "luminar.<key>:<value>" (key without its "luminar_" prefix).
LUMINAR_LABEL_PREFIX = "luminar"
# Every object sent is labelled with the Luminar feed (TAXII collection alias)
# it came from, e.g. "luminar.feed:iocs". Labels accumulate on upsert, so an
# object delivered by several feeds carries one label per feed.
FEED_LABEL_KEY = "feed"
# Never exported: extension metadata and the tenant id (same on every object).
LUMINAR_IGNORED_ATTRIBUTES = {"extension_type", "luminar_tenant_id"}
# Already mapped onto native OpenCTI attributes, per STIX type.
LUMINAR_NATIVE_ATTRIBUTES = {"indicator": {"score"}, "vulnerability": {"x_cvss"}}
# Near-unique per object on live data (e.g. 2,716 distinct resolving domains
# per 4,699 indicators): as labels they would create one label per value, so
# they are appended to the object's description instead.
LUMINAR_DESCRIPTION_ATTRIBUTES = {
    "collection_date",
    "computer_name",
    "resolving_domains",
    "url",
}
# Ignored when comparing objects for collapsing (see _collapse_identical_objects).
COLLAPSE_IGNORED_KEYS = {"id", "created", "modified"}
# Longer labels are unreadable in OpenCTI; such values go to the description.
MAX_LABEL_LENGTH = 128

SDO_TYPES = {
    "attack-pattern",
    "campaign",
    "course-of-action",
    "grouping",
    "identity",
    "incident",
    "indicator",
    "infrastructure",
    "intrusion-set",
    "location",
    "malware",
    "malware-analysis",
    "note",
    "observed-data",
    "opinion",
    "report",
    "threat-actor",
    "tool",
    "vulnerability",
}
SCO_TYPES = {
    "artifact",
    "autonomous-system",
    "directory",
    "domain-name",
    "email-addr",
    "email-message",
    "file",
    "ipv4-addr",
    "ipv6-addr",
    "mac-addr",
    "mutex",
    "network-traffic",
    "process",
    "software",
    "url",
    "user-account",
    "windows-registry-key",
    "x509-certificate",
}
SRO_TYPES = {"relationship", "sighting"}
MARKING_TYPE = "marking-definition"
SUPPORTED_TYPES = SDO_TYPES | SCO_TYPES | SRO_TYPES | {MARKING_TYPE}

# Containers whose ``object_refs`` is required (and must be non-empty).
CONTAINER_TYPES = {"grouping", "note", "observed-data", "opinion", "report"}
# Containers still ingested when none of their object_refs can be resolved.
EMPTY_CONTAINER_TYPES = {"grouping", "report"}
# Containers sent after the relationships (they may reference them);
# observed-data only references observables and is sent with the entities.
PHASE_CONTAINER_TYPES = CONTAINER_TYPES - {"observed-data"}

# OpenCTI identifies these entities by name (identity: name + identity_class),
# so Luminar objects with distinct ids but the same name are merged into one
# entity. Their Luminar ids survive only as stix-id aliases, which concurrent
# upserts of that entity can lose (MISSING_REFERENCE_ERROR seen live for 3
# "REDLINE" malware). Objects sent after the entities therefore reference them
# by OpenCTI's standard id, computed as the platform does. Types whose standard
# id depends on platform-side resolution (threat-actor, location) or on
# timestamp formatting (incident) keep their Luminar ids.
OPENCTI_STANDARD_IDS = {
    "campaign": lambda o: Campaign.generate_id(o["name"]),
    "identity": lambda o: OpenCTIIdentity.generate_id(o["name"], o["identity_class"]),
    "infrastructure": lambda o: Infrastructure.generate_id(o["name"]),
    "intrusion-set": lambda o: IntrusionSet.generate_id(o["name"]),
    "malware": lambda o: Malware.generate_id(o["name"]),
    "tool": lambda o: Tool.generate_id(o["name"]),
    "vulnerability": lambda o: Vulnerability.generate_id(o["name"]),
}
# SDOs without a ``description`` property in STIX 2.1.
SDO_TYPES_WITHOUT_DESCRIPTION = {"observed-data"}
# Ref properties with dedicated handling in the integrity pass.
SPECIAL_REF_KEYS = {
    "created_by_ref",
    "object_marking_refs",
    "source_ref",
    "target_ref",
    "sighting_of_ref",
    "where_sighted_refs",
    "object_refs",
}

# Standard TLP 1.0 markings. OpenCTI uses the same ids, so a reference to one
# of them is valid even when Luminar does not ship the definition itself.
KNOWN_MARKINGS = {
    marking.id: marking
    for marking in (stix2.TLP_WHITE, stix2.TLP_GREEN, stix2.TLP_AMBER, stix2.TLP_RED)
}

# Sort key for versions without a parseable ``modified``.
_OLDEST = datetime.min.replace(tzinfo=timezone.utc)

# One STIX comparison expression: <type>:<path> [NOT] <op> '<string literal>'.
PATTERN_COMPARISON = re.compile(
    r"([a-z0-9-]+):([A-Za-z0-9_.'\-]+)\s+(NOT\s+)?(=|!=|<=|>=|<|>|IN|LIKE|MATCHES)"
    r"\s*'((?:[^'\\]|\\.)*)'"
)
VALUE_OBSERVABLES = {
    "ipv4-addr": stix2.IPv4Address,
    "ipv6-addr": stix2.IPv6Address,
    "domain-name": stix2.DomainName,
    "url": stix2.URL,
    "email-addr": stix2.EmailAddress,
}


@dataclass
class ConversionStats:
    """Counters for one batch (or, merged, for a whole run)."""

    received: int = 0
    output: int = 0
    duplicates: int = 0
    identical_objects_collapsed: int = 0
    malformed: int = 0
    expired: int = 0
    observables_created: int = 0
    dangling_refs_removed: int = 0
    dropped_dangling: int = 0
    containers_emptied: int = 0
    relationships_downgraded: int = 0
    unsupported: Counter = field(default_factory=Counter)
    output_types: Counter = field(default_factory=Counter)

    def merge(self, other: "ConversionStats") -> None:
        for name, value in vars(other).items():
            if isinstance(value, Counter):
                getattr(self, name).update(value)
            else:
                setattr(self, name, getattr(self, name) + value)

    def as_dict(self) -> Dict[str, Any]:
        result: Dict[str, Any] = {}
        for name, value in vars(self).items():
            result[name] = dict(value) if isinstance(value, Counter) else value
        return result


def _stix_to_dict(stix_object: Any) -> Dict[str, Any]:
    return json.loads(stix_object.serialize())


def _get_from_extensions(key: str, stix_object: Dict[str, Any]) -> Optional[Any]:
    """Return ``key`` from the first extension-definition extension holding it."""
    extensions = stix_object.get("extensions")
    if not isinstance(extensions, dict):
        return None
    for ext_id, ext in extensions.items():
        if ext_id.startswith("extension-definition--") and isinstance(ext, dict):
            if key in ext:
                return ext.get(key)
    return None


def _luminar_attributes(stix_object: Dict[str, Any]) -> List[Tuple[str, Any]]:
    """(key, value) pairs from the object's extension-definition extensions
    that are neither ignored nor already mapped onto native attributes."""
    extensions = stix_object.get("extensions")
    if not isinstance(extensions, dict):
        return []
    native = LUMINAR_NATIVE_ATTRIBUTES.get(stix_object.get("type"), set())
    attributes = []
    for ext_id, ext in extensions.items():
        if not ext_id.startswith("extension-definition--") or not isinstance(ext, dict):
            continue
        for key, value in ext.items():
            if key not in LUMINAR_IGNORED_ATTRIBUTES and key not in native:
                attributes.append((key, value))
    return attributes


def _render_value(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (dict, list)):
        return json.dumps(value, sort_keys=True)
    return str(value).strip()


def mask_credential(credential: str) -> str:
    """Keep the first and last character, mask the rest ("changeme" ->
    "c******e"); values of 1-2 characters are fully masked."""
    if len(credential) <= 2:
        return "*" * len(credential)
    return credential[0] + "*" * (len(credential) - 2) + credential[-1]


def _append_labels(stix_object: Dict[str, Any], key: str, labels: List[str]) -> None:
    if not labels:
        return
    existing = stix_object.get(key)
    merged = list(existing) if isinstance(existing, list) else []
    merged.extend(label for label in labels if label not in merged)
    stix_object[key] = merged


class ConverterToStix:
    """Convert raw Luminar batches into STIX objects ready for OpenCTI."""

    def __init__(
        self, logger: Any, create_observable: bool, mask_credentials: bool = False
    ) -> None:
        self.logger = logger
        self.create_observable = create_observable
        self.mask_credentials = mask_credentials
        self.author = _stix_to_dict(
            stix2.Identity(
                id=OpenCTIIdentity.generate_id(
                    name=AUTHOR_NAME, identity_class="organization"
                ),
                name=AUTHOR_NAME,
                identity_class="organization",
                description="Cognyte Luminar Threat Intelligence feeds for IOC, "
                "Leaked Records and Cyberfeeds",
            )
        )

    # ----- public entry point -----

    def convert_batch(
        self,
        feed_name: str,
        raw_objects: List[Any],
        schema: RelationshipSchema,
        now: datetime,
    ) -> Tuple[List[Dict[str, Any]], ConversionStats]:
        """Transform one extracted batch. Returns (stix_objects, stats).

        The returned list is empty when nothing valid remains; otherwise it
        contains the author identity and any standard TLP marking referenced.
        """
        stats = ConversionStats(received=len(raw_objects))

        grouped = self._normalize(raw_objects, stats)
        aliases = self._collapse_identical_objects(grouped, stats)

        valid: Dict[str, Dict[str, Any]] = {}
        for stix_id, versions in grouped.items():
            chosen = self._select_version(feed_name, versions, now, stats)
            if chosen is not None:
                valid[stix_id] = chosen
        if aliases:
            self._rewrite_references(valid, aliases)

        if self.create_observable:
            for indicator in [o for o in valid.values() if o["type"] == "indicator"]:
                for derived in self._observables_from_indicator(feed_name, indicator):
                    if derived["id"] not in valid:
                        valid[derived["id"]] = derived
                        if derived["type"] != "relationship":
                            stats.observables_created += 1

        # Removing refs can leave an object invalid (e.g. network-traffic
        # without src_ref/dst_ref); dropping it can in turn leave other refs
        # dangling, so repeat until stable.
        while True:
            self._enforce_reference_integrity(valid, stats)
            invalid = [i for i, o in valid.items() if not self._is_still_valid(o)]
            if not invalid:
                break
            for stix_id in invalid:
                del valid[stix_id]
                stats.malformed += 1
                self.logger.warning(
                    "[CONVERTER] Skipping object invalid after reference cleanup",
                    {"feed": feed_name, "id": stix_id},
                )
        self._apply_relationship_schema(valid, schema, stats)
        self._reference_standard_ids(valid, stats)
        self._label_feed(valid, feed_name)

        if not valid:
            return [], stats

        used_markings: Set[str] = set()
        for stix_object in valid.values():
            used_markings.update(stix_object.get("object_marking_refs", []))
            for granular in stix_object.get("granular_markings", []):
                used_markings.add(granular.get("marking_ref"))
        extra_markings = [
            _stix_to_dict(KNOWN_MARKINGS[m])
            for m in sorted(used_markings, key=str)
            if m in KNOWN_MARKINGS and m not in valid
        ]

        result = [self.author] + extra_markings + list(valid.values())
        stats.output = len(valid)
        stats.output_types.update(o["type"] for o in valid.values())
        return result, stats

    # ----- normalize / deduplicate / select -----

    def _normalize(
        self, raw_objects: List[Any], stats: ConversionStats
    ) -> Dict[str, List[Dict[str, Any]]]:
        """Structural checks and supported-type filter; groups the versions of
        each id, newest first (by ``modified``, later in the stream on ties or
        when ``modified`` is absent)."""
        grouped: Dict[str, List[Tuple[int, Dict[str, Any]]]] = {}
        for position, raw in enumerate(raw_objects):
            if not isinstance(raw, dict):
                stats.malformed += 1
                continue
            stix_type = raw.get("type")
            stix_id = raw.get("id")
            if (
                not isinstance(stix_type, str)
                or not isinstance(stix_id, str)
                or not STIX_ID_PATTERN.match(stix_id)
                or stix_id.split("--", 1)[0] != stix_type
            ):
                stats.malformed += 1
                self.logger.debug(
                    "[CONVERTER] Skipping object without a valid type/id",
                    {"type": stix_type, "id": stix_id},
                )
                continue
            if stix_type not in SUPPORTED_TYPES:
                stats.unsupported[stix_type] += 1
                continue
            grouped.setdefault(stix_id, []).append((position, raw))

        result: Dict[str, List[Dict[str, Any]]] = {}
        for stix_id, entries in grouped.items():
            stats.duplicates += len(entries) - 1
            entries.sort(
                key=lambda entry: (
                    parse_stix_timestamp(entry[1].get("modified")) or _OLDEST,
                    entry[0],
                ),
                reverse=True,
            )
            result[stix_id] = [raw for _, raw in entries]
        return result

    @staticmethod
    def _collapse_identical_objects(
        grouped: Dict[str, List[Dict[str, Any]]], stats: ConversionStats
    ) -> Dict[str, str]:
        """Collapse SDOs/SCOs that are identical apart from id and timestamps.

        Luminar issues a new id per occurrence of e.g. the software "Exploit" or
        the location {country: "US"} (hundreds per iocs batch). Such objects
        share every identity property, so OpenCTI merges them into one entity
        anyway; the redundant concurrent upserts of that entity cause lock
        contention and lost stix-id aliases, and relationships to the lost ids
        fail with MISSING_REFERENCE_ERROR. Returns {dropped_id: kept_id}; the
        first occurrence is kept. Relationships, sightings and markings are
        never collapsed; distinct leaked credentials differ in content.
        """
        kept_by_content: Dict[str, str] = {}
        aliases: Dict[str, str] = {}
        for stix_id in list(grouped):
            newest = grouped[stix_id][0]
            if newest["type"] not in SDO_TYPES and newest["type"] not in SCO_TYPES:
                continue
            content = json.dumps(
                {k: v for k, v in newest.items() if k not in COLLAPSE_IGNORED_KEYS},
                sort_keys=True,
                default=str,
            )
            kept = kept_by_content.setdefault(content, stix_id)
            if kept != stix_id:
                aliases[stix_id] = kept
                del grouped[stix_id]
        stats.identical_objects_collapsed += len(aliases)
        return aliases

    @staticmethod
    def _rewrite_references(
        objects: Dict[str, Dict[str, Any]], aliases: Dict[str, str]
    ) -> None:
        """Point every top-level reference at the kept id of collapsed objects."""
        for stix_object in objects.values():
            for key, value in list(stix_object.items()):
                if key.endswith("_ref") and isinstance(value, str):
                    stix_object[key] = aliases.get(value, value)
                elif (
                    key.endswith("_refs")
                    and isinstance(value, list)
                    and all(isinstance(ref, str) for ref in value)
                ):
                    stix_object[key] = list(
                        dict.fromkeys(aliases.get(ref, ref) for ref in value)
                    )

    def _select_version(
        self,
        feed_name: str,
        versions: List[Dict[str, Any]],
        now: datetime,
        stats: ConversionStats,
    ) -> Optional[Dict[str, Any]]:
        """Return the newest valid, non-expired version of one object.

        A malformed version falls back to the next older one. When the newest
        valid version is expired the object is excluded (older versions are
        not resurrected). Versions are deep-copied: the extraction stage keeps
        hydrated records in a cache shared across batches.
        """
        last_error = ""
        for raw in versions:
            stix_object = copy.deepcopy(raw)
            try:
                expired = is_expired(stix_object, now)
                self._enrich(feed_name, stix_object)
                self._validate(stix_object)
            except Exception as err:  # pylint: disable=broad-exception-caught
                last_error = f"{err.__class__.__name__}: {err}"
                continue
            if expired:
                stats.expired += 1
                return None
            return stix_object
        stats.malformed += 1
        self.logger.warning(
            "[CONVERTER] Skipping malformed object",
            {"feed": feed_name, "id": versions[0].get("id"), "error": last_error},
        )
        return None

    # ----- enrich -----

    def _enrich(self, feed_name: str, stix_object: Dict[str, Any]) -> None:
        """Apply the connector's OpenCTI-specific additions to one object.

        Source values are never overwritten: defaults are only set when the
        property is absent.
        """
        stix_type = stix_object["type"]
        default_description = FEED_DEFAULT_DESCRIPTIONS.get(
            feed_name, "Cognyte Luminar"
        )

        if stix_type != MARKING_TYPE and stix_type not in SCO_TYPES:
            stix_object.setdefault("spec_version", "2.1")

        if stix_type == "indicator":
            self._enrich_indicator(stix_object)
        elif stix_type == "vulnerability":
            self._enrich_vulnerability(stix_object)
        elif stix_type == "incident" and feed_name == "leakedrecords":
            stix_object.setdefault("source", AUTHOR_NAME)
            stix_object.setdefault("incident_type", "compromise")
            stix_object.setdefault("severity", "high")
        elif stix_type == "user-account":
            self._enrich_user_account(stix_object)
        elif stix_type in SCO_TYPES:
            stix_object.setdefault("x_opencti_score", DEFAULT_SCORE)
            stix_object.setdefault("x_opencti_description", default_description)

        if stix_type in SDO_TYPES - SDO_TYPES_WITHOUT_DESCRIPTION:
            stix_object.setdefault("description", default_description)
        if stix_type == "report" or (
            feed_name == "cyberfeeds" and stix_type in SDO_TYPES
        ):
            stix_object.setdefault("x_opencti_score", DEFAULT_SCORE)
        if stix_type != MARKING_TYPE:
            self._export_luminar_attributes(stix_object)

    @staticmethod
    def _label_feed(objects: Dict[str, Dict[str, Any]], feed_name: str) -> None:
        """Add ``luminar.feed:<feed>`` to every object, including derived
        observables and relationships (markings carry no labels)."""
        label = f"{LUMINAR_LABEL_PREFIX}.{FEED_LABEL_KEY}:{feed_name}"
        for stix_object in objects.values():
            if stix_object["type"] == MARKING_TYPE:
                continue
            key = "x_opencti_labels" if stix_object["type"] in SCO_TYPES else "labels"
            _append_labels(stix_object, key, [label])

    @staticmethod
    def _export_luminar_attributes(stix_object: Dict[str, Any]) -> None:
        """Render unmapped Luminar extension attributes as labels
        ``luminar.<key>:<value>``; near-unique, long or structured values are
        appended to the description as ``- luminar.<key>: <value>`` lines."""
        is_sco = stix_object["type"] in SCO_TYPES
        labels: List[str] = []
        lines: List[str] = []
        for key, value in _luminar_attributes(stix_object):
            name = key[len("luminar_") :] if key.startswith("luminar_") else key
            values = value if isinstance(value, list) else [value]
            rendered = [_render_value(v) for v in values if v is not None and v != ""]
            rendered = list(dict.fromkeys(r for r in rendered if r))
            if not rendered:
                continue
            candidate_labels = [f"{LUMINAR_LABEL_PREFIX}.{name}:{r}" for r in rendered]
            if (
                key in LUMINAR_DESCRIPTION_ATTRIBUTES
                or any(isinstance(v, (dict, list)) for v in values)
                or any(len(label) > MAX_LABEL_LENGTH for label in candidate_labels)
            ):
                lines.append(f"- {LUMINAR_LABEL_PREFIX}.{name}: {', '.join(rendered)}")
            else:
                labels.extend(candidate_labels)

        _append_labels(stix_object, "x_opencti_labels" if is_sco else "labels", labels)
        if not lines:
            return
        description_key = "x_opencti_description" if is_sco else "description"
        if stix_object["type"] in SDO_TYPES_WITHOUT_DESCRIPTION:
            return
        block = "Luminar attributes:\n" + "\n".join(lines)
        existing = stix_object.get(description_key)
        stix_object[description_key] = f"{existing}\n\n{block}" if existing else block

    @staticmethod
    def _indicator_score(indicator: Dict[str, Any]) -> int:
        """Luminar's own 0-100 indicator score when provided, otherwise the
        connector's historical defaults."""
        explicit = indicator.get("x_opencti_score")
        if isinstance(explicit, int) and not isinstance(explicit, bool):
            return explicit
        luminar_score = _get_from_extensions("score", indicator)
        if (
            isinstance(luminar_score, (int, float))
            and not isinstance(luminar_score, bool)
            and 0 <= luminar_score <= 100
        ):
            return int(round(luminar_score))
        name = indicator.get("name")
        if isinstance(name, str) and "Known Malicious IPs" in name:
            return KNOWN_MALICIOUS_IPS_SCORE
        return DEFAULT_SCORE

    @staticmethod
    def _enrich_vulnerability(vulnerability: Dict[str, Any]) -> None:
        """Map Luminar CVSS v3.x onto native OpenCTI attributes (the other
        Luminar attributes become labels like every extension attribute)."""
        cvss = _get_from_extensions("x_cvss", vulnerability)
        if isinstance(cvss, dict):
            v3 = cvss.get("V3_1") or cvss.get("V3_0")
            if isinstance(v3, dict):
                try:
                    base_score = float(v3["baseScore"])
                except (KeyError, TypeError, ValueError):
                    base_score = None
                if base_score is not None:
                    vulnerability.setdefault("x_opencti_cvss_base_score", base_score)
                if isinstance(v3.get("baseSeverity"), str):
                    vulnerability.setdefault(
                        "x_opencti_cvss_base_severity", v3["baseSeverity"]
                    )
                if isinstance(v3.get("vectorString"), str):
                    vulnerability.setdefault(
                        "x_opencti_cvss_vector_string", v3["vectorString"]
                    )

    def _enrich_indicator(self, indicator: Dict[str, Any]) -> None:
        indicator.setdefault("x_opencti_score", self._indicator_score(indicator))
        if isinstance(indicator.get("name"), str) and indicator["name"]:
            indicator.setdefault("description", indicator["name"])

        # STIX and OpenCTI both reject valid_until <= valid_from. The
        # connector historically salvaged such indicators by dropping
        # valid_until; it has already been checked for expiry at this point.
        valid_from = parse_stix_timestamp(indicator.get("valid_from"))
        valid_until = parse_stix_timestamp(indicator.get("valid_until"))
        if valid_from and valid_until and valid_until <= valid_from:
            self.logger.debug(
                "[CONVERTER] Dropping valid_until not after valid_from",
                {"id": indicator["id"]},
            )
            indicator.pop("valid_until", None)

    def _enrich_user_account(self, user_account: Dict[str, Any]) -> None:
        """One OpenCTI object per leaked credential: OpenCTI identifies a
        User-Account by account_type + user_id + account_login, and Luminar
        sends only account_login (often a placeholder such as "[unknown]"), so
        records would merge. The Luminar record id is used as ``user_id`` (the
        account's identifier in Luminar) when the record has none."""
        user_account.setdefault("user_id", user_account["id"])
        credential = user_account.get("credential")
        if self.mask_credentials and isinstance(credential, str) and credential:
            user_account["credential"] = mask_credential(credential)
        user_account.setdefault("x_opencti_score", USER_ACCOUNT_SCORE)
        user_account.setdefault(
            "x_opencti_description", FEED_DEFAULT_DESCRIPTIONS["leakedrecords"]
        )

    # ----- validate -----

    @staticmethod
    def _validate(stix_object: Dict[str, Any]) -> None:
        """Raise when the object is not valid STIX 2.1 (custom props allowed)."""
        stix2.parse(stix_object, allow_custom=True, version="2.1")

    # ----- observables derived from indicator patterns -----

    def _observables_from_indicator(
        self, feed_name: str, indicator: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Build observables (plus ``based-on`` relationships) for the
        equality comparisons of a STIX-pattern indicator.

        Only ``=`` comparisons describe a concrete value; ``!=``, ``LIKE``,
        ``MATCHES``, ranges and negations are ignored.
        """
        if indicator.get("pattern_type") != "stix":
            return []
        pattern = indicator.get("pattern")
        if not isinstance(pattern, str):
            return []

        custom_properties = {
            "x_opencti_score": indicator.get(
                "x_opencti_score", self._indicator_score(indicator)
            ),
            "x_opencti_description": FEED_DEFAULT_DESCRIPTIONS.get(
                feed_name, AUTHOR_NAME
            ),
            "x_opencti_created_by_ref": self.author["id"],
        }
        markings = indicator.get("object_marking_refs")
        derived: List[Dict[str, Any]] = []
        for match in PATTERN_COMPARISON.finditer(pattern):
            stix_type, path, negated, operator, raw_value = match.groups()
            if negated or operator != "=":
                continue
            value = raw_value.replace("\\'", "'").replace("\\\\", "\\")
            try:
                observable = self._build_observable(
                    stix_type, path, value, custom_properties, markings
                )
            except Exception as err:  # pylint: disable=broad-exception-caught
                self.logger.debug(
                    "[CONVERTER] Could not build observable from pattern",
                    {
                        "indicator": indicator["id"],
                        "comparison": match.group(0),
                        "error": f"{err.__class__.__name__}: {err}",
                    },
                )
                continue
            if observable is None:
                continue
            relationship_kwargs = {}
            if markings:
                relationship_kwargs["object_marking_refs"] = markings
            relationship = stix2.Relationship(
                id=StixCoreRelationship.generate_id(
                    "based-on", indicator["id"], observable["id"]
                ),
                relationship_type="based-on",
                source_ref=indicator["id"],
                target_ref=observable["id"],
                created_by_ref=self.author["id"],
                description=RELATIONSHIP_DESCRIPTION,
                allow_custom=True,
                **relationship_kwargs,
            )
            derived.extend([observable, _stix_to_dict(relationship)])
        return derived

    @staticmethod
    def _build_observable(
        stix_type: str,
        path: str,
        value: str,
        custom_properties: Dict[str, Any],
        markings: Optional[List[str]],
    ) -> Optional[Dict[str, Any]]:
        kwargs: Dict[str, Any] = {"custom_properties": dict(custom_properties)}
        if markings:
            kwargs["object_marking_refs"] = markings

        if stix_type in VALUE_OBSERVABLES and path == "value":
            return _stix_to_dict(VALUE_OBSERVABLES[stix_type](value=value, **kwargs))
        if stix_type == "file":
            if path.startswith("hashes."):
                hash_type = path.split(".", 1)[1].strip("'")
                return _stix_to_dict(stix2.File(hashes={hash_type: value}, **kwargs))
            if path == "name":
                return _stix_to_dict(stix2.File(name=value, **kwargs))
            if path == "size" and value.isdigit():
                return _stix_to_dict(stix2.File(size=int(value), **kwargs))
            return None
        if stix_type == "mutex" and path == "name":
            return _stix_to_dict(stix2.Mutex(name=value, **kwargs))
        if stix_type == "directory" and path == "path":
            return _stix_to_dict(stix2.Directory(path=value, **kwargs))
        if stix_type == "windows-registry-key" and path == "key":
            return _stix_to_dict(stix2.WindowsRegistryKey(key=value, **kwargs))
        return None

    # ----- reference integrity -----

    def _enforce_reference_integrity(
        self, objects: Dict[str, Dict[str, Any]], stats: ConversionStats
    ) -> None:
        """Make every reference resolvable inside the bundle.

        * Relationships whose endpoints are missing (expired, malformed,
          unsupported or never hydrated) and self-referencing relationships
          are dropped: OpenCTI rejects them with MISSING_REFERENCE_ERROR.
        * Sightings lose missing ``where_sighted_refs``/``observed_data_refs``
          and are dropped without ``sighting_of_ref`` or any sighted-where.
        * Containers keep only resolvable ``object_refs``. Reports and
          groupings are kept even when none remain (they are not expired and
          OpenCTI accepts empty containers); notes, opinions and observed-data
          only describe their objects and are dropped.
        Repeated until stable, since containers may reference relationships.
        """
        changed = True
        while changed:
            changed = False
            # The author identity is always added to the bundle.
            present = set(objects) | {self.author["id"]}
            for stix_id in list(objects):
                stix_object = objects[stix_id]
                stix_type = stix_object["type"]
                keep = True
                if stix_type == "relationship":
                    source_ref = stix_object.get("source_ref")
                    target_ref = stix_object.get("target_ref")
                    keep = (
                        source_ref in present
                        and target_ref in present
                        and source_ref != target_ref
                    )
                elif stix_type == "sighting":
                    for key in ("where_sighted_refs", "observed_data_refs"):
                        self._filter_ref_list(stix_object, key, present, stats)
                    keep = stix_object.get("sighting_of_ref") in present and bool(
                        stix_object.get("where_sighted_refs")
                    )
                elif stix_type in CONTAINER_TYPES:
                    had_refs = bool(stix_object.get("object_refs"))
                    self._filter_ref_list(stix_object, "object_refs", present, stats)
                    if had_refs and not stix_object.get("object_refs"):
                        if stix_type in EMPTY_CONTAINER_TYPES:
                            stats.containers_emptied += 1
                        else:
                            keep = False
                if not keep:
                    del objects[stix_id]
                    stats.dropped_dangling += 1
                    changed = True
                    self.logger.debug(
                        "[CONVERTER] Dropping object with unresolvable references",
                        {"id": stix_id},
                    )

        present = set(objects) | {self.author["id"]}
        valid_markings = present | set(KNOWN_MARKINGS)
        for stix_object in objects.values():
            self._filter_ref_list(
                stix_object, "object_marking_refs", valid_markings, stats
            )
            self._filter_granular_markings(stix_object, valid_markings, stats)
            self._fix_created_by(stix_object, objects)
            # Remaining optional refs (e.g. sample_refs, parent_directory_ref).
            for key in list(stix_object):
                if key in SPECIAL_REF_KEYS:
                    continue
                value = stix_object[key]
                if (
                    key.endswith("_refs")
                    and isinstance(value, list)
                    and all(isinstance(ref, str) for ref in value)
                ):
                    self._filter_ref_list(stix_object, key, present, stats)
                elif key.endswith("_ref") and isinstance(stix_object[key], str):
                    if stix_object[key] not in present:
                        del stix_object[key]
                        stats.dangling_refs_removed += 1

    @staticmethod
    def _filter_ref_list(
        stix_object: Dict[str, Any],
        key: str,
        allowed: Set[str],
        stats: ConversionStats,
    ) -> None:
        refs = stix_object.get(key)
        if not isinstance(refs, list):
            return
        kept = [ref for ref in refs if isinstance(ref, str) and ref in allowed]
        stats.dangling_refs_removed += len(refs) - len(kept)
        if kept:
            stix_object[key] = kept
        else:
            # STIX forbids empty lists.
            del stix_object[key]

    @staticmethod
    def _filter_granular_markings(
        stix_object: Dict[str, Any], allowed: Set[str], stats: ConversionStats
    ) -> None:
        """Drop granular markings whose ``marking_ref`` cannot be resolved
        (language-only granular markings have no marking_ref and are kept)."""
        granular = stix_object.get("granular_markings")
        if not isinstance(granular, list):
            return
        kept = [
            entry
            for entry in granular
            if not isinstance(entry, dict)
            or "marking_ref" not in entry
            or entry["marking_ref"] in allowed
        ]
        stats.dangling_refs_removed += len(granular) - len(kept)
        if kept:
            stix_object["granular_markings"] = kept
        else:
            del stix_object["granular_markings"]

    def _is_still_valid(self, stix_object: Dict[str, Any]) -> bool:
        """Re-validate an object after reference cleanup."""
        candidate = stix_object
        if stix_object["type"] in EMPTY_CONTAINER_TYPES and not stix_object.get(
            "object_refs"
        ):
            # The stix2 library requires object_refs; an emptied report or
            # grouping is still sent (OpenCTI accepts it), so validate the
            # rest of the object with a placeholder reference.
            candidate = dict(stix_object, object_refs=[self.author["id"]])
        try:
            self._validate(candidate)
        except Exception:  # pylint: disable=broad-exception-caught
            return False
        return True

    def _fix_created_by(
        self, stix_object: Dict[str, Any], objects: Dict[str, Dict[str, Any]]
    ) -> None:
        """Keep a resolvable identity ``created_by_ref``; otherwise attribute
        the object to the connector author (SCOs via x_opencti_created_by_ref)."""
        stix_type = stix_object["type"]
        if stix_type == MARKING_TYPE:
            if stix_object.get("created_by_ref") not in objects:
                stix_object.pop("created_by_ref", None)
            return
        created_by = stix_object.get("created_by_ref")
        resolvable = (
            created_by in objects and objects[created_by]["type"] == "identity"
        ) or created_by == self.author["id"]
        if stix_type in SCO_TYPES:
            if not resolvable:
                stix_object.pop("created_by_ref", None)
            stix_object.setdefault(
                "x_opencti_created_by_ref",
                created_by if resolvable else self.author["id"],
            )
        elif not resolvable:
            stix_object["created_by_ref"] = self.author["id"]

    # ----- OpenCTI relationship schema -----

    def _reference_standard_ids(
        self, objects: Dict[str, Dict[str, Any]], stats: ConversionStats
    ) -> None:
        """Point relationships, sightings and containers at the OpenCTI standard
        id of name-identified entities (see OPENCTI_STANDARD_IDS). Runs after
        the integrity checks: the standard ids are not ids of the batch. A
        relationship whose endpoints now denote the same entity is dropped."""
        standard_ids: Dict[str, str] = {}
        for stix_id, stix_object in objects.items():
            generate_id = OPENCTI_STANDARD_IDS.get(stix_object["type"])
            if generate_id is None:
                continue
            try:
                standard_ids[stix_id] = generate_id(stix_object)
            except (KeyError, AttributeError):
                continue  # e.g. identity without identity_class: keep its id
        if not standard_ids:
            return
        late = {
            stix_id: stix_object
            for stix_id, stix_object in objects.items()
            if stix_object["type"] in SRO_TYPES
            or stix_object["type"] in PHASE_CONTAINER_TYPES
        }
        self._rewrite_references(late, standard_ids)
        for stix_id, stix_object in late.items():
            if (
                stix_object["type"] == "relationship"
                and stix_object["source_ref"] == stix_object["target_ref"]
            ):
                del objects[stix_id]
                stats.dropped_dangling += 1
                self.logger.debug(
                    "[CONVERTER] Dropping relationship between merged entities",
                    {"id": stix_id},
                )

    def _apply_relationship_schema(
        self,
        objects: Dict[str, Dict[str, Any]],
        schema: RelationshipSchema,
        stats: ConversionStats,
    ) -> None:
        """Downgrade relationship types OpenCTI does not allow between the two
        entity types to ``related-to`` (always allowed); direction is never
        changed. Unknown verdicts leave the relationship untouched."""
        if not schema.available:
            return
        endpoints = {**objects, self.author["id"]: self.author}
        for stix_id in list(objects):
            relationship = objects[stix_id]
            if relationship["type"] != "relationship":
                continue
            relationship_type = relationship["relationship_type"]
            source = endpoints.get(relationship["source_ref"])
            target = endpoints.get(relationship["target_ref"])
            if source is None or target is None:
                continue
            verdict = schema.is_allowed(relationship_type, source, target)
            if verdict is not False:
                continue
            self.logger.debug(
                "[CONVERTER] Relationship type not allowed by OpenCTI; "
                "using related-to",
                {
                    "id": stix_id,
                    "relationship_type": relationship_type,
                    "source_ref": relationship["source_ref"],
                    "target_ref": relationship["target_ref"],
                },
            )
            relationship["relationship_type"] = "related-to"
            stats.relationships_downgraded += 1

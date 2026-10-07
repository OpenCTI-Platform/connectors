"""Convert Rösti API objects to STIX 2.1 objects for OpenCTI.

Mapping overview
----------------
* Report          -> Report (``threat-report``), linking everything below
* IOC             -> Observable + Indicator (``based-on``); risk -> score
* IOC group       -> IOCs with the same ``entity_ref`` are combined:
                     file hashes, names and paths -> one File + one Indicator,
                     URLs, domains and IPs -> their observables (domain
                     ``resolves-to`` IP) + one Indicator
* YARA rule       -> Indicator (``pattern_type: yara``)
* MITRE technique -> Attack-Pattern (merged with OpenCTI's MITRE data by ID)
* MITRE mitigation-> Course-Of-Action (merged by ID)
* MITRE group     -> Intrusion-Set (merged by name)
* MITRE campaign  -> Campaign (merged by name)
* MITRE software  -> existing Malware or Tool (see ``SoftwareResolver``)
* CVE             -> Vulnerability
"""

from __future__ import annotations

import datetime as dt
import ipaddress
import re
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

import stix2
from connectors_sdk.models import (
    AttackPattern,
    BaseIdentifiedEntity,
    Campaign,
    CourseOfAction,
    ExternalReference,
    IntrusionSet,
    OrganizationAuthor,
    Reference,
    Report,
    TLPMarking,
    Vulnerability,
)
from connectors_sdk.models.enums import TLPLevel
from connectors_sdk.models.report import ReportStix
from pycti import CustomObservableCryptocurrencyWallet, CustomObservableUserAgent
from pycti import Indicator as PyctiIndicator
from pycti import StixCoreRelationship
from rosti_client.models import CVE, IOC, Mitre
from rosti_client.models import Report as RostiReport
from rosti_client.models import Yara

ROSTI_URL = "https://rosti.dev"
ROSTI_REPORT_URL = ROSTI_URL + "/reports/{id}"

# Namespace of the report STIX IDs, which are derived from the Rösti report ID
# (see report_stix_id).
ROSTI_REPORT_NAMESPACE = uuid.uuid5(uuid.NAMESPACE_URL, "https://rosti.dev/reports/")


def report_stix_id(rosti_report_id: str) -> str:
    """Deterministic STIX ID of a Rösti report, based only on its Rösti ID.

    The usual report ID (name + publication date) changes when Rösti corrects
    a title or date, which would create a second report in OpenCTI. OpenCTI
    keeps this ID in the report's ``x_opencti_stix_ids`` and finds the report
    by it on every later import, so title and date are updated in place.
    """
    return f"report--{uuid.uuid5(ROSTI_REPORT_NAMESPACE, rosti_report_id)}"


# Score (0-100) per Rösti false-positive risk level. A higher false-positive
# risk means OpenCTI should trust the indicator less.
#   0 = nothing found, -1 = informational (e.g. a dyndns provider),
#   1 = small, 2 = moderate, 3 = medium, 4 = high, 5 = very high
RISK_LEVEL_TO_SCORE = {0: 80, -1: 70, 1: 60, 2: 50, 3: 40, 4: 25, 5: 10}

# Rösti IOC tag -> STIX indicator type. Tags not listed give "malicious-activity".
TAG_TO_INDICATOR_TYPE = {
    "proxy": "anonymization",
    "compromised": "compromised",
    "lookup": "benign",
    "tracker": "benign",
}

# Hash IOC types and the STIX hash algorithm names OpenCTI understands.
HASH_ALGORITHMS = {
    "md5": "MD5",
    "sha1": "SHA-1",
    "sha256": "SHA-256",
    "sha512": "SHA-512",
    "ssdeep": "SSDEEP",
    "sha224": "SHA-224",  # indicator only, see _map_hash
}

# Order of the hashes in the pattern of a combined file indicator, and which
# hash names the indicator (the strongest one available).
HASH_PATTERN_ORDER = ["MD5", "SHA-1", "SHA-224", "SHA-256", "SHA-512", "SSDEEP"]
HASH_NAME_PRIORITY = ["SHA-256", "SHA-512", "SHA-1", "MD5", "SHA-224", "SSDEEP"]

# IOC types that are combined when they share an entity_ref. File and network
# IOCs of the same group are never mixed; other types stay separate.
FILE_IOC_TYPES = {*HASH_ALGORITHMS, "filename", "filepath"}
NETWORK_IOC_TYPES = {
    "url",
    "domain",
    "domain:port",
    "domain:ip",
    "ip",
    "ip:port",
    "cidr",
}
# Order of the observable types in a combined network indicator; the first one
# names the indicator and is its main observable type.
NETWORK_TYPE_ORDER = {"Url": 0, "Domain-Name": 1, "IPv4-Addr": 2, "IPv6-Addr": 3}

# IOC types the connector deliberately skips (no meaningful STIX object).
UNSUPPORTED_IOC_TYPES = {"port"}

# Syntax checks, so that values OpenCTI would reject (domains, emails and file
# hashes are validated by the platform) are skipped here with a clear reason.
HASH_HEX_LENGTHS = {
    "MD5": 32,
    "SHA-1": 40,
    "SHA-224": 56,
    "SHA-256": 64,
    "SHA-512": 128,
}
SSDEEP_RE = re.compile(r"^\d+:[A-Za-z0-9/+]+:[A-Za-z0-9/+]+(,.*)?$")
# Same expressions as OpenCTI's `domainChecker` and `emailChecker`.
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)(?:[^\s.](?:[^\s.]{0,61}[^\s.])?\.)+[^\s.]{2,63}$"
)
EMAIL_RE = re.compile(
    r"^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
    r"(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$"
)

# Returns a reference to an existing Malware/Tool for a MITRE software entry,
# or None if it cannot be resolved.
SoftwareResolver = Callable[[Mitre], Reference | None]


@dataclass
class _Mapped:
    """Result of mapping one IOC value."""

    # Observables; the indicator of a single IOC is ``based-on`` the first one.
    observables: list[Any]
    # STIX comparison expression, e.g. "domain-name:value = 'example.com'"
    comparison: str
    main_type: str
    notes: list[str] = field(default_factory=list)
    # Other objects, e.g. the ``resolves-to`` relationship of domain:ip
    related: list[Any] = field(default_factory=list)

    @property
    def pattern(self) -> str:
        return f"[{self.comparison}]"


@dataclass
class GroupResult:
    """Result of converting one group of IOCs (see ``convert_ioc_group``)."""

    objects: list[Any] = field(default_factory=list)
    # IOCs that could not be converted, with the reason
    skipped: list[tuple[IOC, str]] = field(default_factory=list)
    # Groups that could not be combined, with the reason
    warnings: list[str] = field(default_factory=list)
    # One entry ("file" or "network") per combined group
    combined: list[str] = field(default_factory=list)


@dataclass
class _FileParts:
    """The file IOCs of a group, validated (see ``RostiConverter._file_parts``)."""

    hashes: dict[str, str] = field(default_factory=dict)
    names: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    iocs: list[IOC] = field(default_factory=list)
    # Hash algorithm with two different values in the group, if any
    conflict: str | None = None


class ConversionError(Exception):
    """Raised when a single Rösti object cannot be converted."""


def _escape(value: str) -> str:
    """Escape a value for use inside a STIX pattern string literal."""
    return value.replace("\\", "\\\\").replace("'", "\\'")


def _midnight(day: dt.date) -> dt.datetime:
    return dt.datetime.combine(day, dt.time.min, tzinfo=dt.timezone.utc)


def _split_host_port(value: str) -> tuple[str, str]:
    """Split ``host:port`` (also ``[v6]:port``) into host and port."""
    if value.startswith("["):
        host, _, rest = value[1:].partition("]")
        return host, rest.lstrip(":")
    host, _, port = value.rpartition(":")
    return host, port


class RostiConverter:
    """Stateless converter from Rösti objects to STIX objects."""

    def __init__(
        self,
        tlp_level: TLPLevel | str = TLPLevel.CLEAR,
        default_score: int = 50,
        software_resolver: SoftwareResolver | None = None,
    ) -> None:
        self.author = OrganizationAuthor(
            name="Rösti",
            description="Rösti (Repackaged Öpen Source Threat Intelligence) "
            "turns public threat reports into machine-readable IOCs.",
            external_references=[ExternalReference(source_name="Rösti", url=ROSTI_URL)],
        )
        self.tlp_marking = TLPMarking(level=tlp_level)
        self.default_score = default_score
        self.software_resolver = software_resolver
        self._ioc_mappers = self._mappers()

    # ------------------------------------------------------------------
    # Common helpers
    # ------------------------------------------------------------------

    @property
    def _marking_ids(self) -> list[str]:
        return [self.tlp_marking.id]

    def _observable_props(
        self, score: int, labels: list[str], description: str | None
    ) -> dict[str, Any]:
        return {
            "allow_custom": True,
            "object_marking_refs": self._marking_ids,
            "x_opencti_score": score,
            "x_opencti_labels": labels or None,
            "x_opencti_description": description,
            "x_opencti_created_by_ref": self.author.id,
        }

    def _relationship(
        self, rel_type: str, source_id: str, target_id: str
    ) -> stix2.Relationship:
        return stix2.Relationship(
            id=StixCoreRelationship.generate_id(rel_type, source_id, target_id),
            relationship_type=rel_type,
            source_ref=source_id,
            target_ref=target_id,
            created_by_ref=self.author.id,
            object_marking_refs=self._marking_ids,
        )

    def score_for(self, ioc: IOC) -> int:
        if ioc.risk is None:
            return self.default_score
        return RISK_LEVEL_TO_SCORE.get(ioc.risk.level, self.default_score)

    # ------------------------------------------------------------------
    # IOCs
    # ------------------------------------------------------------------

    # Each _map_* method returns (observables, pattern, main observable type,
    # extra description lines). The first observable is the one the indicator
    # is ``based-on``.

    @staticmethod
    def _map_ip(value: str, props: dict[str, Any]) -> _Mapped:
        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError as e:
            raise ConversionError(f"Invalid IP address or CIDR: {value}") from e
        if network.version == 4:
            return _Mapped(
                [stix2.IPv4Address(value=value, **props)],
                f"ipv4-addr:value = '{value}'",
                "IPv4-Addr",
            )
        return _Mapped(
            [stix2.IPv6Address(value=value, **props)],
            f"ipv6-addr:value = '{value}'",
            "IPv6-Addr",
        )

    @staticmethod
    def _map_domain(value: str, props: dict[str, Any]) -> _Mapped:
        if not DOMAIN_RE.match(value):
            raise ConversionError(f"Invalid domain name: {value!r}")
        return _Mapped(
            [stix2.DomainName(value=value, **props)],
            f"domain-name:value = '{_escape(value)}'",
            "Domain-Name",
        )

    def _map_host_port(
        self, value: str, props: dict[str, Any], host_type: str
    ) -> _Mapped:
        host, port = _split_host_port(value)
        if not host or not port.isdigit():
            raise ConversionError(f"Expected host:port, got {value!r}")
        mapper = self._map_ip if host_type == "ip" else self._map_domain
        mapped = mapper(host, props)
        mapped.notes.append(f"Seen on port {port}.")
        return mapped

    def _map_domain_ip(self, value: str, props: dict[str, Any]) -> _Mapped:
        domain, _, ip_value = value.partition(":")
        if not domain or not ip_value:
            raise ConversionError(f"Expected domain:ip, got {value!r}")
        mapped = self._map_domain(domain, props)
        ip_obs = self._map_ip(ip_value, props).observables[0]
        domain_obs = mapped.observables[0]
        mapped.observables.append(ip_obs)
        mapped.related.append(
            self._relationship("resolves-to", domain_obs.id, ip_obs.id)
        )
        mapped.notes.append(f"Resolved to {ip_value}.")
        return mapped

    @staticmethod
    def _check_hash(algorithm: str, value: str) -> None:
        if algorithm == "SSDEEP":
            if not SSDEEP_RE.match(value):
                raise ConversionError(f"Not an ssdeep hash: {value!r}")
        elif not re.fullmatch(rf"[0-9a-fA-F]{{{HASH_HEX_LENGTHS[algorithm]}}}", value):
            raise ConversionError(f"Invalid {algorithm} hash: {value!r}")

    @staticmethod
    def _hash_comparison(algorithm: str, value: str) -> str:
        return f"file:hashes.'{algorithm}' = '{_escape(value)}'"

    def _map_hash(self, algorithm: str, value: str, props: dict[str, Any]) -> _Mapped:
        self._check_hash(algorithm, value)
        comparison = self._hash_comparison(algorithm, value)
        if algorithm == "SHA-224":
            # OpenCTI cannot store a file observable identified only by SHA-224,
            # so only the indicator is created.
            return _Mapped([], comparison, "StixFile")
        return _Mapped(
            [stix2.File(hashes={algorithm: value}, **props)], comparison, "StixFile"
        )

    @staticmethod
    def _file_name(value: str, is_path: bool) -> tuple[str, str | None]:
        """File name of a filename/filepath IOC, and a note with the full path."""
        name = value.replace("\\", "/").rsplit("/", 1)[-1] if is_path else value
        if not name:
            raise ConversionError(f"No file name in {value!r}")
        return name, (f"Full path: {value}" if name != value else None)

    def _map_file(self, value: str, props: dict[str, Any], is_path: bool) -> _Mapped:
        name, note = self._file_name(value, is_path)
        mapped = _Mapped(
            [stix2.File(name=name, **props)],
            f"file:name = '{_escape(name)}'",
            "StixFile",
        )
        if note:
            mapped.notes.append(note)
        return mapped

    def _map_email(self, value: str, props: dict[str, Any]) -> _Mapped:
        if not EMAIL_RE.match(value):
            raise ConversionError(f"Invalid email address: {value!r}")
        return self._map_simple(
            stix2.EmailAddress, "email-addr", "value", "Email-Addr"
        )(value, props)

    @staticmethod
    def _map_simple(
        stix_class: Any, stix_type: str, prop: str, main_type: str
    ) -> Callable[[str, dict[str, Any]], _Mapped]:
        def mapper(value: str, props: dict[str, Any]) -> _Mapped:
            return _Mapped(
                [stix_class(**{prop: value}, **props)],
                f"{stix_type}:{prop} = '{_escape(value)}'",
                main_type,
            )

        return mapper

    def _mappers(self) -> dict[str, Callable[[str, dict[str, Any]], _Mapped]]:
        mappers: dict[str, Callable[[str, dict[str, Any]], _Mapped]] = {
            "ip": self._map_ip,
            "cidr": self._map_ip,
            "domain": self._map_domain,
            "ip:port": lambda v, p: self._map_host_port(v, p, "ip"),
            "domain:port": lambda v, p: self._map_host_port(v, p, "domain"),
            "domain:ip": self._map_domain_ip,
            "filename": lambda v, p: self._map_file(v, p, is_path=False),
            "filepath": lambda v, p: self._map_file(v, p, is_path=True),
            "url": self._map_simple(stix2.URL, "url", "value", "Url"),
            "email": self._map_email,
            "mutex": self._map_simple(stix2.Mutex, "mutex", "name", "Mutex"),
            "user-agent": self._map_simple(
                CustomObservableUserAgent, "user-agent", "value", "User-Agent"
            ),
            "blockchain": self._map_simple(
                CustomObservableCryptocurrencyWallet,
                "cryptocurrency-wallet",
                "value",
                "Cryptocurrency-Wallet",
            ),
        }
        for ioc_type, algorithm in HASH_ALGORITHMS.items():
            mappers[ioc_type] = lambda v, p, a=algorithm: self._map_hash(a, v, p)
        return mappers

    def _map_ioc(self, ioc: IOC, props: dict[str, Any]) -> _Mapped:
        mapper = self._ioc_mappers.get(ioc.type)
        if mapper is None:
            raise ConversionError(f"Unsupported IOC type {ioc.type!r}")
        return mapper(ioc.value.strip(), props)

    @staticmethod
    def _indicator_types(tags: list[str]) -> list[str]:
        if not tags:
            return ["unknown"]
        # Sub-tags come as "<tag>-<subtag>" (e.g. "proxy-tor"): map by the main tag.
        types = {
            TAG_TO_INDICATOR_TYPE.get(tag.split("-", 1)[0], "malicious-activity")
            for tag in tags
        }
        return sorted(types)

    @staticmethod
    def _labels(iocs: list[IOC]) -> list[str]:
        return sorted({tag for ioc in iocs for tag in ioc.tags or []})

    @staticmethod
    def _description(iocs: list[IOC], notes: list[str]) -> str | None:
        lines = []
        # The comments of a group's IOCs are meant to be the same: use the first.
        comment = next((ioc.comment for ioc in iocs if ioc.comment), None)
        if comment:
            lines.append(comment)
        for ioc in iocs:
            if ioc.risk is None:
                continue
            subject = "False-positive risk"
            if len(iocs) > 1:
                subject += f" of {ioc.value.strip()}"
            risk_line = f"{subject}: {ioc.risk.meaning or ioc.risk.level}"
            if ioc.risk.msg:
                risk_line += f" ({ioc.risk.msg})"
            lines.append(risk_line + ".")
        lines.extend(dict.fromkeys(notes))
        return "\n".join(lines) or None

    def _indicator(  # pylint: disable=too-many-arguments,too-many-positional-arguments
        self,
        iocs: list[IOC],
        pattern: str,
        name: str,
        main_type: str,
        notes: list[str],
    ) -> stix2.Indicator:
        """Indicator for one IOC or a group of IOCs.

        For a group, tags are merged, the first comment is used, and the
        values are the most cautious ones: the lowest score, detection only if
        every IOC is marked for IDS, and the earliest date.
        """
        labels = self._labels(iocs)
        return stix2.Indicator(
            id=PyctiIndicator.generate_id(pattern),
            name=name,
            description=self._description(iocs, notes),
            pattern=pattern,
            pattern_type="stix",
            valid_from=_midnight(min(ioc.date for ioc in iocs)),
            indicator_types=self._indicator_types(labels),
            labels=labels or None,
            created_by_ref=self.author.id,
            object_marking_refs=self._marking_ids,
            allow_custom=True,
            x_opencti_score=min(self.score_for(ioc) for ioc in iocs),
            x_opencti_detection=all(ioc.ids for ioc in iocs),
            x_opencti_main_observable_type=main_type,
        )

    def convert_ioc(self, ioc: IOC) -> list[Any]:
        """Convert one IOC into observables, an indicator and ``based-on`` relationships."""
        if ioc.type in UNSUPPORTED_IOC_TYPES:
            raise ConversionError(f"IOC type {ioc.type!r} is not imported")

        props = self._observable_props(self.score_for(ioc), self._labels([ioc]), None)
        mapped = self._map_ioc(ioc, props)
        indicator = self._indicator(
            [ioc], mapped.pattern, ioc.value.strip(), mapped.main_type, mapped.notes
        )
        objects: list[Any] = [indicator, *mapped.observables, *mapped.related]
        if mapped.observables:
            objects.append(
                self._relationship("based-on", indicator.id, mapped.observables[0].id)
            )
        return objects

    # ------------------------------------------------------------------
    # IOC groups (same entity_ref)
    # ------------------------------------------------------------------

    def convert_ioc_group(self, iocs: list[IOC]) -> GroupResult:
        """Convert a group of IOCs that share an ``entity_ref``.

        Hashes, file names and file paths become one File with one indicator;
        URLs, domains and IPs become one indicator over their observables.
        File and network IOCs are never combined with each other, and all
        other IOCs (and a part with a single IOC) are converted on their own.
        """
        result = GroupResult()
        single: list[IOC] = []
        if len(iocs) > 1:
            files = [ioc for ioc in iocs if ioc.type in FILE_IOC_TYPES]
            network = [ioc for ioc in iocs if ioc.type in NETWORK_IOC_TYPES]
            single = [
                ioc
                for ioc in iocs
                if ioc.type not in FILE_IOC_TYPES and ioc.type not in NETWORK_IOC_TYPES
            ]
            for part, combine in (
                (files, self._combine_files),
                (network, self._combine_network),
            ):
                if len(part) > 1:
                    combine(part, result)
                else:
                    single.extend(part)
        else:
            single = list(iocs)
        for ioc in single:
            self._convert_single(ioc, result)
        return result

    def _convert_single(self, ioc: IOC, result: GroupResult) -> None:
        try:
            result.objects.extend(self.convert_ioc(ioc))
        except ConversionError as e:
            result.skipped.append((ioc, str(e)))

    def _combined_objects(
        self, indicator: stix2.Indicator, observables: list[Any], related: list[Any]
    ) -> list[Any]:
        based_on = [
            self._relationship("based-on", indicator.id, observable.id)
            for observable in observables
        ]
        return [indicator, *observables, *related, *based_on]

    def _file_parts(self, iocs: list[IOC], result: GroupResult) -> _FileParts:
        """Validate the file IOCs of a group and collect their hashes and names."""
        parts = _FileParts()
        for ioc in iocs:
            value = ioc.value.strip()
            try:
                if ioc.type in HASH_ALGORITHMS:
                    algorithm = HASH_ALGORITHMS[ioc.type]
                    self._check_hash(algorithm, value)
                    known = parts.hashes.setdefault(algorithm, value)
                    if known.lower() != value.lower():
                        parts.conflict = algorithm
                else:
                    name, note = self._file_name(value, ioc.type == "filepath")
                    if name not in parts.names:
                        parts.names.append(name)
                    if note:
                        parts.notes.append(note)
            except ConversionError as e:
                result.skipped.append((ioc, str(e)))
                continue
            parts.iocs.append(ioc)
        return parts

    def _file_observable(self, parts: _FileParts) -> stix2.File | None:
        file_props: dict[str, Any] = {}
        # OpenCTI cannot store SHA-224 on a file: it is only part of the pattern.
        file_hashes = {a: v for a, v in parts.hashes.items() if a != "SHA-224"}
        if file_hashes:
            file_props["hashes"] = file_hashes
        if parts.names:
            file_props["name"] = parts.names[0]
        if len(parts.names) > 1:
            file_props["x_opencti_additional_names"] = parts.names[1:]
        if not file_props:
            return None
        props = self._observable_props(
            min(self.score_for(ioc) for ioc in parts.iocs),
            self._labels(parts.iocs),
            None,
        )
        return stix2.File(**file_props, **props)

    def _combine_files(self, iocs: list[IOC], result: GroupResult) -> None:
        """One File with all hashes and names, and one indicator for it."""
        parts = self._file_parts(iocs, result)
        if parts.conflict or len(parts.iocs) < 2:
            if parts.conflict:
                result.warnings.append(
                    f"IOC group {iocs[0].entity_ref} has different {parts.conflict} "
                    "hashes, so it cannot be one file: its IOCs are imported separately"
                )
            for ioc in parts.iocs:
                self._convert_single(ioc, result)
            return

        hashes = parts.hashes
        if hashes:
            ordered = sorted(hashes, key=HASH_PATTERN_ORDER.index)
            comparisons = [self._hash_comparison(a, hashes[a]) for a in ordered]
            name = hashes[min(hashes, key=HASH_NAME_PRIORITY.index)]
        else:
            comparisons = [f"file:name = '{_escape(n)}'" for n in sorted(parts.names)]
            name = parts.names[0]
        pattern = "[" + " OR ".join(comparisons) + "]"
        indicator = self._indicator(parts.iocs, pattern, name, "StixFile", parts.notes)
        observable = self._file_observable(parts)
        result.objects.extend(
            self._combined_objects(indicator, [observable] if observable else [], [])
        )
        result.combined.append("file")

    def _combine_network(self, iocs: list[IOC], result: GroupResult) -> None:
        """One indicator over the URLs, domains and IPs; domain ``resolves-to`` IP."""
        mapped_iocs: list[tuple[IOC, _Mapped]] = []
        for ioc in iocs:
            props = self._observable_props(
                self.score_for(ioc), self._labels([ioc]), None
            )
            try:
                mapped_iocs.append((ioc, self._map_ioc(ioc, props)))
            except ConversionError as e:
                result.skipped.append((ioc, str(e)))
        if len(mapped_iocs) < 2:
            for ioc, _ in mapped_iocs:
                self._convert_single(ioc, result)
            return

        observables: dict[str, Any] = {}
        related: dict[str, Any] = {}
        # comparison -> (main observable type, value)
        comparisons: dict[str, tuple[str, str]] = {}
        notes: list[str] = []
        for ioc, mapped in mapped_iocs:
            for observable in mapped.observables:
                observables.setdefault(observable.id, observable)
            for obj in mapped.related:
                related.setdefault(obj.id, obj)
            comparisons.setdefault(
                mapped.comparison,
                (mapped.main_type, mapped.observables[0].value),
            )
            notes.extend(mapped.notes)

        domains = [o for o in observables.values() if o.type == "domain-name"]
        ips = [
            o
            for o in observables.values()
            if o.type in ("ipv4-addr", "ipv6-addr") and "/" not in o.value
        ]
        # With several domains it is unknown which one resolves to which IP.
        if len(domains) == 1:
            for ip in ips:
                relationship = self._relationship("resolves-to", domains[0].id, ip.id)
                related.setdefault(relationship.id, relationship)

        ordered = sorted(
            comparisons.items(),
            key=lambda item: (NETWORK_TYPE_ORDER[item[1][0]], item[0]),
        )
        pattern = " OR ".join(f"[{comparison}]" for comparison, _ in ordered)
        main_type, name = ordered[0][1]
        indicator = self._indicator(
            [ioc for ioc, _ in mapped_iocs], pattern, name, main_type, notes
        )
        result.objects.extend(
            self._combined_objects(
                indicator, list(observables.values()), list(related.values())
            )
        )
        result.combined.append("network")

    # ------------------------------------------------------------------
    # YARA
    # ------------------------------------------------------------------

    def convert_yara(
        self, rule: Yara, report_date: dt.date, pattern: str | None = None
    ) -> stix2.Indicator:
        """Convert a YARA rule; ``pattern`` overrides the rule text (see yara_rules)."""
        pattern = (pattern or rule.rule).strip()
        return stix2.Indicator(
            id=PyctiIndicator.generate_id(pattern),
            name=rule.name,
            pattern=pattern,
            pattern_type="yara",
            valid_from=_midnight(report_date),
            indicator_types=["malicious-activity"],
            labels=sorted(set(rule.tags)) if rule.tags else None,
            created_by_ref=self.author.id,
            object_marking_refs=self._marking_ids,
            allow_custom=True,
            x_opencti_main_observable_type="StixFile",
            x_opencti_detection=True,
        )

    # ------------------------------------------------------------------
    # MITRE ATT&CK and CVEs
    # ------------------------------------------------------------------

    def convert_mitre(self, entry: Mitre) -> BaseIdentifiedEntity | Reference | None:
        """Convert a MITRE entry. Returns None for types that are not imported.

        Tactics and data sources describe ATT&CK itself, not the threat, and
        are not imported.
        """
        if entry.object_type == "software":
            if self.software_resolver is None:
                return None
            return self.software_resolver(entry)

        common = {"author": self.author, "markings": [self.tlp_marking]}
        builders: dict[str, Callable[[], BaseIdentifiedEntity]] = {
            "techniques": lambda: AttackPattern(
                name=entry.description, mitre_id=entry.id, **common
            ),
            "mitigations": lambda: CourseOfAction(
                name=entry.description, mitre_id=entry.id, **common
            ),
            "groups": lambda: IntrusionSet(name=entry.description, **common),
            "campaigns": lambda: Campaign(name=entry.description, **common),
        }
        builder = builders.get(entry.object_type)
        return builder() if builder else None

    def convert_cve(self, cve: CVE) -> Vulnerability:
        return Vulnerability(
            name=cve.id,
            description=cve.description,
            author=self.author,
            markings=[self.tlp_marking],
            external_references=[
                ExternalReference(
                    source_name="cve",
                    external_id=cve.id,
                    url=f"https://www.cve.org/CVERecord?id={cve.id}",
                )
            ],
        )

    # ------------------------------------------------------------------
    # Report
    # ------------------------------------------------------------------

    def convert_report(
        self,
        report: RostiReport,
        object_refs: list[BaseIdentifiedEntity | Reference],
    ) -> ReportStix:
        """Convert a report.

        Its STIX ID depends only on the Rösti report ID (``report_stix_id``),
        so a corrected title or date updates the same report in OpenCTI.
        The report carries an OpenCTI upsert operation that *replaces* its
        contained objects. Without it, OpenCTI only adds references when a
        report is updated, so IOCs removed from a Rösti report would stay in
        the OpenCTI report forever.
        """
        lines = []
        if report.source is not None:
            lines.append(f"Published by {report.source.name}.")
        if report.authors:
            lines.append(f"Authors: {', '.join(report.authors)}.")
        lines.append(f"Original report: {report.url}")

        external_references = [
            ExternalReference(
                source_name=report.source.name if report.source else "Original report",
                url=report.url,
            ),
            ExternalReference(
                source_name="Rösti",
                external_id=report.id,
                url=ROSTI_REPORT_URL.format(id=report.id),
            ),
        ]
        stix_report = Report(
            name=report.title,
            publication_date=_midnight(report.date),
            description="\n".join(lines),
            report_types=["threat-report"],
            objects=object_refs,
            labels=sorted(set(report.tags)) if report.tags else None,
            author=self.author,
            markings=[self.tlp_marking],
            external_references=external_references,
        ).to_stix2_object()
        # Stable ID from the Rösti report ID instead of the SDK's name + date ID.
        return ReportStix(
            id=report_stix_id(report.id),
            **{key: stix_report[key] for key in stix_report if key != "id"},
            allow_custom=True,
            opencti_upsert_operations=[
                {
                    "key": "objects",
                    "value": list(stix_report.get("object_refs") or []),
                    "operation": "replace",
                }
            ],
        )

"""Convert Splunk data into STIX 2.1 objects."""

from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Any

import stix2
import yaml
from connectors_sdk.models import (
    AttackPattern,
    ExternalReference,
    Incident,
    Indicator,
    Individual,
    Infrastructure,
    Note,
    OrganizationAuthor,
    Sighting,
    TLPMarking,
)
from pycti import StixCoreRelationship

MITRE_TECHNIQUE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)
MITRE_FIELD_HINTS = ("mitre", "attack", "technique")


class ConverterToStix:
    """Creates deterministic STIX objects for Splunk records."""

    def __init__(self, tlp_level: str = "amber", confidence: int = 60) -> None:
        self.author = OrganizationAuthor(
            name="Splunk",
            description="Splunk source imported by the OpenCTI Splunk connector.",
        )
        self.tlp_marking = TLPMarking(level=tlp_level)
        self.confidence = confidence

    def common_objects(self) -> list[stix2.v21._STIXBase21]:
        return [self.author.to_stix2_object(), self.tlp_marking.to_stix2_object()]

    def saved_search_to_stix(
        self,
        record: dict[str, Any],
        note_type: str,
    ) -> list[stix2.v21._STIXBase21]:
        content = self._content(record)
        name = str(
            record.get("name")
            or content.get("title")
            or content.get("name")
            or "Splunk saved search"
        )
        search = str(content.get("search") or record.get("search") or "").strip()
        if not search:
            return []

        now = datetime.now(UTC)
        indicator = Indicator(
            name=name,
            description=self._description(
                "Splunk saved search",
                content,
                include=("description", "qualifiedSearch", "action.email.subject"),
            ),
            pattern=search,
            pattern_type="spl",
            indicator_types=["unknown"],
            labels=self._labels(
                "splunk",
                "saved-search",
                content.get("eai:acl.app"),
                content.get("alert_type"),
            ),
            valid_from=self._parse_datetime(content.get("updated")) or now,
            score=self.confidence,
            author=self.author,
            markings=[self.tlp_marking],
            external_references=self._external_refs(record, content, "splunk-saved-search"),
        )

        parameters = self._saved_search_parameters(record, content)
        note = Note(
            abstract=f"Search parameters for {name}",
            content=yaml.safe_dump(parameters, sort_keys=True, default_flow_style=False),
            note_types=[note_type],
            labels=["splunk", "search-parameters"],
            objects=[indicator],
            author=self.author,
            markings=[self.tlp_marking],
            created=now,
        )

        stix_objects: list[stix2.v21._STIXBase21] = [
            indicator.to_stix2_object(),
            note.to_stix2_object(),
        ]
        for technique_id in self._extract_mitre_ids(record, content):
            attack_pattern = AttackPattern(
                name=f"MITRE ATT&CK {technique_id}",
                mitre_id=technique_id,
                labels=["mitre-attack"],
                author=self.author,
                markings=[self.tlp_marking],
            )
            stix_attack_pattern = attack_pattern.to_stix2_object()
            stix_objects.append(stix_attack_pattern)
            stix_objects.append(
                self._relationship(
                    "indicates",
                    indicator.id,
                    stix_attack_pattern.id,
                    "Saved search references MITRE ATT&CK technique metadata.",
                )
            )
        return stix_objects

    def asset_identity_to_stix(self, record: dict[str, Any]) -> list[stix2.v21._STIXBase21]:
        record_type = str(record.get("record_type") or record.get("type") or "").lower()
        if record_type == "asset" or self._asset_name(record):
            return self._asset_to_stix(record)
        return self._identity_to_stix(record)

    def finding_to_stix(self, record: dict[str, Any]) -> list[stix2.v21._STIXBase21]:
        now = datetime.now(UTC)
        name = self._first_value(
            record,
            "title",
            "name",
            "finding_name",
            "rule_name",
            "search_name",
            default="Splunk finding",
        )
        first_seen_value = self._first_value(
            record, "_time", "first_seen", "orig_time", "time", default=None
        )
        last_seen_value = self._first_value(
            record, "last_seen", "last_time", "updated_time", default=None
        )
        first_seen = self._parse_datetime(first_seen_value)
        last_seen = self._parse_datetime(last_seen_value)
        incident = Incident(
            name=str(name),
            description=self._description(
                "Splunk Enterprise Security finding",
                record,
                include=("description", "summary", "drilldown_search", "search_name", "sid"),
            ),
            incident_type="alert",
            severity=self._severity(record),
            source="Splunk Enterprise Security",
            first_seen=first_seen or now,
            last_seen=last_seen or first_seen or now,
            labels=self._labels(
                "splunk", "finding", record.get("status"), record.get("urgency")
            ),
            author=self.author,
            markings=[self.tlp_marking],
            external_references=self._external_refs(record, record, "splunk-finding"),
        )
        sighting = Sighting(
            sighting_of=incident,
            where_sighted=[self.author],
            first_seen=incident.first_seen,
            last_seen=incident.last_seen,
            count=self._int_or_none(record.get("count")) or 1,
            description=f"Splunk finding sighting for {name}",
            author=self.author,
            markings=[self.tlp_marking],
        )

        stix_objects: list[stix2.v21._STIXBase21] = [
            incident.to_stix2_object(),
            sighting.to_stix2_object(),
        ]
        for technique_id in self._extract_mitre_ids(record, record):
            attack_pattern = AttackPattern(
                name=f"MITRE ATT&CK {technique_id}",
                mitre_id=technique_id,
                labels=["mitre-attack"],
                author=self.author,
                markings=[self.tlp_marking],
            )
            stix_attack_pattern = attack_pattern.to_stix2_object()
            stix_objects.append(stix_attack_pattern)
            stix_objects.append(
                self._relationship(
                    "uses",
                    incident.id,
                    stix_attack_pattern.id,
                    "Finding references MITRE ATT&CK technique metadata.",
                )
            )
        return stix_objects

    def _asset_to_stix(self, record: dict[str, Any]) -> list[stix2.v21._STIXBase21]:
        name = self._asset_name(record) or "Unknown Splunk asset"
        aliases = self._split_values(record.get("aliases") or record.get("alias"))
        infrastructure = Infrastructure(
            name=name,
            description=self._description("Splunk ES asset", record),
            aliases=aliases or None,
            infrastructure_types=[self._infrastructure_type(record)],
            author=self.author,
            markings=[self.tlp_marking],
            external_references=self._external_refs(record, record, "splunk-asset"),
        )
        stix_objects = [infrastructure.to_stix2_object()]

        owner = self._first_value(record, "owner", "user", "identity", default=None)
        if owner:
            identity = Individual(
                name=str(owner),
                description="Owner or user associated with a Splunk ES asset.",
                author=self.author,
                markings=[self.tlp_marking],
            )
            stix_objects.append(identity.to_stix2_object())
            stix_objects.append(
                self._relationship(
                    "related-to",
                    identity.id,
                    infrastructure.id,
                    "Splunk asset ownership or usage association.",
                )
            )
        return stix_objects

    def _identity_to_stix(self, record: dict[str, Any]) -> list[stix2.v21._STIXBase21]:
        name = self._first_value(
            record,
            "identity",
            "user",
            "username",
            "name",
            "email",
            default="Unknown Splunk identity",
        )
        identity = Individual(
            name=str(name),
            description=self._description("Splunk ES identity", record),
            aliases=self._split_values(record.get("aliases") or record.get("alias")) or None,
            author=self.author,
            markings=[self.tlp_marking],
            external_references=self._external_refs(record, record, "splunk-identity"),
        )
        return [identity.to_stix2_object()]

    def _relationship(
        self, relationship_type: str, source_id: str, target_id: str, description: str
    ) -> stix2.Relationship:
        return stix2.Relationship(
            id=StixCoreRelationship.generate_id(relationship_type, source_id, target_id),
            relationship_type=relationship_type,
            source_ref=source_id,
            target_ref=target_id,
            description=description,
            created_by_ref=self.author.id,
            object_marking_refs=[self.tlp_marking.id],
        )

    @staticmethod
    def _content(record: dict[str, Any]) -> dict[str, Any]:
        content = record.get("content")
        return content if isinstance(content, dict) else record

    @staticmethod
    def _asset_name(record: dict[str, Any]) -> str | None:
        value = ConverterToStix._first_value(
            record,
            "asset",
            "host",
            "hostname",
            "dns",
            "ip",
            "dest",
            "src",
            default=None,
        )
        return str(value) if value else None

    @staticmethod
    def _first_value(record: dict[str, Any], *keys: str, default: Any) -> Any:
        for key in keys:
            value = record.get(key)
            if value not in (None, ""):
                return value
        return default

    @staticmethod
    def _description(
        prefix: str,
        record: dict[str, Any],
        include: tuple[str, ...] | None = None,
    ) -> str:
        keys = include or tuple(
            sorted(k for k in record.keys() if not str(k).startswith("_"))
        )
        lines = [prefix]
        for key in keys:
            value = record.get(key)
            if value not in (None, "", [], {}):
                lines.append(f"{key}: {value}")
        return "\n".join(lines)

    @staticmethod
    def _labels(*values: Any) -> list[str]:
        labels = []
        for value in values:
            if value in (None, "", [], {}):
                continue
            if isinstance(value, list):
                labels.extend(str(item).strip().lower() for item in value if item)
            else:
                labels.append(str(value).strip().lower())
        return sorted(set(label for label in labels if label))

    @staticmethod
    def _split_values(value: Any) -> list[str]:
        if value in (None, ""):
            return []
        if isinstance(value, list):
            return [str(item).strip() for item in value if str(item).strip()]
        return [item.strip() for item in str(value).split(",") if item.strip()]

    @staticmethod
    def _parse_datetime(value: Any) -> datetime | None:
        if value in (None, ""):
            return None
        if isinstance(value, datetime):
            return value if value.tzinfo else value.replace(tzinfo=UTC)
        try:
            return datetime.fromtimestamp(float(value), tz=UTC)
        except (TypeError, ValueError):
            pass
        text = str(value).strip().replace("Z", "+00:00")
        try:
            parsed = datetime.fromisoformat(text)
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
        except ValueError:
            return None

    @staticmethod
    def _int_or_none(value: Any) -> int | None:
        try:
            return int(value)
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _extract_mitre_ids(*records: dict[str, Any]) -> list[str]:
        found: set[str] = set()
        for record in records:
            for key, value in record.items():
                if value in (None, "", [], {}):
                    continue
                key_text = str(key).lower()
                if any(hint in key_text for hint in MITRE_FIELD_HINTS):
                    found.update(
                        match.upper()
                        for match in MITRE_TECHNIQUE_RE.findall(str(value))
                    )
        return sorted(found)

    @staticmethod
    def _infrastructure_type(record: dict[str, Any]) -> str:
        values = " ".join(
            str(record.get(key, ""))
            for key in ("category", "type", "asset_type", "bunit", "priority")
        ).lower()
        if any(term in values for term in ("router", "switch", "network", "firewall")):
            return "routers-switches"
        if any(term in values for term in ("server", "cloud", "instance")):
            return "hosting-target-lists"
        if any(term in values for term in ("workstation", "endpoint", "laptop", "desktop")):
            return "workstation"
        return "unknown"

    @staticmethod
    def _saved_search_parameters(
        record: dict[str, Any], content: dict[str, Any]
    ) -> dict[str, Any]:
        parameter_keys = (
            "cron_schedule",
            "dispatch.earliest_time",
            "dispatch.latest_time",
            "earliest_time",
            "latest_time",
            "alert_type",
            "alert_comparator",
            "alert_threshold",
            "alert.severity",
            "actions",
            "disabled",
            "is_scheduled",
            "qualifiedSearch",
        )
        params = {
            key: content.get(key)
            for key in parameter_keys
            if content.get(key) not in (None, "")
        }
        acl = content.get("eai:acl") or record.get("acl")
        if isinstance(acl, dict):
            params["acl"] = acl
        params["name"] = record.get("name") or content.get("title")
        return params

    @staticmethod
    def _external_refs(
        record: dict[str, Any], content: dict[str, Any], source_name: str
    ) -> list[ExternalReference] | None:
        refs: list[ExternalReference] = []
        url = (
            record.get("id")
            or content.get("url")
            or content.get("drilldown_uri")
            or content.get("drilldown_url")
        )
        external_id = (
            record.get("id")
            or content.get("id")
            or content.get("sid")
            or content.get("finding_id")
            or content.get("source_id")
        )
        if url or external_id:
            refs.append(
                ExternalReference(
                    source_name=source_name,
                    url=(
                        str(url)
                        if url and str(url).startswith(("http://", "https://"))
                        else None
                    ),
                    external_id=str(external_id) if external_id else None,
                )
            )
        return refs or None

    @staticmethod
    def _severity(record: dict[str, Any]) -> str:
        value = str(
            record.get("severity")
            or record.get("urgency")
            or record.get("risk_severity")
            or ""
        ).lower()
        if value in {"critical", "very_high", "very high"}:
            return "critical"
        if value in {"high", "urgent"}:
            return "high"
        if value in {"medium", "moderate"}:
            return "medium"
        return "low"

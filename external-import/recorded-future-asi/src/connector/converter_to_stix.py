from datetime import datetime, timezone
from typing import Literal

from connector.settings import ExposureSeverity
from connector.utils import build_asset_description, detect_observable_type
from connectors_sdk.models import (
    DomainName,
    ExternalReference,
    Incident,
    IPV4Address,
    IPV6Address,
    OrganizationAuthor,
    Relationship,
    TLPMarking,
    Vulnerability,
)
from connectors_sdk.models.base_identified_entity import BaseIdentifiedEntity
from connectors_sdk.models.base_observable_entity import BaseObservableEntity
from connectors_sdk.models.enums import RelationshipType
from pycti import Incident as PyctiIncident
from pycti import OpenCTIConnectorHelper
from pydantic import Field, HttpUrl
from stix2.v21 import Incident as Stix2Incident

AUTHOR_NAME = "Recorded Future ASI"
SOURCE_NAME = "Recorded Future ASI"
INCIDENT_TYPE = "Attack Surface Monitoring"
LABEL_ADDED = "recorded-future-asi:added"
LABEL_CLEARED = "recorded-future-asi:cleared"
EXPOSURE_INCIDENT_ID_ANCHOR = "recorded-future-asi-exposure"

SEVERITY_MAP = {
    "critical": "critical",
    "high": "critical",
    "moderate": "medium",
    "informational": "low",
    "unknown": "low",
}

CLASSIFICATION_TO_FILTER_SEVERITY: dict[str, ExposureSeverity] = {
    "high": "critical",
    "critical": "critical",
    "moderate": "moderate",
    "informational": "informational",
    "unknown": "unknown",
}

SEVERITY_FILTER_RANK: dict[ExposureSeverity, int] = {
    "unknown": 0,
    "informational": 1,
    "moderate": 2,
    "critical": 3,
}

ObservableType = Literal["ipv4", "ipv6", "domain"]


class ExposureIncident(Incident):
    """Incident whose STIX ID is keyed on RF exposure id for stable added/cleared updates."""

    exposure_id: str = Field(default="", exclude=True)

    def to_stix2_object(self) -> Stix2Incident:
        """Make stix object with a deterministic exposure-id-based identifier."""
        return Stix2Incident(
            id=PyctiIncident.generate_id(
                self.exposure_id,
                EXPOSURE_INCIDENT_ID_ANCHOR,
            ),
            name=self.name,
            description=self.description,
            labels=self.labels,
            allow_custom=True,
            source=self.source,
            severity=self.severity,
            incident_type=self.incident_type,
            first_seen=self.first_seen,
            last_seen=self.last_seen,
            objective=self.objective,
            **self._common_stix2_properties(),
        )


class ConverterToStix:
    """Convert RF ASI exposure data into STIX 2.1 objects."""

    def __init__(
        self,
        helper: OpenCTIConnectorHelper,
        tlp_level: Literal["clear", "white", "green", "amber", "amber+strict", "red"],
        project_id: str,
        portal_base_url: HttpUrl | str | None = None,
    ):
        """
        Initialize the converter with necessary configuration.

        Args:
            helper: The helper of the connector. Used for logs.
            tlp_level: The TLP level to add to the created STIX entities.
            project_id: ASI project ID used for external reference deep links.
            portal_base_url: Optional portal base URL for external reference URLs.
        """
        self.helper = helper
        self.project_id = project_id
        self.portal_base_url = (
            str(portal_base_url).rstrip("/") if portal_base_url else None
        )

        self._author = OrganizationAuthor(name=AUTHOR_NAME)
        self._tlp_marking = TLPMarking(level=tlp_level)
        self.author = self._author.to_stix2_object()
        self.tlp_marking = self._tlp_marking.to_stix2_object()

        self._observable_cache: dict[
            tuple[ObservableType, str], BaseObservableEntity
        ] = {}
        self._vulnerability_cache: dict[str, Vulnerability] = {}

    def reset_entity_caches(self) -> None:
        """Clear observable and vulnerability caches between scheduled runs."""
        self._observable_cache.clear()
        self._vulnerability_cache.clear()

    @staticmethod
    def map_severity(rf_severity: str | None) -> str:
        """Map RF ASI severity values to OpenCTI incident severity."""
        if not rf_severity:
            return SEVERITY_MAP["unknown"]
        return SEVERITY_MAP.get(rf_severity.lower(), SEVERITY_MAP["unknown"])

    @staticmethod
    def normalize_classification(classification: str | None) -> ExposureSeverity:
        """Map v1 history rule classification to v2 severity filter vocabulary."""
        if not classification:
            return "unknown"
        return CLASSIFICATION_TO_FILTER_SEVERITY.get(
            classification.lower(),
            "unknown",
        )

    @staticmethod
    def rule_matches_severity_filter(
        rule: dict,
        *,
        filter_severity_min: ExposureSeverity | None = None,
        filter_severity_exact: ExposureSeverity | None = None,
    ) -> bool:
        """Return whether a v1 history rule passes configured severity filters."""
        if filter_severity_min is None and filter_severity_exact is None:
            return True

        normalized = ConverterToStix.normalize_classification(
            rule.get("classification")
        )

        if filter_severity_exact is not None:
            return normalized == filter_severity_exact

        if filter_severity_min is not None:
            return (
                SEVERITY_FILTER_RANK[normalized]
                >= SEVERITY_FILTER_RANK[filter_severity_min]
            )

        return True

    @staticmethod
    def _merge_signature_references(*signatures: dict) -> list[str]:
        """Merge signature reference URLs, deduplicating while preserving order."""
        merged: list[str] = []
        seen: set[str] = set()
        for signature in signatures:
            for reference in signature.get("references") or []:
                if reference and reference not in seen:
                    seen.add(reference)
                    merged.append(reference)
        return merged

    def build_external_references(self, signature: dict) -> list[ExternalReference]:
        """Build external references for an exposure signature."""
        signature_id = signature.get("id") or ""
        references: list[ExternalReference] = []

        if self.portal_base_url:
            references.append(
                ExternalReference(
                    source_name=SOURCE_NAME,
                    external_id=signature_id or None,
                    url=f"{self.portal_base_url}/{self.project_id}/overview",
                )
            )

        for reference in signature.get("references") or []:
            if reference:
                references.append(
                    ExternalReference(source_name=SOURCE_NAME, url=reference)
                )

        return references

    @staticmethod
    def _build_description(signature: dict, asset_count: int | None) -> str | None:
        parts: list[str] = []
        if description := signature.get("description"):
            parts.append(description)
        if asset_count is not None:
            parts.append(f"Affected assets: {asset_count}")
        return "\n\n".join(parts) if parts else None

    def _resolve_created(self, signature: dict) -> datetime:
        added_at = signature.get("added_at")
        if added_at:
            if isinstance(added_at, datetime):
                return (
                    added_at
                    if added_at.tzinfo
                    else added_at.replace(tzinfo=timezone.utc)
                )
            parsed = datetime.fromisoformat(str(added_at).replace("Z", "+00:00"))
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
        self.helper.connector_logger.warning(
            "[CONVERTER] Exposure missing added_at; using current timestamp",
            {"signature_id": signature.get("id"), "name": signature.get("name")},
        )
        return datetime.now(timezone.utc)

    @staticmethod
    def history_rule_to_exposure_summary(rule: dict) -> dict:
        """Map a v1 history rule to a v2-like exposure summary."""
        metadata = rule.get("rule_metadata") or {}
        entity_counts = metadata.get("entity_counts") or {}
        domains = entity_counts.get("domains") or 0
        ips = entity_counts.get("ips") or 0
        return {
            "signature": {
                "id": rule.get("id"),
                "name": rule.get("name"),
                "description": rule.get("description"),
                "severity": rule.get("classification"),
            },
            "asset_count": domains + ips,
        }

    def _build_incident(
        self,
        signature: dict,
        asset_count: int | None,
        *,
        label: str = LABEL_ADDED,
    ) -> ExposureIncident:
        """Build an SDK Incident from an RF ASI exposure signature."""
        exposure_id = signature.get("id") or ""
        return ExposureIncident(
            exposure_id=exposure_id,
            name=signature.get("name") or "Unknown exposure",
            description=self._build_description(signature, asset_count),
            created=self._resolve_created(signature),
            incident_type=INCIDENT_TYPE,
            severity=self.map_severity(signature.get("severity")),
            source=SOURCE_NAME,
            labels=[label],
            author=self._author,
            markings=[self._tlp_marking],
            external_references=self.build_external_references(signature),
        )

    def build_cleared_incident(self, rule: dict) -> ExposureIncident:
        """
        Build an incident-only STIX entity for a cleared exposure.

        Uses the v1 history removed rule payload and the same exposure-id-based
        incident ID as the prior ``recorded-future-asi:added`` update.
        """
        exposure_id = rule.get("id") or ""
        name = rule.get("name") or "Unknown exposure"
        signature = {"id": exposure_id, "name": name}
        return ExposureIncident(
            exposure_id=exposure_id,
            name=name,
            created=datetime.now(timezone.utc),
            incident_type=INCIDENT_TYPE,
            severity=self.map_severity(rule.get("classification")),
            source=SOURCE_NAME,
            labels=[LABEL_CLEARED],
            author=self._author,
            markings=[self._tlp_marking],
            external_references=self.build_external_references(signature),
        )

    def exposure_to_incident(self, exposure_summary: dict) -> Stix2Incident:
        """
        Convert an RF ASI exposure summary into a STIX 2.1 Incident.

        Args:
            exposure_summary: API item with ``signature`` and ``asset_count`` fields.

        Returns:
            STIX 2.1 Incident object.
        """
        signature = exposure_summary.get("signature") or {}
        asset_count = exposure_summary.get("asset_count")
        return self._build_incident(signature, asset_count).to_stix2_object()

    @staticmethod
    def _normalize_cwe_label(cwe_id: str) -> str:
        normalized = cwe_id.strip().lower()
        if normalized.startswith("cwe-"):
            return normalized
        if normalized.isdigit():
            return f"cwe-{normalized}"
        return normalized

    def _vulnerability_from_rf(self, vuln_dict: dict) -> Vulnerability | None:
        """Map an RF ASI vulnerability payload to an SDK Vulnerability."""
        name = vuln_dict.get("cve_id") or vuln_dict.get("name")
        if not name:
            return None

        external_references = [
            ExternalReference(source_name=SOURCE_NAME, url=reference)
            for reference in (vuln_dict.get("references") or [])
            if reference
        ]
        labels = [
            self._normalize_cwe_label(cwe_id)
            for cwe_id in (vuln_dict.get("cwe_ids") or [])
            if cwe_id
        ]

        return Vulnerability(
            name=name,
            cvss_v3_base_score=vuln_dict.get("cvss_score"),
            cvss_v3_vector_string=vuln_dict.get("cvss_metrics"),
            epss_score=vuln_dict.get("epss_score"),
            labels=labels or None,
            external_references=external_references or None,
            author=self._author,
            markings=[self._tlp_marking],
        )

    def _asset_id_to_observable(
        self,
        asset_id: str,
        asset_exposure: dict,
        observable_type: ObservableType,
    ) -> BaseObservableEntity:
        """Map an RF ASI asset_id to the matching SDK observable."""
        common_fields = {
            "value": asset_id.strip(),
            "description": build_asset_description(asset_exposure),
            "author": self._author,
            "markings": [self._tlp_marking],
        }

        if observable_type == "ipv4":
            return IPV4Address(**common_fields)
        if observable_type == "ipv6":
            return IPV6Address(**common_fields)
        return DomainName(**common_fields)

    def _get_or_create_observable(
        self,
        asset_id: str,
        asset_exposure: dict,
    ) -> tuple[BaseObservableEntity | None, bool]:
        """Return a cached observable and whether it was newly created."""
        observable_type = detect_observable_type(asset_id)
        if observable_type is None:
            self.helper.connector_logger.warning(
                "[CONVERTER] Skipping asset with empty or malformed asset_id",
                {"asset_exposure": asset_exposure},
            )
            return None, False

        normalized_asset_id = asset_id.strip()
        cache_key = (observable_type, normalized_asset_id)
        cached_observable = self._observable_cache.get(cache_key)
        if cached_observable is not None:
            return cached_observable, False

        observable = self._asset_id_to_observable(
            normalized_asset_id,
            asset_exposure,
            observable_type,
        )
        self._observable_cache[cache_key] = observable
        return observable, True

    def _get_or_create_vulnerability(
        self,
        vuln_dict: dict,
    ) -> tuple[Vulnerability | None, bool]:
        """Return a cached vulnerability and whether it was newly created."""
        vulnerability = self._vulnerability_from_rf(vuln_dict)
        if vulnerability is None:
            return None, False

        cached_vulnerability = self._vulnerability_cache.get(vulnerability.name)
        if cached_vulnerability is not None:
            return cached_vulnerability, False

        self._vulnerability_cache[vulnerability.name] = vulnerability
        return vulnerability, True

    def build_exposure_objects(
        self,
        exposure_summary: dict,
        exposure_assets_response: dict,
        *,
        label: str = LABEL_ADDED,
    ) -> list[BaseIdentifiedEntity]:
        """
        Build SDK entities for one exposure, including related observables and CVEs.

        Args:
            exposure_summary: Exposure list item with ``signature`` and ``asset_count``.
            exposure_assets_response: Aggregated get-assets response with
                ``signature`` and ``asset_exposures``.

        Returns:
            SDK entities to convert to STIX: incident, new observables/vulnerabilities,
            and per-incident relationships.
        """
        list_signature = exposure_summary.get("signature") or {}
        asset_count = exposure_summary.get("asset_count")
        assets_signature = exposure_assets_response.get("signature") or {}
        references = self._merge_signature_references(list_signature, assets_signature)
        signature_for_incident = {**list_signature, "references": references}
        incident = self._build_incident(
            signature_for_incident,
            asset_count,
            label=label,
        )

        objects: list[BaseIdentifiedEntity] = [incident]
        relationships: list[Relationship] = []
        resolved_vulnerabilities: list[Vulnerability] = []

        for vuln_dict in assets_signature.get("vulnerabilities") or []:
            vulnerability, is_new = self._get_or_create_vulnerability(vuln_dict)
            if vulnerability is None:
                continue
            if is_new:
                objects.append(vulnerability)
            resolved_vulnerabilities.append(vulnerability)
            relationships.append(
                Relationship(
                    type=RelationshipType.RELATED_TO,
                    source=incident,
                    target=vulnerability,
                )
            )

        for asset_exposure in exposure_assets_response.get("asset_exposures") or []:
            asset_id = asset_exposure.get("asset_id")
            if not asset_id:
                self.helper.connector_logger.warning(
                    "[CONVERTER] Skipping asset exposure with missing asset_id",
                    {"asset_exposure": asset_exposure},
                )
                continue

            observable, is_new = self._get_or_create_observable(
                asset_id,
                asset_exposure,
            )
            if observable is None:
                continue
            if is_new:
                objects.append(observable)
            relationships.append(
                Relationship(
                    type=RelationshipType.RELATED_TO,
                    source=incident,
                    target=observable,
                )
            )

            for vulnerability in resolved_vulnerabilities:
                relationships.append(
                    Relationship(
                        type=RelationshipType.RELATED_TO,
                        source=observable,
                        target=vulnerability,
                    )
                )

        objects.extend(relationships)
        return objects

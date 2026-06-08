from datetime import datetime, timezone
from typing import Literal

from connectors_sdk.models import (
    ExternalReference,
    Incident,
    OrganizationAuthor,
    TLPMarking,
)
from pydantic import HttpUrl
from pycti import OpenCTIConnectorHelper
from stix2 import Incident as Stix2Incident

AUTHOR_NAME = "Recorded Future ASI"
SOURCE_NAME = "Recorded Future ASI"
INCIDENT_TYPE = "alert"
LABEL_ADDED = "rf-asi:added"

SEVERITY_MAP = {
    "critical": "critical",
    "moderate": "medium",
    "informational": "low",
    "unknown": "low",
}


class ConverterToStix:
    """Convert RF ASI exposure summaries into STIX 2.1 Incident objects."""

    def __init__(
        self,
        helper: OpenCTIConnectorHelper,
        tlp_level: Literal[
            "clear", "white", "green", "amber", "amber+strict", "red"
        ],
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

    @staticmethod
    def map_severity(rf_severity: str | None) -> str:
        """Map RF ASI severity values to OpenCTI incident severity."""
        if not rf_severity:
            return SEVERITY_MAP["unknown"]
        return SEVERITY_MAP.get(rf_severity.lower(), SEVERITY_MAP["unknown"])

    def build_external_reference(self, signature: dict) -> ExternalReference:
        """Build an external reference for an exposure signature."""
        signature_id = signature.get("id") or ""
        url = None
        if self.portal_base_url and signature_id:
            url = (
                f"{self.portal_base_url}/projects/{self.project_id}"
                f"/exposures/{signature_id}"
            )
        return ExternalReference(
            source_name=SOURCE_NAME,
            external_id=signature_id or None,
            url=url,
        )

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
            return added_at
        self.helper.connector_logger.warning(
            "[CONVERTER] Exposure missing added_at; using current timestamp",
            {"signature_id": signature.get("id"), "name": signature.get("name")},
        )
        return datetime.now(timezone.utc)

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

        incident = Incident(
            name=signature.get("name") or "Unknown exposure",
            description=self._build_description(signature, asset_count),
            created=self._resolve_created(signature),
            incident_type=INCIDENT_TYPE,
            severity=self.map_severity(signature.get("severity")),
            source=SOURCE_NAME,
            labels=[LABEL_ADDED],
            author=self._author,
            markings=[self._tlp_marking],
            external_references=[self.build_external_reference(signature)],
        )
        return incident.to_stix2_object()

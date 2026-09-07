"""ZeroFox Alerts data processor using the SDK BaseDataProcessor."""

from __future__ import annotations

from collections.abc import Generator
from datetime import datetime, timezone
from typing import Any

from connectors_sdk import BaseDataProcessor
from connectors_sdk.models import (
    URL,
    DomainName,
    ExternalReference,
    Incident,
    Note,
    Organization,
    OrganizationAuthor,
    Relationship,
    Text,
    ThreatActorGroup,
    TLPMarking,
)
from connectors_sdk.models.enums import (
    IncidentSeverity,
    IncidentType,
    NoteType,
    RelationshipType,
)
from pydantic import HttpUrl, ValidationError
from zerofox_alerts.client_api import ZerofoxAlertsClient
from zerofox_alerts.models import ZerofoxAlert

# --- Author ---
ZEROFOX_AUTHOR = OrganizationAuthor(
    name="ZeroFox",
    description="ZeroFox provides digital risk protection.",
)

# --- Mapping constants ---
SEVERITY_MAP: dict[str, IncidentSeverity] = {
    "low": IncidentSeverity.LOW,
    "medium": IncidentSeverity.MEDIUM,
    "high": IncidentSeverity.HIGH,
    "critical": IncidentSeverity.CRITICAL,
}

INCIDENT_TYPE_MAP: dict[str, IncidentType] = {
    "phishing": IncidentType.PHISHING,
    "compromised_credential": IncidentType.COMPROMISE,
    "data_leakage": IncidentType.DATA_LEAK,
    "impersonation": IncidentType.REPUTATION_DAMAGE,
    "domain_squatting": IncidentType.TYPOSQUATTING,
    "search_query": IncidentType.ALERT,
}


def _refang_url(value: str) -> str | None:
    """Refang a defanged URL and validate it.

    ZeroFox may return defanged URLs (hxxp://, hxxps://).
    Returns the refanged URL string if valid, None otherwise.
    """
    url = value.replace("hxxps://", "https://").replace("hxxp://", "http://")
    try:
        return str(HttpUrl(url))
    except ValidationError:
        return None


def _to_aware_datetime(value: str | None) -> datetime | None:
    """Convert an ISO 8601 timestamp string to a timezone-aware datetime (UTC)."""
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except (ValueError, TypeError):
        return None


class ZerofoxAlertsProcessor(BaseDataProcessor):
    """Collect ZeroFox alerts and convert them to STIX Incidents.

    Pipeline:
        collect() → paginate through /alerts/ API, yield pages of raw alert dicts
        transform() → parse each alert, convert to STIX objects, yield bundles
    """

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def post_init(self) -> None:
        """Initialize after dependencies are injected."""
        self._config = self.settings.zerofox_alerts  # type: ignore[attr-defined]
        self._client = ZerofoxAlertsClient(
            base_url=str(self._config.api_base_url).rstrip("/"),
            api_token=self._config.api_token.get_secret_value(),
            timeout=60,
            max_retries=3,
            backoff_factor=2.0,
        )
        self._marking = TLPMarking(level=self._config.marking.value)

    # ------------------------------------------------------------------
    # DataProcessor pipeline
    # ------------------------------------------------------------------

    def collect(self) -> Generator[list[dict[str, Any]], None, None]:
        """Fetch alerts from the ZeroFox API using cursor-based pagination.

        Uses `state.last_run` to only fetch alerts newer than the last run.
        Falls back to `import_start_date` config on first run.

        Yields:
            Pages of raw alert dicts.
        """
        min_timestamp = self._get_min_timestamp()
        self.logger.info(
            f"Collecting ZeroFox alerts since {min_timestamp} "
            f"with statuses: {self._config.alert_statuses}"
        )
        self.work_name = f"ZeroFox Alerts import ({min_timestamp})"

        total_alerts = 0
        for page in self._client.get_alerts(
            min_timestamp=min_timestamp,
            status=self._config.alert_statuses,
            page_size=self._config.page_size,
        ):
            total_alerts += len(page)
            self.logger.info(
                f"Fetched page with {len(page)} alerts (total: {total_alerts})"
            )
            yield page

        self.logger.info(f"Collection complete: {total_alerts} alerts fetched.")

    def transform(
        self, data: Generator[list[dict[str, Any]], None, None]
    ) -> Generator[list[Any], None, None]:
        """Parse raw alert dicts and convert to STIX 2.1 objects.

        Args:
            data: Generator of alert pages from collect().

        Yields:
            Lists of STIX objects per page.
        """
        for page in data:
            stix_objects: list[Any] = []
            for raw_alert in page:
                try:
                    alert = ZerofoxAlert.model_validate(raw_alert)
                except ValidationError as e:
                    self.logger.error(f"Failed to parse alert: {e}")
                    continue

                try:
                    objects = self._convert_alert(alert)
                    stix_objects.extend(objects)
                except Exception as e:
                    self.logger.error(
                        f"Failed to convert alert #{alert.id} to STIX: {e}"
                    )
                    continue

            if stix_objects:
                seen_ids: set[str] = set()
                unique_objects = []
                for obj in stix_objects:
                    obj_id = getattr(obj, "id", None)
                    if obj_id and obj_id not in seen_ids:
                        seen_ids.add(obj_id)
                        unique_objects.append(obj)
                    elif not obj_id:
                        unique_objects.append(obj)

                self.logger.info(
                    f"Sending {len(unique_objects)} STIX objects for page."
                )
                yield unique_objects

    # ------------------------------------------------------------------
    # Conversion logic
    # ------------------------------------------------------------------

    def _convert_alert(self, alert: ZerofoxAlert) -> list[Any]:
        """Convert a single ZeroFox alert into SDK model STIX objects."""
        objects: list[Any] = []
        relationships: list[Any] = []

        incident = self._build_incident(alert)
        objects.append(incident)

        self._build_victim(alert, incident, objects, relationships)
        self._build_perpetrator(alert, incident, objects, relationships)
        self._build_observables(alert, incident, objects, relationships)
        self._build_notes(alert, incident, objects)

        return [ZEROFOX_AUTHOR, self._marking, *objects, *relationships]

    def _build_incident(self, alert: ZerofoxAlert) -> Incident:
        """Build the Incident object from an alert."""
        labels = list(alert.tags)
        if alert.network:
            labels.append(f"zerofox:network:{alert.network}")
        if alert.escalated:
            labels.append("zerofox:escalated")
        if alert.metadata and alert.metadata.justification:
            labels.append(f"zerofox:justification:{alert.metadata.justification}")

        return Incident(
            name=alert.rule_name or f"ZeroFox Alert #{alert.id}",
            description=alert.description or None,
            created=_to_aware_datetime(alert.timestamp),
            first_seen=_to_aware_datetime(alert.content_created_at)
            or _to_aware_datetime(alert.timestamp),
            severity=SEVERITY_MAP.get(alert.effective_severity),
            incident_type=INCIDENT_TYPE_MAP.get(alert.alert_type or ""),
            source="ZeroFox",
            labels=labels if labels else None,
            author=ZEROFOX_AUTHOR,
            markings=[self._marking],
            external_references=[
                ExternalReference(
                    source_name="ZeroFox",
                    external_id=str(alert.id),
                    url=alert.external_url,
                )
            ],
        )

    def _build_victim(
        self,
        alert: ZerofoxAlert,
        incident: Incident,
        objects: list[Any],
        relationships: list[Any],
    ) -> None:
        """Build victim Identity and targets relationship."""
        victim = alert.victim_entity
        if not (victim and victim.name):
            return

        victim_identity = Organization(
            name=victim.name,
            author=ZEROFOX_AUTHOR,
            markings=[self._marking],
            external_references=(
                [
                    ExternalReference(
                        source_name="ZeroFox",
                        external_id=str(victim.id),
                    )
                ]
                if victim.id
                else None
            ),
        )
        objects.append(victim_identity)
        relationships.append(
            Relationship(
                type=RelationshipType.TARGETS,
                source=incident,
                target=victim_identity,
                author=ZEROFOX_AUTHOR,
                markings=[self._marking],
            )
        )

    def _build_perpetrator(
        self,
        alert: ZerofoxAlert,
        incident: Incident,
        objects: list[Any],
        relationships: list[Any],
    ) -> None:
        """Build ThreatActor, attributed-to relationship, and perpetrator URL."""
        perpetrator = alert.perpetrator
        if not (perpetrator and perpetrator.name):
            return

        aliases = (
            [perpetrator.display_name]
            if perpetrator.display_name and perpetrator.display_name != perpetrator.name
            else None
        )
        threat_actor = ThreatActorGroup(
            name=perpetrator.name,
            aliases=aliases,
            first_seen=_to_aware_datetime(perpetrator.timestamp),
            author=ZEROFOX_AUTHOR,
            markings=[self._marking],
        )
        objects.append(threat_actor)
        relationships.append(
            Relationship(
                type=RelationshipType.ATTRIBUTED_TO,
                source=incident,
                target=threat_actor,
                author=ZEROFOX_AUTHOR,
                markings=[self._marking],
            )
        )

        # Perpetrator URL
        perp_url_value = _refang_url(perpetrator.url) if perpetrator.url else None
        if perp_url_value:
            perp_url = URL(
                value=perp_url_value,
                author=ZEROFOX_AUTHOR,
                markings=[self._marking],
            )
            objects.append(perp_url)
            relationships.append(
                Relationship(
                    type=RelationshipType.RELATED_TO,
                    source=incident,
                    target=perp_url,
                    author=ZEROFOX_AUTHOR,
                    markings=[self._marking],
                )
            )

    def _build_observables(
        self,
        alert: ZerofoxAlert,
        incident: Incident,
        objects: list[Any],
        relationships: list[Any],
    ) -> None:
        """Build URL, Text, and DomainName observables with relationships."""
        # Offending content URL
        offending_url_value = (
            _refang_url(alert.offending_content_url)
            if alert.offending_content_url
            else None
        )
        if offending_url_value:
            url_obj = URL(
                value=offending_url_value,
                author=ZEROFOX_AUTHOR,
                markings=[self._marking],
            )
            objects.append(url_obj)
            relationships.append(
                Relationship(
                    type=RelationshipType.RELATED_TO,
                    source=incident,
                    target=url_obj,
                    author=ZEROFOX_AUTHOR,
                    markings=[self._marking],
                )
            )

        # Darkweb term as Text observable
        if alert.darkweb_term:
            text_obj = Text(
                value=alert.darkweb_term,
                author=ZEROFOX_AUTHOR,
                markings=[self._marking],
            )
            objects.append(text_obj)
            relationships.append(
                Relationship(
                    type=RelationshipType.RELATED_TO,
                    source=incident,
                    target=text_obj,
                    author=ZEROFOX_AUTHOR,
                    markings=[self._marking],
                )
            )

        # Domain names from metadata occurrences
        for domain_value in alert.observable_domains:
            domain_obj = DomainName(
                value=domain_value,
                author=ZEROFOX_AUTHOR,
                markings=[self._marking],
            )
            objects.append(domain_obj)
            relationships.append(
                Relationship(
                    type=RelationshipType.RELATED_TO,
                    source=incident,
                    target=domain_obj,
                    author=ZEROFOX_AUTHOR,
                    markings=[self._marking],
                )
            )

    def _build_notes(
        self,
        alert: ZerofoxAlert,
        incident: Incident,
        objects: list[Any],
    ) -> None:
        """Build Note objects from alert logs."""
        for log in alert.logs:
            if log.action and log.timestamp:
                note = Note(
                    content=f"[ZeroFox] {log.action}",
                    created=_to_aware_datetime(log.timestamp),
                    note_types=[NoteType.EXTERNAL],
                    objects=[incident],
                    author=ZEROFOX_AUTHOR,
                    markings=[self._marking],
                )
                objects.append(note)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _get_min_timestamp(self) -> str:
        """Determine the minimum timestamp for fetching alerts."""
        if self.state.last_run:
            return self.state.last_run.strftime("%Y-%m-%dT%H:%M:%SZ")
        start = datetime.now(timezone.utc) - self._config.import_start_date
        return start.strftime("%Y-%m-%dT%H:%M:%SZ")

"""Processor turning Wiz Threat Detection issues into OpenCTI Incidents.

Each issue becomes an Incident, and the cloud resource it was raised on
becomes a System linked with a targets relationship.
"""

from collections.abc import Iterator
from datetime import datetime, timezone
from importlib import resources

from connectors_sdk import BaseDataProcessor
from connectors_sdk.models import (
    ExternalReference,
    Incident,
    OrganizationAuthor,
    Relationship,
    System,
    TLPMarking,
)
from connectors_sdk.models.enums import IncidentSeverity, IncidentType, RelationshipType
from pydantic import ValidationError
from wiz_cloud.client_api import WizApiClient
from wiz_cloud.models import WizEntitySnapshot, WizIssue

ISSUES_QUERY = (
    resources.files("wiz_cloud.queries").joinpath("issues.graphql").read_text("utf-8")
)

# Wiz Severity enum to SDK IncidentSeverity. INFORMATIONAL has no OpenCTI
# equivalent and maps to LOW.
_SEVERITY = {
    "CRITICAL": IncidentSeverity.CRITICAL,
    "HIGH": IncidentSeverity.HIGH,
    "MEDIUM": IncidentSeverity.MEDIUM,
    "LOW": IncidentSeverity.LOW,
    "INFORMATIONAL": IncidentSeverity.LOW,
}


def _utc(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class WizIssuesProcessor(BaseDataProcessor):
    # -- lifecycle -----------------------------------------------------------

    def post_init(self) -> None:
        self._config = self.settings.wiz_cloud
        self._client = WizApiClient(
            base_url=str(self._config.api_url),
            auth_url=str(self._config.auth_url),
            client_id=self._config.client_id.get_secret_value(),
            client_secret=self._config.client_secret.get_secret_value(),
            timeout=60,
            max_retries=3,
            backoff_factor=2.0,
        )
        self._author = OrganizationAuthor(name="Wiz")
        self._marking = TLPMarking(level=self._config.marking)

    # -- collect -------------------------------------------------------------

    def collect(self) -> Iterator[list[dict]]:
        since = self.state.issues_last_created_at or (
            datetime.now(tz=timezone.utc) - self._config.since
        )
        self.work_name = f"Wiz Cloud issues import since {since:%Y-%m-%d %H:%M}"
        self.logger.info(
            "[WIZ-CLOUD] Collecting issues",
            {
                "since": since.isoformat(),
                "severity": self._config.issue_severity,
                "status": self._config.issue_status,
            },
        )

        variables = {
            "first": self._config.page_size,
            "after": None,
            # Most recent first. Safe with a createdAt cursor because
            # createdAt is append-only; see state.py.
            "orderBy": {"field": "CREATED_AT", "direction": "DESC"},
            "filterBy": {
                "type": ["THREAT_DETECTION"],
                "severity": list(self._config.issue_severity),
                "status": list(self._config.issue_status),
                "createdAt": {"after": _utc(since)},
            },
        }
        yield from self._client.paginate(
            ISSUES_QUERY, variables, connection_key="issues"
        )

    # -- transform -----------------------------------------------------------

    def transform(self, data: Iterator[list[dict]]) -> Iterator[list]:
        # Run-scoped caches: the same entitySnapshot backs many issues, and
        # author/marking must be sent once, not once per page.
        systems_cache: dict[str, System] = {}
        shared_sent = False
        max_created = self.state.issues_last_created_at

        for page in data:
            objects: list = []
            if not shared_sent:
                objects.extend([self._author, self._marking])
                shared_sent = True

            for raw in page:
                try:
                    issue = WizIssue.model_validate(raw)
                except ValidationError as err:
                    self.logger.warning(
                        "[WIZ-CLOUD] Skipping unparseable issue",
                        {"id": raw.get("id"), "error": str(err)},
                    )
                    continue

                objects.extend(self._convert(issue, systems_cache))
                if max_created is None or issue.created_at > max_created:
                    max_created = issue.created_at

            if objects:
                yield objects

        # Cursor advances only after every page converted without raising.
        # The connector persists state after all processors succeed.
        if max_created is not None:
            self.state.issues_last_created_at = max_created

    # -- conversion ----------------------------------------------------------

    def _convert(self, issue: WizIssue, systems_cache: dict[str, System]) -> list:
        """One Wiz issue to [Incident, System?, Relationship?].

        Returns a list so further entities can be appended without changing
        the signature.
        """
        objects: list = []

        incident = Incident(
            name=self._incident_name(issue),
            description=issue.description or None,  # "" observed in payloads
            incident_type=IncidentType.ALERT,
            severity=_SEVERITY.get(issue.severity, IncidentSeverity.LOW),
            source="Wiz",
            # Event timestamps are the real activity window; createdAt is
            # only when Wiz noticed.
            first_seen=issue.first_event_at or issue.created_at,
            last_seen=issue.last_event_at or issue.updated_at,
            labels=self._labels(issue),
            external_references=self._issue_references(issue),
            author=self._author,
            markings=[self._marking],
        )
        objects.append(incident)

        if issue.entity_snapshot is not None:
            system, is_new = self._system_for(issue.entity_snapshot, systems_cache)
            if is_new:
                objects.append(system)
            objects.append(
                Relationship(
                    type=RelationshipType.TARGETS,
                    source=incident,
                    target=system,
                    author=self._author,
                    markings=[self._marking],
                )
            )

        return objects

    def _incident_name(self, issue: WizIssue) -> str:
        # sourceRule.name + the Wiz issue id. Rule name alone repeats across
        # hundreds of issues and description is rule-generic prose, so the id
        # is what keeps each incident name unambiguous.
        name = issue.rule_name or ""
        return f"{name} - Wiz issue {issue.id}" if name else f"Wiz issue {issue.id}"

    def _labels(self, issue: WizIssue) -> list[str]:
        labels = ["wiz", issue.type.lower().replace("_", "-"), issue.status.lower()]
        if issue.rule_name:
            labels.append(issue.rule_name)
        return labels

    def _issue_references(self, issue: WizIssue) -> list[ExternalReference]:
        references = []
        if issue.url:
            references.append(
                ExternalReference(
                    source_name="Wiz",
                    url=issue.url,  # taken from the API, never rebuilt
                    external_id=issue.id,
                    description="Wiz issue",
                )
            )
        return references

    def _system_for(
        self, snapshot: WizEntitySnapshot, cache: dict[str, System]
    ) -> tuple[System, bool]:
        if snapshot.id in cache:
            return cache[snapshot.id], False

        description_parts = [
            part
            for part in (
                snapshot.type,
                snapshot.cloud_platform,
                snapshot.region or None,  # "" observed in payloads
                snapshot.provider_id or None,
            )
            if part
        ]
        references = []
        if snapshot.external_id:
            references.append(
                ExternalReference(
                    source_name="Wiz",
                    external_id=snapshot.external_id,
                    description="Cloud provider resource identifier",
                    # cloudProviderURL is usually "" in practice; guard on
                    # falsiness, not None.
                    url=snapshot.cloud_provider_url or None,
                )
            )

        system = System(
            name=snapshot.name,
            description=" | ".join(description_parts) or None,
            labels=[f"{key}={value}" for key, value in snapshot.tags.items()],
            external_references=references,
            author=self._author,
            markings=[self._marking],
        )
        cache[snapshot.id] = system
        return system, True

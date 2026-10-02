from __future__ import annotations

from typing import TYPE_CHECKING

from connectors_sdk.models import (
    ExternalReference,
    Incident,
    OrganizationAuthor,
    Relationship,
    System,
    TLPMarking,
)
from connectors_sdk.models.enums import (
    IncidentSeverity,
    IncidentType,
    RelationshipType,
)

if TYPE_CHECKING:
    from wiz_client.models import WizEntitySnapshot, WizIssue


# Wiz Severity enum to SDK IncidentSeverity. INFORMATIONAL has no OpenCTI
# equivalent and maps to LOW.
_SEVERITY = {
    "CRITICAL": IncidentSeverity.CRITICAL,
    "HIGH": IncidentSeverity.HIGH,
    "MEDIUM": IncidentSeverity.MEDIUM,
    "LOW": IncidentSeverity.LOW,
    "INFORMATIONAL": IncidentSeverity.LOW,
}


class IssueConverter:
    """Convert Wiz issues into Incidents, Systems and "targets" relationships.

    Args:
        author: Author added to every object.
        marking: Marking added to every object.
    """

    def __init__(self, author: OrganizationAuthor, marking: TLPMarking) -> None:
        self._author = author
        self._marking = marking

    def convert_issue(self, issue: WizIssue, systems_cache: dict[str, System]) -> list:
        """Convert one Wiz issue into its bundle objects.

        Args:
            issue: Parsed Wiz issue.
            systems_cache: Systems already built during this run, keyed by
                entitySnapshot id, so a resource shared by several issues is
                emitted once and targeted many times.

        Returns:
            A list holding the Incident, plus the System and the targets
            Relationship when the issue carries an entity snapshot. A list is
            returned so further entities can be appended without changing the
            signature.
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
        # No "wiz" label: the incident is already created-by the Wiz author
        # and carries a Wiz external reference, so it would only add a label
        # every analyst has to filter out.
        labels = [issue.type.lower().replace("_", "-"), issue.status.lower()]
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

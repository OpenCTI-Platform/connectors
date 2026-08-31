"""Processor turning Wiz Threat Detection issues into OpenCTI Incidents.

Each issue becomes an Incident, and the cloud resource it was raised on
becomes a System linked with a targets relationship. When vulnerability
import is enabled, the findings of that resource are fetched while the issue
is converted and travel in the same bundle, so an issue and its
vulnerabilities are never committed apart.
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
    Vulnerability,
)
from connectors_sdk.models.enums import IncidentSeverity, IncidentType, RelationshipType
from pydantic import ValidationError
from wiz_cloud.client_api import WizApiClient
from wiz_cloud.models import WizEntitySnapshot, WizIssue
from wiz_cloud.processors.vulnerabilities_processor import WizVulnerabilitiesProcessor

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
    # Full precision matters: Wiz createdAt carries microseconds and the
    # filter is exclusive, so truncating to the second would re-select the
    # issue the cursor points at on every run.
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


class WizIssuesProcessor(BaseDataProcessor):
    # Set in post_init() when vulnerability import is enabled. Declared here
    # so conversion works on a processor whose post_init() was skipped.
    _vulnerabilities: WizVulnerabilitiesProcessor | None = None

    # -- lifecycle -----------------------------------------------------------

    def post_init(self) -> None:
        """Build the Wiz client and the objects shared by every bundle.

        Called by the SDK once dependencies are injected, so settings are
        available here but not in __init__.
        """
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
        # Built here rather than in __init__ because it needs the settings and
        # shares the client, so both queries ride on a single access token.
        self._vulnerabilities: WizVulnerabilitiesProcessor | None = None
        if self._config.import_vulnerabilities:
            self._vulnerabilities = WizVulnerabilitiesProcessor(
                client=self._client,
                config=self._config,
                logger=self.logger,
                author=self._author,
                marking=self._marking,
            )

    # -- collect -------------------------------------------------------------

    def collect(self) -> Iterator[list[dict]]:
        """Fetch Threat Detection issues created since the last run.

        The lower bound is the stored cursor, or now minus the configured
        since window on a first run.

        Yields:
            Lists of raw issue dicts, one per API page.
        """
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
        """Convert raw issue pages into bundle objects.

        Unparseable issues are logged and skipped rather than failing the run.

        When vulnerability import is enabled, each issue is emitted as its own
        bundle carrying the vulnerabilities of its resource, so the two are
        committed together. Otherwise one bundle per page is emitted, as
        before.

        Args:
            data: Pages of raw issue dicts yielded by collect().

        Yields:
            Lists of SDK objects: one bundle per issue when vulnerabilities
            are imported, one bundle per non-empty page otherwise.
        """
        # Run-scoped caches: the same entitySnapshot backs many issues, and
        # author/marking must be sent once, not once per page.
        systems_cache: dict[str, System] = {}
        shared_sent = False
        max_created = self.state.issues_last_created_at
        issues_converted = 0
        bundles_sent = 0
        vulnerabilities_sent = 0

        for page in data:
            page_objects: list = []

            for raw in page:
                try:
                    issue = WizIssue.model_validate(raw)
                except ValidationError as err:
                    self.logger.warning(
                        "[WIZ-CLOUD] Skipping unparseable issue",
                        {"id": raw.get("id"), "error": str(err)},
                    )
                    continue

                objects = self._convert(issue, systems_cache)
                issues_converted += 1
                if max_created is None or issue.created_at > max_created:
                    max_created = issue.created_at

                if self._vulnerabilities is None:
                    page_objects.extend(objects)
                    continue

                vulnerabilities = 0
                if issue.entity_snapshot is not None:
                    found = self._vulnerabilities.objects_for_asset(
                        issue.entity_snapshot.id,
                        systems_cache[issue.entity_snapshot.id],
                    )
                    vulnerabilities = sum(
                        1 for obj in found if isinstance(obj, Vulnerability)
                    )
                    objects.extend(found)
                vulnerabilities_sent += vulnerabilities

                self.logger.info(
                    "[WIZ-CLOUD] Sending an incident with its vulnerabilities",
                    {
                        "issue_id": issue.id,
                        "asset": (
                            issue.entity_snapshot.name
                            if issue.entity_snapshot
                            else None
                        ),
                        # Zero when the asset was already scanned this run:
                        # its vulnerabilities went out with an earlier issue.
                        "vulnerabilities": vulnerabilities,
                    },
                )
                yield self._with_shared(objects, shared_sent)
                shared_sent = True
                bundles_sent += 1

            if page_objects:
                yield self._with_shared(page_objects, shared_sent)
                shared_sent = True
                bundles_sent += 1

        if issues_converted == 0:
            self.logger.info(
                "[WIZ-CLOUD] Nothing to ingest, no new issue since the last run",
                (
                    {"since": _utc(self.state.issues_last_created_at)}
                    if self.state.issues_last_created_at
                    else {}
                ),
            )
        else:
            self.logger.info(
                "[WIZ-CLOUD] Import finished",
                {
                    "incidents": issues_converted,
                    "vulnerabilities": vulnerabilities_sent,
                    "bundles": bundles_sent,
                },
            )

        self._advance_cursor(max_created)

    def _with_shared(self, objects: list, already_sent: bool) -> list:
        """Prepend the author and marking to the first bundle carrying data.

        Args:
            objects: The bundle objects.
            already_sent: Whether a previous bundle carried them.

        Returns:
            The bundle, with author and marking in front when they are still
            owed. They never travel in a bundle of their own.
        """
        if already_sent:
            return objects
        return [self._author, self._marking, *objects]

    def _advance_cursor(self, max_created: datetime | None) -> None:
        """Store the newest issue createdAt, unless vulnerabilities failed.

        A failed fetch is not fatal, but the issues it belongs to must not be
        marked as done: leaving the cursor where it is replays the whole
        window on the next run. Replaying is harmless because every object
        carries a deterministic id, whereas advancing would drop those
        vulnerabilities for good.

        The connector persists the state only after all processors succeed.

        Args:
            max_created: The newest createdAt converted this run, if any.
        """
        if max_created is None:
            return

        failures = self._vulnerabilities.failures if self._vulnerabilities else 0
        if failures:
            self.logger.warning(
                "[WIZ-CLOUD] Holding the issues cursor back after vulnerability "
                "failures, the window will be imported again on the next run",
                {"failed_assets": failures},
            )
            return

        self.state.issues_last_created_at = max_created

    # -- conversion ----------------------------------------------------------

    def _convert(self, issue: WizIssue, systems_cache: dict[str, System]) -> list:
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

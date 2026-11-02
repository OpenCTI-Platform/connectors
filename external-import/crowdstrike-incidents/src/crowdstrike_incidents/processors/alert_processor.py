"""CrowdStrike alert processor using the SDK BaseDataProcessor.

Pipeline:
    collect()   -> stream pages of alerts updated since the stored cursor
    transform() -> map each alert to an Incident and its related objects,
                   yield one bundle per page together with the page cursor
    send()      -> send the bundle, then checkpoint the cursor

Checkpointing deliberately deviates from the SDK rule that processors must not
call ``state.save()``: the cursor is saved after every bundle so that a crash
during a large backlog resumes instead of restarting from the beginning. The
SDK's final ``save()`` only adds ``last_run`` on top of it.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Generator, Iterable
from datetime import datetime, timedelta, timezone
from typing import Any

from connectors_sdk import BaseDataProcessor, ExternalImportConnectorState
from connectors_sdk.models import (
    AttackPattern,
    ExternalReference,
    File,
    Hostname,
    Incident,
    IPV4Address,
    IPV6Address,
    Note,
    OrganizationAuthor,
    Relationship,
    TLPMarking,
    UserAccount,
)
from connectors_sdk.models.enums import (
    HashAlgorithm,
    IncidentSeverity,
    IncidentType,
    NoteType,
    RelationshipType,
)
from crowdstrike_incidents.client_api import (
    AlertPage,
    CrowdstrikeAlertsClient,
    CrowdstrikeEventsClient,
)
from crowdstrike_incidents.models import CrowdstrikeAlert, SourceEvent
from crowdstrike_incidents.settings import Severity
from pydantic import Field, ValidationError

AUTHOR = OrganizationAuthor(
    name="CrowdStrike",
    description="CrowdStrike Falcon cybersecurity platform.",
)

SOURCE_NAMES: dict[str, str] = {
    "ngsiem": "CrowdStrike Falcon Next-Gen SIEM",
}

SEVERITY_MAP: dict[Severity, IncidentSeverity] = {
    Severity.INFORMATIONAL: IncidentSeverity.LOW,
    Severity.LOW: IncidentSeverity.LOW,
    Severity.MEDIUM: IncidentSeverity.MEDIUM,
    Severity.HIGH: IncidentSeverity.HIGH,
    Severity.CRITICAL: IncidentSeverity.CRITICAL,
}

# Length of the alert ID suffix that makes Incident names unique.
SHORT_ID_LENGTH = 8

# Source events can predate their alert by the rule lookback; the search window
# starts from the oldest detection window of the page, minus this margin.
EVENT_SEARCH_MARGIN = timedelta(hours=1)

# MITRE ATT&CK technique or sub-technique ID; CrowdStrike also uses
# proprietary technique IDs, which are not mapped to Attack Patterns.
MITRE_TECHNIQUE_ID = re.compile(r"^T\d{4}(\.\d{3})?$")


class CrowdstrikeIncidentsState(ExternalImportConnectorState):
    """Connector state with the incremental cursor."""

    last_updated_timestamp: str | None = Field(
        default=None,
        description="updated_timestamp to resume from (raw API value).",
    )
    last_boundary_ids: list[str] = Field(
        default_factory=list,
        description="Composite IDs already sent whose timestamp equals the cursor.",
    )

    def load(self, force: bool = False) -> None:
        """Load the state, resetting the fields absent from the stored state.

        The SDK only overwrites the keys present in the stored state: after a
        state reset in OpenCTI, the previous in-memory cursor would survive and
        be saved back.
        """
        if self._client and (force or self._can_be_loaded):
            for name, model_field in type(self).model_fields.items():
                setattr(self, name, model_field.get_default(call_default_factory=True))
        super().load(force=force)


HASH_LENGTHS: dict[HashAlgorithm, int] = {
    HashAlgorithm.MD5: 32,
    HashAlgorithm.SHA1: 40,
    HashAlgorithm.SHA256: 64,
}
HEX = re.compile(r"^[0-9a-fA-F]+$")


def _is_valid_hash(algorithm: HashAlgorithm, value: str) -> bool:
    """Whether a hash is hexadecimal and has the length of its algorithm."""
    return len(value) == HASH_LENGTHS[algorithm] and bool(HEX.match(value))


def _is_placeholder_hash(value: str) -> bool:
    """Whether a hash is a placeholder made only of zeros."""
    return set(value) == {"0"}


def _indicator_id(alert: CrowdstrikeAlert) -> str:
    """Last segment of the alert composite ID, which keys its source event."""
    return alert.composite_id.rsplit(":", 1)[-1]


def _escape_cell(value: Any) -> str:
    """Escape a value for a markdown table cell."""
    return str(value).replace("|", "\\|").replace("\r", " ").replace("\n", " ")


def _parse_severity(severity_name: str | None) -> Severity | None:
    try:
        return Severity((severity_name or "").lower())
    except ValueError:
        return None


class AlertProcessor(BaseDataProcessor):
    """Collect CrowdStrike Falcon alerts and convert them to OpenCTI Incidents."""

    state: CrowdstrikeIncidentsState

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def post_init(self) -> None:
        """Initialize the API client once dependencies are injected."""
        self._config = self.settings.crowdstrike_incidents  # type: ignore[attr-defined]
        self._client = CrowdstrikeAlertsClient(
            base_url=str(self._config.api_base_url).rstrip("/"),
            client_id=self._config.client_id,
            client_secret=self._config.client_secret.get_secret_value(),
        )
        self._marking = TLPMarking(level=self._config.tlp_level.value)
        self._events_client = (
            CrowdstrikeEventsClient(
                base_url=str(self._config.api_base_url).rstrip("/"),
                client_id=self._config.client_id,
                client_secret=self._config.client_secret.get_secret_value(),
            )
            if self._config.enrich_from_events
            else None
        )

    # ------------------------------------------------------------------
    # DataProcessor pipeline
    # ------------------------------------------------------------------

    def collect(self) -> Generator[AlertPage, None, None]:
        """Stream pages of raw alerts updated since the stored cursor."""
        since = self.state.last_updated_timestamp or self._initial_cursor()
        self.work_name = f"CrowdStrike Incidents import (since {since})"
        self.logger.info(
            "Collecting CrowdStrike alerts",
            meta={"since": since, "products": ",".join(self._config.products)},
        )
        total = 0
        for page in self._client.iter_alert_pages(
            since=since,
            products=self._config.products,
            include_hidden=self._config.include_hidden,
            skip_ids=self.state.last_boundary_ids,
        ):
            total += len(page.alerts)
            if page.skipped_ids:
                self.logger.warning(
                    "Alerts without composite_id or updated_timestamp skipped",
                    meta={"composite_ids": list(page.skipped_ids)},
                )
            self.logger.info(f"Fetched {len(page.alerts)} alerts (total: {total})")
            yield page
        self.logger.info(f"Collection complete: {total} alerts fetched.")

    def transform(
        self, data: Iterable[AlertPage]
    ) -> Generator[tuple[list[Any], AlertPage], None, None]:
        """Yield ``(objects, page)`` per page.

        The page carries the cursor computed by the client; it also covers the
        alerts that were filtered out or failed to convert, so that they are not
        fetched again.
        """
        for page in data:
            objects: list[Any] = []
            alerts: list[CrowdstrikeAlert] = []
            for raw_alert in page.alerts:
                try:
                    alert = CrowdstrikeAlert.model_validate(raw_alert)
                except ValidationError as err:
                    self.logger.error(
                        "Failed to parse alert",
                        meta={
                            "composite_id": raw_alert.get("composite_id"),
                            "error": str(err),
                        },
                    )
                    continue
                if self._is_wanted(alert):
                    alerts.append(alert)

            events = self._source_events(alerts)
            for alert in alerts:
                try:
                    objects.extend(
                        self._convert_alert(alert, events.get(_indicator_id(alert)))
                    )
                except Exception as err:  # noqa: BLE001
                    self.logger.error(
                        "Failed to convert alert",
                        meta={"composite_id": alert.composite_id, "error": str(err)},
                    )
            yield self._dedup(objects), page

    def send(  # type: ignore[override]
        self, bundle_objects: Iterable[tuple[list[Any], AlertPage]]
    ) -> None:
        """Send each bundle, then checkpoint the cursor (see module docstring)."""
        for objects, page in bundle_objects:
            if objects:
                self.work_manager.send(objects, self.work_name)
            self.state.last_updated_timestamp = page.cursor
            self.state.last_boundary_ids = sorted(page.boundary_ids)
            self.state.save()

    # ------------------------------------------------------------------
    # Conversion
    # ------------------------------------------------------------------

    def _source_events(self, alerts: list[CrowdstrikeAlert]) -> dict[str, SourceEvent]:
        """Fetch the source events of the alerts, keyed by indicator ID.

        Enrichment is best effort: when the search fails, the Incidents are
        still created, without their threat observables.
        """
        if self._events_client is None or not alerts:
            return {}
        since = (
            min(alert.start_time or alert.created_timestamp for alert in alerts)
            - EVENT_SEARCH_MARGIN
        )
        try:
            raw_events = self._events_client.get_source_events(
                [_indicator_id(alert) for alert in alerts], since=since
            )
        except Exception as err:  # noqa: BLE001
            self.logger.warning(
                "Source events search failed, Incidents are created without "
                "their threat observables",
                meta={"alerts": len(alerts), "error": str(err)},
            )
            return {}

        events: dict[str, SourceEvent] = {}
        for raw_event in raw_events:
            try:
                event = SourceEvent.model_validate(raw_event)
            except ValidationError as err:
                self.logger.warning(
                    "Failed to parse source event", meta={"error": str(err)}
                )
                continue
            events.setdefault(event.indicator_id, event)
        self.logger.info(
            f"Found the source event of {len(events)} of {len(alerts)} alerts.",
            meta={"search_window_start": since.isoformat()},
        )
        return events

    def _convert_alert(
        self, alert: CrowdstrikeAlert, event: SourceEvent | None = None
    ) -> list[Any]:
        """Convert an alert, and its source event if any, into the Incident and
        its related objects."""
        incident = self._build_incident(alert)
        related: list[Any] = []
        relationships: list[Relationship] = []

        for observable in [
            *self._build_observables(alert, event),
            *self._build_threat_observables(event),
        ]:
            related.append(observable)
            relationships.append(
                self._relationship(RelationshipType.RELATED_TO, incident, observable)
            )
        for attack_pattern in self._build_attack_patterns(alert):
            related.append(attack_pattern)
            relationships.append(
                self._relationship(RelationshipType.USES, incident, attack_pattern)
            )
        note = self._build_execution_note(alert, event, incident)
        if note:
            related.append(note)

        return [AUTHOR, self._marking, incident, *related, *relationships]

    def _build_execution_note(
        self,
        alert: CrowdstrikeAlert,
        event: SourceEvent | None,
        incident: Incident,
    ) -> Note | None:
        """Build a Note with the execution context of the source event.

        The context is kept out of the Incident description: an update of the
        alert imported while the enrichment is unavailable would otherwise erase
        it. The Note is only sent when the source event is found, and its ID
        derives from its content and the alert creation date, so it is stable.
        Temporary: the command line and process chain are to be moved to a
        Process observable once the connectors-sdk provides one
        (OpenCTI-Platform/connectors#7968).
        """
        if event is None:
            return None
        chain = [event.grandparent_name, event.parent_name, event.file_name]
        rows = [
            ("Command line", event.command_line),
            ("Executable", event.executable),
            ("Process chain", " → ".join(name for name in chain if name)),
        ]
        table = "\n".join(
            f"| {label} | {_escape_cell(value)} |"
            for label, value in rows
            if value not in (None, "")
        )
        if not table:
            return None
        return Note(
            abstract="Execution context (CrowdStrike Next-Gen SIEM source event)",
            content=f"| Attribute | Value |\n| --- | --- |\n{table}",
            created=alert.created_timestamp,
            note_types=[NoteType.EXTERNAL],
            objects=[incident],
            author=AUTHOR,
            markings=[self._marking],
        )

    def _build_incident(self, alert: CrowdstrikeAlert) -> Incident:
        source = SOURCE_NAMES.get(alert.product or "", "CrowdStrike Falcon")
        severity = _parse_severity(alert.severity_name)
        tactics = list(dict.fromkeys(t.tactic for t in alert.mitre_attack if t.tactic))
        return Incident(
            name=self._incident_name(alert),
            description=self._incident_description(alert),
            created=alert.created_timestamp,
            first_seen=alert.start_time,
            last_seen=alert.end_time,
            severity=SEVERITY_MAP.get(severity) if severity else None,
            incident_type=IncidentType.ALERT,
            source=source,
            labels=tactics or None,
            author=AUTHOR,
            markings=[self._marking],
            external_references=[
                ExternalReference(
                    source_name=source,
                    url=alert.falcon_host_link,
                    external_id=alert.composite_id,
                )
            ],
        )

    @staticmethod
    def _incident_name(alert: CrowdstrikeAlert) -> str:
        """Build '<rule> (<alert short ID>)'.

        OpenCTI identifies an Incident by its name and creation date, so the name
        must be stable across alert updates and unique per alert: hosts and
        users, which can change, are in the description, and the short alert ID
        makes the name unique.
        """
        rule = alert.display_name or alert.name
        if not rule:
            return alert.composite_id
        return f"{rule} ({_indicator_id(alert)[:SHORT_ID_LENGTH]})"

    @staticmethod
    def _user_names(alert: CrowdstrikeAlert) -> list[str]:
        names = [u.user_name for u in alert.users if u.user_name] or alert.user_names
        return list(dict.fromkeys(names))

    @classmethod
    def _incident_description(cls, alert: CrowdstrikeAlert) -> str:
        rows: list[tuple[str, Any]] = [
            ("Hosts", ", ".join(dict.fromkeys(alert.host_names))),
            ("Users", ", ".join(cls._user_names(alert))),
            ("Product", alert.product),
            ("Type", alert.type),
            ("Status", alert.status),
            ("Priority", alert.priority_value),
            ("Priority explanation", "; ".join(alert.priority_explanation)),
            ("Detection ID", alert.detection_id),
            ("Event IDs", ", ".join(alert.event_ids)),
        ]
        table = "\n".join(
            f"| {label} | {_escape_cell(value)} |"
            for label, value in rows
            if value not in (None, "")
        )
        parts = [alert.description] if alert.description else []
        parts.append(f"| Attribute | Value |\n| --- | --- |\n{table}")
        return "\n\n".join(parts)

    def _build_observables(
        self, alert: CrowdstrikeAlert, event: SourceEvent | None = None
    ) -> list[Any]:
        """Build the victim-side observables (host, IPs, user accounts)."""
        common = {"author": AUTHOR, "markings": [self._marking]}
        observables: list[Any] = []

        for host in dict.fromkeys(alert.host_names):
            observables.append(Hostname(value=host, **common))

        ips = [*alert.source_ips]
        if event and event.agent_public_ip:
            ips.append(event.agent_public_ip)
        for value in dict.fromkeys(ips):
            try:
                ip = ipaddress.ip_address(value)
            except ValueError:
                self.logger.warning(
                    "Invalid IP address skipped",
                    meta={"composite_id": alert.composite_id, "value": value},
                )
                continue
            ip_class = IPV4Address if ip.version == 4 else IPV6Address
            observables.append(ip_class(value=value, **common))

        # Keyed on (login, SID): the same login can be different accounts (e.g.
        # local Administrator on several hosts). A login without SID is only
        # added when no account with a SID has this login, to keep a stable ID.
        accounts = dict.fromkeys(
            (user.user_name, user.sid) for user in alert.users if user.user_name
        )
        logins_with_sid = {login for login, _ in accounts}
        for login in alert.user_names:
            if login not in logins_with_sid:
                accounts.setdefault((login, None))
        for login, sid in accounts:
            observables.append(
                UserAccount(account_login=login, user_id=sid or None, **common)
            )

        return observables

    def _build_threat_observables(self, event: SourceEvent | None) -> list[Any]:
        """Build the threat-side observables of the source event (executed file).

        Placeholder hashes made only of zeros (e.g. the SHA-1 CrowdStrike sends
        when it did not compute it) are dropped: OpenCTI matches Files on any of
        their hashes, so a shared placeholder would merge unrelated binaries.
        Malformed hashes are dropped too, as stix2 rejects them and the whole
        Incident would be lost. Enrichment is best effort: a File that cannot
        be built is logged and skipped, the Incident is kept.
        """
        if event is None:
            return []
        hashes: dict[HashAlgorithm, str] = {}
        for algorithm, value in (
            (HashAlgorithm.SHA256, event.sha256),
            (HashAlgorithm.MD5, event.md5),
            (HashAlgorithm.SHA1, event.sha1),
        ):
            if not value or _is_placeholder_hash(value):
                continue
            if not _is_valid_hash(algorithm, value):
                self.logger.warning(
                    "Malformed hash skipped",
                    meta={
                        "indicator_id": event.indicator_id,
                        "algorithm": algorithm.value,
                    },
                )
                continue
            hashes[algorithm] = value
        if not hashes and not event.file_name:
            return []
        try:
            return [
                File(
                    name=event.file_name,
                    hashes=hashes or None,
                    author=AUTHOR,
                    markings=[self._marking],
                )
            ]
        except Exception as err:  # noqa: BLE001
            self.logger.warning(
                "Failed to build the File of the source event",
                meta={"indicator_id": event.indicator_id, "error": str(err)},
            )
            return []

    def _build_attack_patterns(self, alert: CrowdstrikeAlert) -> list[AttackPattern]:
        attack_patterns: dict[str, AttackPattern] = {}
        for technique in alert.mitre_attack:
            technique_id = (technique.technique_id or "").strip()
            if not MITRE_TECHNIQUE_ID.match(technique_id):
                continue
            attack_patterns.setdefault(
                technique_id,
                # No author nor marking: the Attack Pattern merges with the
                # shared MITRE ATT&CK one and must not restrict or re-attribute it.
                AttackPattern(
                    name=technique.technique or technique_id,
                    mitre_id=technique_id,
                ),
            )
        return list(attack_patterns.values())

    def _relationship(
        self, relationship_type: RelationshipType, source: Any, target: Any
    ) -> Relationship:
        return Relationship(
            type=relationship_type,
            source=source,
            target=target,
            author=AUTHOR,
            markings=[self._marking],
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _is_wanted(self, alert: CrowdstrikeAlert) -> bool:
        """Keep supported products and alerts at or above the minimum severity.

        Alerts with an unknown severity are always kept.
        """
        if alert.product not in self._config.products:
            return False
        threshold = self._config.severity_min
        severity = _parse_severity(alert.severity_name)
        if threshold is None or severity is None:
            return True
        return severity >= threshold

    def _initial_cursor(self) -> str:
        start = datetime.now(timezone.utc) - self._config.import_start_date
        return start.strftime("%Y-%m-%dT%H:%M:%SZ")

    @staticmethod
    def _dedup(objects: list[Any]) -> list[Any]:
        seen: set[str] = set()
        unique: list[Any] = []
        for obj in objects:
            obj_id = getattr(obj, "id", None)
            if obj_id is None or obj_id not in seen:
                if obj_id is not None:
                    seen.add(obj_id)
                unique.append(obj)
        return unique

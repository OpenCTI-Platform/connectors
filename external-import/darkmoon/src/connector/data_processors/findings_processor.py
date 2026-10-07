"""Processor importing Darkmoon findings as STIX objects.

Each Darkmoon campaign becomes one OpenCTI ``Report`` grouping, for every
finding it contains:

    - a ``Vulnerability`` (named after its CVE when present, otherwise after the
      finding title), carrying the CVSS score/vector/severity and any detectable
      CWE id, plus external references (CVE, MITRE ATT&CK, ISO 27001, the
      Darkmoon finding id);
    - a ``Note`` holding the finding's evidence (reproduction commands, raw
      HTTP request/response, logs, technical analysis, remediation), linked to
      the vulnerability;
    - optionally an ``Attack Pattern`` for the finding's MITRE ATT&CK technique,
      linked to the vulnerability with a ``related-to`` relationship.

The STIX objects are built with ``connectors-sdk`` models so deterministic IDs
are handled by the SDK/pycti.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from connectors_sdk import BaseDataProcessor
from connectors_sdk.models import (
    AttackPattern,
    ExternalReference,
    Note,
    OrganizationAuthor,
    Relationship,
    Report,
    TLPMarking,
    Vulnerability,
)
from connectors_sdk.models.enums import (
    CvssSeverity,
    NoteType,
    RelationshipType,
    ReportType,
)
from darkmoon_client import DarkmoonClient, parse_darkmoon_datetime

if TYPE_CHECKING:
    from connector.settings import ConnectorSettings
    from connector.state import ConnectorState
    from connectors_sdk.models import BaseIdentifiedObject
    from darkmoon_client.models import CampaignBundle, DarkmoonFinding

_CWE_RE = re.compile(r"CWE-\d+", re.IGNORECASE)
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)

_SEVERITY_TO_CVSS_SEVERITY = {
    "critical": CvssSeverity.CRITICAL,
    "high": CvssSeverity.HIGH,
    "medium": CvssSeverity.MEDIUM,
    "low": CvssSeverity.LOW,
}
_SEVERITY_TO_SCORE = {
    "critical": 90,
    "high": 75,
    "medium": 50,
    "low": 25,
    "info": 5,
}


class FindingConversionError(Exception):
    """Raised when a single Darkmoon finding cannot be converted to STIX."""


class CampaignConversionError(Exception):
    """Raised when a single Darkmoon campaign cannot be converted to STIX."""


class FindingsProcessor(BaseDataProcessor):
    """Fetch Darkmoon campaign findings from disk and convert them to STIX."""

    settings: ConnectorSettings
    state: ConnectorState

    work_name = "Darkmoon findings import"

    def post_init(self) -> None:
        """Build the filesystem client and the STIX objects shared by every item."""
        self.client = DarkmoonClient(
            export_path=self.settings.darkmoon.export_path,
            logger=self.logger,
        )
        self.author = OrganizationAuthor(
            name="Darkmoon",
            description="Darkmoon autonomous AI pentest (OSS CLI, GPLv3) by ASC-IT. "
            "https://github.com/ASCIT31/Dark-Moon",
        )
        self.tlp_marking = TLPMarking(level=self.settings.darkmoon.tlp_level)

    def collect(self) -> list[CampaignBundle]:
        """Fetch Darkmoon campaign bundles newer than the last checkpoint."""
        since = (
            self.state.last_campaign_date
            or self.state.last_run
            or self.settings.darkmoon.import_since
        )
        return self.client.collect(since=since)

    def transform(
        self, bundles: list[CampaignBundle]
    ) -> list[BaseIdentifiedObject] | None:
        """Convert campaign bundles into STIX objects and checkpoint progress."""
        objects_by_id: dict[str, BaseIdentifiedObject] = {}
        objects_by_id[self.author.id] = self.author
        objects_by_id[self.tlp_marking.id] = self.tlp_marking

        latest_date = self.state.last_campaign_date

        for bundle in bundles:
            try:
                campaign_objects = self._convert_campaign(bundle)
            except CampaignConversionError as err:
                self.logger.warning(
                    "Failed to convert Darkmoon campaign, skipping it",
                    {"campaign_id": bundle.campaign.id, "error": str(err)},
                )
                continue

            for obj in campaign_objects:
                objects_by_id.setdefault(obj.id, obj)

            campaign_date = parse_darkmoon_datetime(bundle.campaign.date)
            if campaign_date is not None and (
                latest_date is None or campaign_date > latest_date
            ):
                latest_date = campaign_date

        # Only the author + marking means nothing was actually imported.
        if len(objects_by_id) <= 2:
            return None

        try:
            return list(objects_by_id.values())
        finally:
            if latest_date is not None:
                self.state.last_campaign_date = latest_date

    def _convert_campaign(self, bundle: CampaignBundle) -> list[BaseIdentifiedObject]:
        """Convert one campaign bundle into a Report and all its child objects."""
        try:
            campaign = bundle.campaign
            host = (
                ((bundle.target.host or bundle.target.ip) if bundle.target else None)
                or campaign.target_id
                or "unknown target"
            )

            published = parse_darkmoon_datetime(campaign.date) or datetime.now(
                timezone.utc
            )

            report_objects: list[BaseIdentifiedObject] = []
            for finding in bundle.findings:
                try:
                    report_objects.extend(self._convert_finding(finding))
                except FindingConversionError as err:
                    self.logger.warning(
                        "Failed to convert Darkmoon finding, skipping it",
                        {
                            "campaign_id": campaign.id,
                            "finding_id": finding.id,
                            "error": str(err),
                        },
                    )

            if not report_objects:
                raise CampaignConversionError("no finding could be converted")

            report = Report(
                name=f"Darkmoon pentest — {host} ({campaign.id})",
                publication_date=published,
                description=self._build_campaign_description(bundle),
                report_types=[ReportType.THREAT_REPORT],
                objects=report_objects,
                labels=["darkmoon", "pentest"],
                author=self.author,
                markings=[self.tlp_marking],
                created=published,
            )
            return [report, *report_objects]
        except CampaignConversionError:
            raise
        except (
            Exception
        ) as err:  # noqa: BLE001 - normalize into a single exception type
            raise CampaignConversionError(str(err)) from err

    def _convert_finding(self, finding: DarkmoonFinding) -> list[BaseIdentifiedObject]:
        """Convert a single finding into a vulnerability, a note and optional ATT&CK objects."""
        try:
            vulnerability = self._build_vulnerability(finding)
            note = self._build_note(finding, vulnerability)
            objects: list[BaseIdentifiedObject] = [vulnerability, note]

            if (
                self.settings.darkmoon.import_attack_patterns
                and finding.mitre_attack_id
            ):
                attack_pattern = AttackPattern(
                    name=finding.mitre_attack_name or finding.mitre_attack_id,
                    mitre_id=finding.mitre_attack_id,
                    external_references=[
                        self._mitre_reference(finding.mitre_attack_id)
                    ],
                    author=self.author,
                    markings=[self.tlp_marking],
                )
                relationship = Relationship(
                    type=RelationshipType.RELATED_TO,
                    source=vulnerability,
                    target=attack_pattern,
                    author=self.author,
                    markings=[self.tlp_marking],
                )
                objects.extend([attack_pattern, relationship])

            return objects
        except (
            Exception
        ) as err:  # noqa: BLE001 - normalize into a single exception type
            raise FindingConversionError(str(err)) from err

    def _build_vulnerability(self, finding: DarkmoonFinding) -> Vulnerability:
        """Map a finding to a STIX Vulnerability."""
        severity = (finding.severity or "info").strip().lower()
        cve = finding.cve.strip().upper() if finding.cve else None
        is_cve = bool(cve and _CVE_RE.match(cve))

        name = cve if is_cve else finding.title
        aliases = [finding.title] if is_cve else None

        if finding.cvss_score:
            score = max(0, min(100, int(round(finding.cvss_score * 10))))
        else:
            score = _SEVERITY_TO_SCORE.get(severity)

        description_parts = []
        if finding.description:
            description_parts.append(finding.description)
        if finding.category:
            description_parts.append(f"Category: {finding.category}")
        if finding.endpoint:
            description_parts.append(f"Affected endpoint: {finding.endpoint}")
        description = "\n\n".join(description_parts) or None

        cwe_ids = (
            sorted(
                {
                    match.upper()
                    for text in (finding.category, finding.description, finding.title)
                    if text
                    for match in _CWE_RE.findall(text)
                }
            )
            or None
        )

        labels = [
            label
            for label in (
                "darkmoon",
                f"severity:{severity}",
                f"status:{(finding.status or 'unconfirmed').lower()}",
                f"category:{finding.category}" if finding.category else None,
            )
            if label
        ]

        return Vulnerability(
            name=name,
            description=description,
            aliases=aliases,
            cwe_ids=cwe_ids,
            score=score,
            cvss_v3_base_score=finding.cvss_score or None,
            cvss_v3_vector_string=finding.cvss_vector or None,
            cvss_v3_base_severity=_SEVERITY_TO_CVSS_SEVERITY.get(severity),
            labels=labels,
            external_references=self._vulnerability_references(finding, cve, is_cve),
            author=self.author,
            markings=[self.tlp_marking],
            created=parse_darkmoon_datetime(finding.discovered_at),
        )

    def _vulnerability_references(
        self, finding: DarkmoonFinding, cve: str | None, is_cve: bool
    ) -> list[ExternalReference]:
        references: list[ExternalReference] = []
        if is_cve and cve:
            references.append(
                ExternalReference(
                    source_name="cve",
                    external_id=cve,
                    url=f"https://www.cve.org/CVERecord?id={cve}",
                )
            )
        if finding.mitre_attack_id:
            references.append(self._mitre_reference(finding.mitre_attack_id))
        if finding.iso27001_control:
            references.append(
                ExternalReference(
                    source_name="ISO 27001",
                    external_id=finding.iso27001_control,
                )
            )
        if finding.id:
            references.append(
                ExternalReference(
                    source_name="Darkmoon",
                    external_id=finding.id,
                    description="Darkmoon finding identifier"
                    + (
                        f" (agent: {finding.discovered_by_agent})"
                        if finding.discovered_by_agent
                        else ""
                    ),
                )
            )
        return references

    @staticmethod
    def _mitre_reference(technique_id: str) -> ExternalReference:
        technique = technique_id.strip().upper()
        url_path = technique.replace(".", "/")
        return ExternalReference(
            source_name="mitre-attack",
            external_id=technique,
            url=f"https://attack.mitre.org/techniques/{url_path}",
        )

    def _build_note(
        self, finding: DarkmoonFinding, vulnerability: Vulnerability
    ) -> Note:
        """Build the evidence note attached to the vulnerability."""
        severity = (finding.severity or "info").strip().lower()
        status = (finding.status or "unconfirmed").strip().lower()
        lines: list[str] = []

        meta: list[str] = []
        if finding.category:
            meta.append(f"- **Category:** {finding.category}")
        meta.append(f"- **Severity:** {severity}")
        meta.append(f"- **Status:** {status}")
        if finding.cvss_score:
            meta.append(f"- **CVSS score:** {finding.cvss_score}")
        if finding.cvss_vector:
            meta.append(f"- **CVSS vector:** `{finding.cvss_vector}`")
        if finding.cve:
            meta.append(f"- **CVE:** {finding.cve}")
        if finding.mitre_attack_id:
            mitre = finding.mitre_attack_id
            if finding.mitre_attack_name:
                mitre += f" — {finding.mitre_attack_name}"
            meta.append(f"- **MITRE ATT&CK:** {mitre}")
        if finding.endpoint:
            meta.append(f"- **Endpoint:** {finding.endpoint}")
        if finding.plugin_or_component:
            meta.append(f"- **Component:** {finding.plugin_or_component}")
        if finding.discovered_by_agent:
            meta.append(f"- **Discovered by agent:** {finding.discovered_by_agent}")
        if finding.discovered_at:
            meta.append(f"- **Discovered at:** {finding.discovered_at}")
        lines.extend(meta)

        evidence = finding.evidence
        if finding.description:
            lines.append("\n### Description\n")
            lines.append(finding.description)
        if evidence.explanation:
            lines.append("\n### Technical analysis\n")
            lines.append(evidence.explanation)
        if evidence.commands:
            lines.append("\n### Reproduction commands\n")
            lines.append("```bash")
            lines.extend(evidence.commands)
            lines.append("```")
        if evidence.raw_request:
            lines.append("\n### Raw request\n")
            lines.append("```http")
            lines.append(evidence.raw_request)
            lines.append("```")
        if evidence.raw_response:
            lines.append("\n### Raw response\n")
            lines.append("```http")
            lines.append(evidence.raw_response)
            lines.append("```")
        if evidence.logs:
            lines.append("\n### Evidence logs\n")
            lines.append("```")
            lines.extend(evidence.logs)
            lines.append("```")
        if finding.remediation:
            lines.append("\n### Remediation\n")
            lines.append(finding.remediation)

        content = "\n".join(lines).strip() or "No evidence recorded for this finding."

        return Note(
            abstract=f"{finding.title} — {severity}/{status}",
            content=content,
            note_types=[NoteType.ANALYSIS],
            authors=[self.author.name],
            objects=[vulnerability],
            labels=["darkmoon", "evidence"],
            author=self.author,
            markings=[self.tlp_marking],
            created=parse_darkmoon_datetime(finding.discovered_at),
        )

    @staticmethod
    def _build_campaign_description(bundle: CampaignBundle) -> str | None:
        campaign = bundle.campaign
        parts: list[str] = []
        if campaign.executive_summary:
            parts.append(campaign.executive_summary)
        details: list[str] = []
        if campaign.methodology:
            details.append(f"- **Methodology:** {campaign.methodology}")
        if campaign.overall_risk:
            details.append(f"- **Overall risk:** {campaign.overall_risk}")
        if campaign.status:
            details.append(f"- **Status:** {campaign.status}")
        stats = campaign.stats or {}
        if stats:
            summary = ", ".join(
                f"{key}: {stats[key]}"
                for key in (
                    "total_findings",
                    "critical",
                    "high",
                    "medium",
                    "low",
                    "info",
                    "exploited",
                    "confirmed",
                )
                if key in stats
            )
            if summary:
                details.append(f"- **Findings:** {summary}")
        details.append(
            "- **Source:** Darkmoon OSS campaign findings store "
            "(https://github.com/ASCIT31/Dark-Moon)"
        )
        if details:
            parts.append("\n".join(details))
        return "\n\n".join(parts) or None

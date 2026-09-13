import datetime
from typing import Any
from unicodedata import category

from censys_enrichmentapis.builders.base import AreaStixBuilder
from censys_platform import HostEnrichmentService, Reputation, ReputationEvidenceFeature
from connectors_sdk.models import (
    AttackPattern,
    ExternalReference,
    Malware,
    Note,
    Reference,
    Relationship,
    Software,
    Vulnerability,
)
from connectors_sdk.models.enums import (
    CvssSeverity,
    MalwareType,
    NoteType,
    RelationshipType,
)


class ServiceStixBuilder(AreaStixBuilder):
    def add_software(
        self,
        observable: Reference,
        name: str | None,
        vendor: str | None,
        cpe: str | None,
        version: str | None = None,
    ) -> Software | None:
        if not name:
            return None

        software = Software(
            name=name,
            vendor=vendor,
            cpe=cpe,
            version=version,
            **self.common_props,
        )
        self.bundle.extend(
            [
                software,
                Relationship(
                    source=observable,
                    target=software,
                    type=RelationshipType.RELATED_TO,
                    **self.common_props,
                ),
            ]
        )
        return software

    def add_vulnerability(
        self, software: Software, vulnerability: object
    ) -> Vulnerability | None:
        identifier = self._get_value(vulnerability, "id") or self._get_value(
            vulnerability, "name"
        )
        if not isinstance(identifier, str) or not identifier.startswith("CVE-"):
            return None

        metrics = self._get_value(vulnerability, "metrics") or {}
        cvss = self._get_value(metrics, "cvss_v31") or {}
        epss = self._get_value(metrics, "epss") or {}
        components = self._get_value(cvss, "components") or {}
        severity = self._get_value(vulnerability, "severity")

        vulnerability_entity = Vulnerability(
            name=identifier,
            cwe_ids=self._string_values(self._get_value(vulnerability, "cwes")),
            epss_score=self._get_value(epss, "score"),
            epss_percentile=self._get_value(epss, "percentile"),
            is_cisa_kev=bool(self._get_value(vulnerability, "kev")),
            cvss_v3_vector_string=self._get_value(cvss, "vector"),
            cvss_v3_base_score=self._get_value(cvss, "score"),
            cvss_v3_base_severity=self._cvss_severity(severity),
            cvss_v3_attack_vector=self._get_value(components, "attack_vector"),
            cvss_v3_attack_complexity=self._get_value(
                components, "attack_complexity"
            ),
            cvss_v3_privileges_required=self._get_value(
                components, "privileges_required"
            ),
            cvss_v3_user_interaction=self._get_value(
                components, "user_interaction"
            ),
            cvss_v3_scope=self._get_value(components, "scope"),
            cvss_v3_confidentiality_impact=self._get_value(
                components, "confidentiality"
            ),
            cvss_v3_integrity_impact=self._get_value(components, "integrity"),
            cvss_v3_availability_impact=self._get_value(
                components, "availability"
            ),
            external_references=[
                ExternalReference(
                    source_name="CVE",
                    external_id=identifier,
                    url=f"https://nvd.nist.gov/vuln/detail/{identifier}",
                )
            ],
            **self.common_props,
        )
        self.bundle.extend(
            [
                vulnerability_entity,
                Relationship(
                    source=software,
                    target=vulnerability_entity,
                    type=RelationshipType.HAS,
                    **self.common_props,
                ),
            ]
        )
        return vulnerability_entity

    def add_service_vulnerabilities(
        self,
        observable: Reference,
        services: list[HostEnrichmentService] | None,
    ) -> None:
        """Create the IP -> Software -> Vulnerability path for each service."""
        for service in services or []:
            software_by_cpe: dict[str, Software] = {}
            for software_data in self._get_value(service, "software") or []:
                software = self.add_software(
                    observable=observable,
                    name=self._get_value(software_data, "product"),
                    vendor=self._get_value(software_data, "vendor"),
                    cpe=self._get_value(software_data, "cpe"),
                    version=self._get_value(software_data, "version"),
                )
                cpe = self._get_value(software_data, "cpe")
                if software and isinstance(cpe, str):
                    software_by_cpe[cpe] = software

            for vulnerability in self._get_value(service, "vulns") or []:
                for cpe in self._vulnerability_cpes(vulnerability):
                    software = software_by_cpe.get(cpe)
                    if software is None:
                        software = self._add_software_from_cpe(observable, cpe)
                        if software is not None:
                            software_by_cpe[cpe] = software
                    if software is not None:
                        self.add_vulnerability(software, vulnerability)

    def _add_software_from_cpe(
        self, observable: Reference, cpe: str
    ) -> Software | None:
        parts = cpe.split(":")
        if len(parts) < 6 or parts[0:2] != ["cpe", "2.3"]:
            return None
        return self.add_software(
            observable=observable,
            vendor=parts[3],
            name=parts[4],
            version=parts[5] if parts[5] != "*" else None,
            cpe=cpe,
        )

    def _vulnerability_cpes(self, vulnerability: object) -> set[str]:
        cpes = set()
        for evidence in self._get_value(vulnerability, "evidence") or []:
            cpe = self._get_value(evidence, "found_value")
            if isinstance(cpe, str) and cpe.startswith("cpe:2.3:"):
                cpes.add(cpe)
        return cpes

    def add_note(
        self,
        observable: Reference,
        content: str | None,
        publication_date: str | None,
        port: int | None,
    ) -> None:
        if not (content and publication_date and port):
            return

        self.bundle.append(
            Note(
                abstract=f"Service banner on port {port}",
                content=content,
                publication_date=datetime.datetime.fromisoformat(publication_date),
                authors=[self._context.author.name],
                objects=[observable],
                **self.common_props,
            )
        )

    def add_reputation_note(
        self, observable: Reference, reputation: Reputation | None
    ) -> None:
        if not reputation:
            return

        score_label = reputation.label
        content_parts = []
        if reputation.score is not None:
            value = int(reputation.score * 100)
            content_parts.append(f"- Score: {value}")
        if score_label:
            content_parts.append(f"- Label: {score_label}")
        if reputation.model_version:
            content_parts.append(f"- Model version: {reputation.model_version}")

        self._add_reputation_evidence_features(reputation, content_parts)
        if not content_parts:
            return

        self.bundle.append(
            Note(
                abstract="Censys host reputation",
                content="\n".join(content_parts),
                note_types=[NoteType.EXTERNAL],
                labels=[score_label] if score_label else None,
                authors=[self._context.author.name],
                objects=[observable],
                **self.common_props,
            )
        )

    def _add_reputation_evidence_features(
        self, reputation: Reputation, content_parts: list[str]
    ) -> None:
        if not reputation.evidence or not isinstance(reputation.evidence, list):
            return

        content_parts.append("\n**Evidence Features:**")
        rows = [
            "| Feature | Value | Contribution | Category |",
            "|---|---:|---:|---|",
        ]
        for evidence in reputation.evidence:
            if evidence.feature:
                feature = evidence.feature
                name = (str(feature.name)) if feature.name else "Unknown" # Access the feature name to ensure it is loaded
                value = (str(feature.value)) if feature.value else "Unknown"  # Access the feature value to ensure it is loaded
                category = (str(feature.category)) if feature.category else "Unknown"  # Access the feature category to ensure it is loaded
                contribution = "Unknown"
                if (feature.contribution is not None):
                        if isinstance(feature.contribution, (int, float)):
                            contribution = f"{feature.contribution:+.2f}%"
                        else:
                            contribution = str(feature.contribution)
                rows.append(
                    f"| {name} | {value} | {contribution} | {category} |"
                )

        if len(rows) > 2:
            content_parts.append("\n".join(rows))

    @staticmethod
    def _markdown_cell(value: Any) -> str:
        """Make a value safe for use inside a Markdown table cell."""
        if value is None:
            return "—"

        if isinstance(value, bool):
            value = str(value).lower()

        return (
            str(value)
            .replace("|", r"\|")
            .replace("\n", "<br>")
    )


    def _build_service_content(self, service: HostEnrichmentService) -> str:
        content_parts = []
        if service.protocol:
            content_parts.append(f"- Protocol: {service.protocol}")
        if service.scan_time:
            content_parts.append(f"- Scan Time: {service.scan_time}")

        labels = [label.value for label in service.labels or [] if label.value]
        if labels:
            if content_parts:
                content_parts.append("")
            content_parts.append("- Labels")
            content_parts.extend(f"  - {label}" for label in labels)

        threats_info = []
        for threat in service.threats or []:
            threat_details = []
            if self._get_value(threat, "name"):
                threat_details.append(self._get_value(threat, "name"))
            if self._get_value(threat, "severity"):
                threat_details.append(
                    f"Severity: {self._get_value(threat, 'severity')}"
                )
            if threat_details:
                threats_info.append("- " + " | ".join(threat_details))

        if threats_info:
            if content_parts:
                content_parts.append("")
            content_parts.append("### Threats")
            content_parts.extend(threats_info)
        return "\n".join(content_parts)

    def add_service_notes(
        self,
        observable: Reference,
        services: list[HostEnrichmentService] | None,
    ) -> None:
        for service in services or []:
            if not (service.scan_time and service.port):
                continue

            content = self._build_service_content(service)
            if not content:
                continue
            self.bundle.append(
                Note(
                    abstract=(
                        f"Service information on port {service.port} "
                        f"({service.protocol or 'Unknown'})"
                    ),
                    content=content,
                    note_types=[NoteType.EXTERNAL],
                    publication_date=datetime.datetime.fromisoformat(
                        service.scan_time
                    ),
                    authors=[self._context.author.name],
                    objects=[observable],
                    **self.common_props,
                )
            )

    def add_service_threats(
        self,
        observable: Reference,
        services: list[HostEnrichmentService] | None,
    ) -> None:
        for service in services or []:
            self._add_threats(
                observable=observable,
                threats=self._get_value(service, "threats"),
                port=self._get_value(service, "port"),
                protocol=self._get_value(service, "protocol"),
            )

    def _add_threats(
        self,
        observable: Reference,
        threats: object | None,
        port: int | None,
        protocol: str | None,
    ) -> None:
        for threat in threats or []:
            threat_name = self._get_value(threat, "name")
            threat_id = self._get_value(threat, "id")
            if not threat_name or not threat_id:
                continue

            malware = self._add_threat_malware(threat)
            if malware:
                self.bundle.extend(
                    [
                        malware,
                        Relationship(
                            source=observable,
                            target=malware,
                            type=RelationshipType.RELATED_TO,
                            **self.common_props,
                        ),
                    ]
                )

            for tactic in self._get_value(threat, "tactic") or []:
                attack_pattern = self._add_threat_attack_pattern(tactic)
                if attack_pattern:
                    self.bundle.extend(
                        [
                            attack_pattern,
                            Relationship(
                                source=observable,
                                target=attack_pattern,
                                type=RelationshipType.RELATED_TO,
                                **self.common_props,
                            ),
                        ]
                    )

            threat_note = self._build_threat_note(
                observable=observable,
                threat=threat,
                port=port,
                protocol=protocol,
            )
            if threat_note:
                self.bundle.append(threat_note)

    def _add_threat_malware(self, threat: object) -> Malware | None:
        malware_data = self._get_value(threat, "malware")
        if not isinstance(malware_data, dict):
            return None
        primary_name = malware_data.get("primary_name")
        if not primary_name:
            return None

        malware_type_enums = []
        for threat_type in self._get_value(threat, "type") or []:
            if isinstance(threat_type, str):
                try:
                    normalized = threat_type.lower().replace("_", "-")
                    malware_type_enums.append(MalwareType(normalized))
                except (ValueError, KeyError):
                    pass

        return Malware(
            name=primary_name,
            is_family=False,
            aliases=malware_data.get("all_names", []),
            types=malware_type_enums or None,
            description=(
                f"{self._get_value(threat, 'id')}: "
                f"{self._get_value(threat, 'name')}"
            ),
            **self.common_props,
        )

    def _add_threat_attack_pattern(self, tactic: str) -> AttackPattern | None:
        if not isinstance(tactic, str) or not tactic.strip():
            return None

        tactic_name = tactic.upper().replace("_", " ")
        mitre_id = self._get_mitre_tactic_id(tactic)
        external_refs = []
        if mitre_id:
            external_refs.append(
                ExternalReference(
                    source_name="mitre-attack",
                    external_id=mitre_id,
                    url=f"https://attack.mitre.org/tactics/{mitre_id}/",
                )
            )
        return AttackPattern(
            name=tactic_name,
            external_references=external_refs or None,
            **self.common_props,
        )

    def _build_threat_note(
        self,
        observable: Reference,
        threat: object,
        port: int | None,
        protocol: str | None,
    ) -> Note | None:
        threat_name = self._get_value(threat, "name")
        threat_id = self._get_value(threat, "id")
        if not threat_name:
            return None

        rows = [
            "| Key | Value |",
            "|---|---|",
            f"| Threat ID | {self._markdown_cell(threat_id)} |",
            f"| Name | {self._markdown_cell(threat_name)} |",
        ]

        threat_types = self._get_value(threat, "type") or []
        types_str = ", ".join(
            item.replace("_", " ")
            for item in threat_types
            if isinstance(item, str)
        )
        if types_str:
            rows.append(f"| Threat Types | {self._markdown_cell(types_str)} |")

        tactics = self._get_value(threat, "tactic") or []
        tactics_str = ", ".join(
            item.replace("_", " ").title()
            for item in tactics
            if isinstance(item, str)
        )
        if tactics_str:
            rows.append(f"| Tactics | {self._markdown_cell(tactics_str)} |")

        content_parts = ["\n".join(rows)]

        if evidence := self._get_value(threat, "evidence"):
            if isinstance(evidence, list) and evidence:
                content_parts.append("\n**Evidence:**")
                for item in evidence:
                    if isinstance(item, dict):
                        data_path = item.get("data_path", "unknown")
                        found_value = item.get("found_value", "")
                        content_parts.append(f"- {data_path}: {found_value}")

        if malware_data := self._get_value(threat, "malware"):
            if isinstance(malware_data, dict) and malware_data.get("primary_name"):
                content_parts.append(
                    f"\n- **Malware:** {malware_data['primary_name']}"
                )
                if aliases := malware_data.get("all_names"):
                    content_parts.append(f"- **Aliases:** {', '.join(aliases)}")
                if updated := malware_data.get("last_updated_at"):
                    content_parts.append(f"- **Last Updated:** {updated}")

        return Note(
            abstract=f"Service Threat: {threat_name}"
            + (f" (Port {port}/{protocol})" if port and protocol else ""),
            content="\n".join(content_parts),
            note_types=[NoteType.EXTERNAL],
            labels=[
                item.lower().replace("_", "-")
                for item in threat_types
                if isinstance(item, str)
            ]
            or None,
            authors=[self._context.author.name],
            objects=[observable],
            **self.common_props,
        )

    @staticmethod
    def _get_mitre_tactic_id(tactic: str) -> str | None:
        mitre_map = {
            "persistence": "TA0003",
            "execution": "TA0002",
            "discovery": "TA0007",
            "lateral_movement": "TA0008",
            "collection": "TA0009",
            "exfiltration": "TA0010",
            "command_and_control": "TA0011",
            "impact": "TA0040",
            "initial_access": "TA0001",
            "privilege_escalation": "TA0004",
            "defense_evasion": "TA0005",
            "credential_access": "TA0006",
        }
        return mitre_map.get(tactic.lower())

    @staticmethod
    def _get_value(value: object, field: str) -> object | None:
        if isinstance(value, dict):
            return value.get(field)
        return getattr(value, field, None)

    @staticmethod
    def _string_values(value: object | None) -> list[str] | None:
        if not isinstance(value, list):
            return None
        values = [item for item in value if isinstance(item, str)]
        return values or None

    @staticmethod
    def _cvss_severity(value: object | None) -> CvssSeverity | None:
        if not isinstance(value, str):
            return None
        try:
            return CvssSeverity(value.upper())
        except ValueError:
            return None

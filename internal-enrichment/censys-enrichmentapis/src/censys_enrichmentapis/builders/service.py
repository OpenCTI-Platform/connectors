from collections.abc import Sequence
from typing import Any
from urllib.parse import quote

from censys_enrichmentapis.builders.base import AreaStixBuilder, StixBuildContext
from censys_platform import HostEnrichmentService, Reputation, Service, Webproperty
from connectors_sdk.models import (
    AttackPattern,
    BaseIdentifiedEntity,
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

HostService = HostEnrichmentService | Service

# ``MalwareType`` is a permissive STIX open-vocabulary enum: constructing it
# from a value outside this set still succeeds, but emits a ``UserWarning``
# (it never raises). Checking membership here keeps the intent of only
# tagging ``Malware.types`` with recognized STIX malware types, without
# triggering that warning for every Censys threat ``type`` value (e.g.
# ``"proxy"``) that isn't one.
_KNOWN_MALWARE_TYPES = frozenset(member.value for member in MalwareType)


class ServiceStixBuilder(AreaStixBuilder):
    """Build the STIX objects derived from Censys services and web properties.

    Censys reports the same software, CVE, malware or tactic on several
    services (or several threats) of one host. Every entity created here is
    therefore cached by its natural key for the duration of a conversion so
    the bundle carries one object and one relationship per distinct pair
    instead of one copy per occurrence.
    """

    def __init__(self, context: StixBuildContext) -> None:
        super().__init__(context)
        self._software_by_key: dict[tuple[str | None, ...], Software] = {}
        self._vulnerabilities_by_identifier: dict[str, Vulnerability] = {}
        self._malware_by_name: dict[str, Malware] = {}
        self._attack_patterns_by_tactic: dict[str, AttackPattern] = {}
        self._relationships: set[tuple[str, str, str]] = set()

    def reset(self) -> None:
        self._software_by_key.clear()
        self._vulnerabilities_by_identifier.clear()
        self._malware_by_name.clear()
        self._attack_patterns_by_tactic.clear()
        self._relationships.clear()

    def _add_unique_relationship(
        self,
        source: BaseIdentifiedEntity | Reference,
        target: BaseIdentifiedEntity | Reference,
        relationship_type: RelationshipType,
    ) -> None:
        relationship_key = (str(source.id), str(target.id), relationship_type.value)
        if relationship_key in self._relationships:
            return
        self._relationships.add(relationship_key)
        self.bundle.append(
            Relationship(
                source=source,
                target=target,
                type=relationship_type,
                **self.common_props,
            )
        )

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

        software_key = (name, vendor, cpe, version)
        software = self._software_by_key.get(software_key)
        if software is None:
            software = Software(
                name=name,
                vendor=vendor,
                cpe=cpe,
                version=version,
                **self.common_props,
            )
            self._software_by_key[software_key] = software
            self.bundle.append(software)
        self._add_unique_relationship(observable, software, RelationshipType.RELATED_TO)
        return software

    def add_vulnerability(
        self, software: Software, vulnerability: object
    ) -> Vulnerability | None:
        identifier = self._get_value(vulnerability, "id") or self._get_value(
            vulnerability, "name"
        )
        if not isinstance(identifier, str) or not identifier.startswith("CVE-"):
            return None

        vulnerability_entity = self._vulnerabilities_by_identifier.get(identifier)
        if vulnerability_entity is None:
            vulnerability_entity = self._create_vulnerability(
                identifier=identifier,
                vulnerability=vulnerability,
            )
            self._vulnerabilities_by_identifier[identifier] = vulnerability_entity
            self.bundle.append(vulnerability_entity)

        self._add_unique_relationship(
            software, vulnerability_entity, RelationshipType.HAS
        )
        return vulnerability_entity

    def _create_vulnerability(
        self, identifier: str, vulnerability: object
    ) -> Vulnerability:
        metrics = self._get_value(vulnerability, "metrics") or {}
        cvss = self._get_value(metrics, "cvss_v31") or {}
        epss = self._get_value(metrics, "epss") or {}
        components = self._get_value(cvss, "components") or {}
        severity = self._get_value(vulnerability, "severity")

        return Vulnerability(
            name=identifier,
            cwe_ids=self._cwe_ids(self._get_value(vulnerability, "cwes")),
            epss_score=self._get_value(epss, "score"),
            epss_percentile=self._get_value(epss, "percentile"),
            is_cisa_kev=bool(self._get_value(vulnerability, "kev")),
            cvss_v3_vector_string=self._get_value(cvss, "vector"),
            cvss_v3_base_score=self._get_value(cvss, "score"),
            cvss_v3_base_severity=self._cvss_severity(severity),
            cvss_v3_attack_vector=self._get_value(components, "attack_vector"),
            cvss_v3_attack_complexity=self._get_value(components, "attack_complexity"),
            cvss_v3_privileges_required=self._get_value(
                components, "privileges_required"
            ),
            cvss_v3_user_interaction=self._get_value(components, "user_interaction"),
            cvss_v3_scope=self._get_value(components, "scope"),
            cvss_v3_confidentiality_impact=self._get_value(
                components, "confidentiality"
            ),
            cvss_v3_integrity_impact=self._get_value(components, "integrity"),
            cvss_v3_availability_impact=self._get_value(components, "availability"),
            external_references=[
                ExternalReference(
                    source_name="CVE",
                    external_id=identifier,
                    url=f"https://nvd.nist.gov/vuln/detail/{identifier}",
                )
            ],
            **self.common_props,
        )

    def add_service_vulnerabilities(
        self,
        observable: Reference,
        services: Sequence[HostService] | None,
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

    def add_web_property_note(
        self,
        observable: Reference,
        web_property: Webproperty,
        labels: list[str] | None = None,
    ) -> None:
        """Add the selected Censys web-property fields as a Markdown table."""
        rows = ["| Key | Value |", "|---|---|"]

        def add_row(key: str, value: object | None) -> None:
            if value is None or value == "":
                return
            rows.append(
                f"| {self._markdown_cell(key)} | "
                f"{self._markdown_inline_code(value)} |"
            )

        hostname_value = self._get_value(web_property, "hostname")
        port_value = self._get_value(web_property, "port")
        add_row("web.hostname", hostname_value)
        add_row("web.port", port_value)
        for endpoint in self._get_value(web_property, "endpoints") or []:
            add_row(
                "web.endpoints.endpoint_type",
                self._get_value(endpoint, "endpoint_type"),
            )
        add_row("web.scan_time", self._get_value(web_property, "scan_time"))
        for label in self._get_value(web_property, "labels") or []:
            add_row("web.labels.value", self._get_value(label, "value"))
        for threat in self._get_value(web_property, "threats") or []:
            add_row("web.threats.name", self._get_value(threat, "name"))
        for vulnerability in self._get_value(web_property, "vulns") or []:
            add_row("web.vulns.name", self._get_value(vulnerability, "name"))
        for software in self._get_value(web_property, "software") or []:
            add_row("web.software.vendor", self._get_value(software, "vendor"))
            add_row("web.software.product", self._get_value(software, "product"))
            add_row("web.software.version", self._get_value(software, "version"))

        certificate = self._get_value(web_property, "cert")
        add_row(
            "web.cert.fingerprint_sha256",
            self._get_value(certificate, "fingerprint_sha256"),
        )
        parsed = self._get_value(certificate, "parsed")
        add_row(
            "web.cert.parsed.subject_dn",
            self._get_value(parsed, "subject_dn"),
        )
        add_row(
            "web.cert.parsed.issuer_dn",
            self._get_value(parsed, "issuer_dn"),
        )
        subject = self._get_value(parsed, "subject")
        for common_name in self._get_value(subject, "common_name") or []:
            add_row("web.cert.parsed.subject.common_name", common_name)
        validity_period = self._get_value(parsed, "validity_period")
        add_row(
            "web.cert.parsed.validity_period.not_before",
            self._get_value(validity_period, "not_before"),
        )
        add_row(
            "web.cert.parsed.validity_period.not_after",
            self._get_value(validity_period, "not_after"),
        )
        signature = self._get_value(parsed, "signature")
        add_row(
            "web.cert.parsed.signature.self_signed",
            self._get_value(signature, "self_signed"),
        )
        for name in self._get_value(certificate, "names") or []:
            add_row("web.cert.names", name)

        if len(rows) == 2:
            return

        hostname = hostname_value or "unknown host"
        port = port_value or "unknown port"
        title_hostname = self._markdown_inline_code(hostname)
        content_parts = []
        if isinstance(hostname_value, str) and isinstance(port_value, int):
            webproperty_id = quote(f"{hostname_value}:{port_value}", safe=":")
            censys_url = f"https://platform.censys.io/web/{webproperty_id}"
            content_parts.append(f"[{censys_url}]({censys_url})")
        content_parts.append("\n".join(rows))

        self.bundle.append(
            Note(
                abstract=f"Censys web property {title_hostname}:{port}",
                content="\n\n".join(content_parts),
                note_types=[NoteType.EXTERNAL],
                labels=labels or None,
                authors=[self._context.author.name],
                objects=[observable],
                **self.common_props,
            )
        )

    def add_reputation_note(
        self,
        observable: Reference,
        observable_value: str,
        reputation: Reputation | None,
    ) -> None:
        if not reputation:
            return

        content_parts = []
        censys_url = (
            "https://platform.censys.io/hosts/" f"{quote(observable_value, safe='')}"
        )
        content_parts.append(
            f"\n[View this host {observable_value} on Censys Platform]({censys_url})\n\n"
        )

        score_label = reputation.label
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
                name = str(feature.name) if feature.name else "Unknown"
                value = str(feature.value) if feature.value else "Unknown"
                category = str(feature.category) if feature.category else "Unknown"
                contribution = "Unknown"
                if feature.contribution is not None:
                    if isinstance(feature.contribution, (int, float)):
                        contribution = f"{feature.contribution:+.2f}%"
                    else:
                        contribution = str(feature.contribution)
                rows.append(f"| {name} | {value} | {contribution} | {category} |")

        if len(rows) > 2:
            content_parts.append("\n".join(rows))

    def _markdown_cell(self, value: Any) -> str:
        """Make a value safe for use inside a Markdown table cell."""
        if value is None:
            return "—"

        if isinstance(value, bool):
            value = str(value).lower()

        return str(value).replace("|", r"\|").replace("\n", "<br>")

    def _markdown_inline_code(self, value: Any) -> str:
        """Render a table value as non-linkable Markdown inline code."""
        text = self._markdown_cell(value)
        delimiter = "`"
        while delimiter in text:
            delimiter += "`"
        return f"{delimiter}{text}{delimiter}"

    def _build_service_content(self, service: HostService) -> str:
        protocol = self._get_value(service, "protocol")
        scan_time = self._get_value(service, "scan_time")
        rows = [
            "| Key | Value |",
            "|---|---|",
        ]
        if protocol:
            rows.append(f"| Protocol | {self._markdown_cell(protocol)} |")
        if scan_time:
            rows.append(f"| Last Scan Time | {self._markdown_cell(scan_time)} |")

        labels = [
            label
            for label in self._get_value(service, "labels") or []
            if self._get_value(label, "value")
        ]
        for label_number, label in enumerate(labels, start=1):
            label_key = f"Label {label_number}"
            rows.append(
                f"| {label_key} | "
                f"{self._markdown_cell(self._get_value(label, 'value'))} |"
            )
            for evidence in self._get_value(label, "evidence") or []:
                data_path = self._get_value(evidence, "data_path")
                found_value = self._get_value(evidence, "found_value")
                evidence_key = f"{label_key} Evidence"
                if data_path:
                    evidence_key += f" — {data_path}"
                rows.append(
                    f"| {self._markdown_cell(evidence_key)} | "
                    f"{self._markdown_cell(found_value)} |"
                )

        content_parts = ["\n".join(rows)]

        threats_info = []
        for threat in self._get_value(service, "threats") or []:
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
        services: Sequence[HostService] | None,
    ) -> None:
        for service in services or []:
            scan_time = self._get_value(service, "scan_time")
            port = self._get_value(service, "port")
            protocol = self._get_value(service, "protocol")
            if not (scan_time and port):
                continue

            content = self._build_service_content(service)
            if not content:
                continue
            self.bundle.append(
                Note(
                    abstract=(
                        f"Service information on port {port} "
                        f"({protocol or 'Unknown'})"
                    ),
                    content=content,
                    note_types=[NoteType.EXTERNAL],
                    authors=[self._context.author.name],
                    objects=[observable],
                    **self.common_props,
                )
            )

    def add_service_threats(
        self,
        observable: Reference,
        observable_value: str,
        services: Sequence[HostService] | None,
    ) -> None:
        for service in services or []:
            self._add_threats(
                observable=observable,
                observable_value=observable_value,
                threats=self._get_value(service, "threats"),
                port=self._get_value(service, "port"),
                protocol=self._get_value(service, "protocol"),
            )

    def _add_threats(
        self,
        observable: Reference,
        observable_value: str,
        threats: object | None,
        port: int | None,
        protocol: str | None,
    ) -> None:
        for threat in threats or []:
            threat_name = self._get_value(threat, "name")
            if not threat_name:
                continue

            malware = self._add_threat_malware(threat)
            if malware:
                self._add_unique_relationship(
                    observable, malware, RelationshipType.RELATED_TO
                )

            for tactic in self._get_value(threat, "tactic") or []:
                attack_pattern = self._add_threat_attack_pattern(tactic)
                if attack_pattern:
                    self._add_unique_relationship(
                        observable, attack_pattern, RelationshipType.RELATED_TO
                    )

            threat_note = self._build_threat_note(
                observable=observable,
                observable_value=observable_value,
                threat=threat,
                port=port,
                protocol=protocol,
            )
            if threat_note:
                self.bundle.append(threat_note)

    def _add_threat_malware(self, threat: object) -> Malware | None:
        # ``threat.malware`` is a ``ThreatMalware`` model once deserialized by
        # censys-platform and a plain dict in raw payloads; ``_get_value``
        # reads both shapes.
        malware_data = self._get_value(threat, "malware")
        primary_name = self._get_value(malware_data, "primary_name")
        if not isinstance(primary_name, str) or not primary_name:
            return None

        malware = self._malware_by_name.get(primary_name)
        if malware is not None:
            return malware

        malware_type_enums = []
        for threat_type in self._get_value(threat, "type") or []:
            if isinstance(threat_type, str):
                normalized = threat_type.lower().replace("_", "-")
                if normalized in _KNOWN_MALWARE_TYPES:
                    malware_type_enums.append(MalwareType(normalized))

        description_parts = [
            str(part)
            for part in (
                self._get_value(threat, "id"),
                self._get_value(threat, "name"),
            )
            if part
        ]
        malware = Malware(
            name=primary_name,
            is_family=False,
            aliases=self._string_values(self._get_value(malware_data, "all_names")),
            types=malware_type_enums or None,
            description=": ".join(description_parts) or None,
            **self.common_props,
        )
        self._malware_by_name[primary_name] = malware
        self.bundle.append(malware)
        return malware

    def _add_threat_attack_pattern(self, tactic: str) -> AttackPattern | None:
        if not isinstance(tactic, str) or not tactic.strip():
            return None

        tactic_key = tactic.strip().lower()
        attack_pattern = self._attack_patterns_by_tactic.get(tactic_key)
        if attack_pattern is not None:
            return attack_pattern

        tactic_name = tactic_key.upper().replace("_", " ")
        mitre_id = self._get_mitre_tactic_id(tactic_key)
        external_refs = []
        if mitre_id:
            external_refs.append(
                ExternalReference(
                    source_name="mitre-attack",
                    external_id=mitre_id,
                    url=f"https://attack.mitre.org/tactics/{mitre_id}/",
                )
            )
        attack_pattern = AttackPattern(
            name=tactic_name,
            external_references=external_refs or None,
            **self.common_props,
        )
        self._attack_patterns_by_tactic[tactic_key] = attack_pattern
        self.bundle.append(attack_pattern)
        return attack_pattern

    def _build_threat_note(
        self,
        observable: Reference,
        observable_value: str,
        threat: object,
        port: int | None,
        protocol: str | None,
    ) -> Note | None:
        threat_name = self._get_value(threat, "name")
        if not threat_name:
            return None

        censys_url = (
            "https://platform.censys.io/hosts/" f"{quote(observable_value, safe='')}"
        )
        content_parts = [
            f"\n[View this host {observable_value} on Censys Platform]({censys_url})\n\n"
        ]

        rows = [
            "| Key | Value |",
            "|---|---|",
            f"| Name | {self._markdown_cell(threat_name)} |",
        ]

        threat_types = self._get_value(threat, "type") or []
        types_str = ", ".join(
            item.replace("_", " ") for item in threat_types if isinstance(item, str)
        )
        if types_str:
            rows.append(f"| Threat Types | {self._markdown_cell(types_str)} |")

        tactics = self._get_value(threat, "tactic") or []
        tactics_str = ", ".join(
            item.replace("_", " ").title() for item in tactics if isinstance(item, str)
        )
        if tactics_str:
            rows.append(f"| Tactics | {self._markdown_cell(tactics_str)} |")

        content_parts.append("\n".join(rows))

        evidence_rows = [
            "| Key | Value |",
            "|---|---|",
        ]
        if isinstance(evidence := self._get_value(threat, "evidence"), list):
            for item in evidence:
                data_path = self._get_value(item, "data_path")
                found_value = self._get_value(item, "found_value")
                if not data_path or found_value is None or found_value == "":
                    continue
                evidence_rows.append(
                    f"| {self._markdown_cell(data_path)} | "
                    f"{self._markdown_cell(found_value)} |"
                )

        if len(evidence_rows) > 2:
            content_parts.append("\n\n**Evidence:**")
            content_parts.append("\n".join(evidence_rows))

        malware_data = self._get_value(threat, "malware")
        malware_name = self._get_value(malware_data, "primary_name")
        if isinstance(malware_name, str) and malware_name:
            content_parts.append(f"\n- **Malware:** {malware_name}")
            if aliases := self._string_values(
                self._get_value(malware_data, "all_names")
            ):
                content_parts.append(f"- **Aliases:** {', '.join(aliases)}")
            if updated := self._get_value(malware_data, "last_updated_at"):
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

    def _get_mitre_tactic_id(self, tactic: str) -> str | None:
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

    def _get_value(self, value: object, field: str) -> object | None:
        """Read *field* from a dict or an SDK model; ``None`` when absent.

        Unset censys-platform fields hold the ``UNSET`` sentinel, which is
        falsy, so callers can safely chain ``or []`` / ``or {}`` on the result.
        """
        if value is None:
            return None
        if isinstance(value, dict):
            return value.get(field)
        return getattr(value, field, None)

    def _string_values(self, value: object | None) -> list[str] | None:
        if not isinstance(value, list):
            return None
        values = [item for item in value if isinstance(item, str)]
        return values or None

    def _cwe_ids(self, value: object | None) -> list[str] | None:
        """Extract CWE identifiers from Censys ``cwes`` entries.

        Censys returns ``[{"entry": "CWE-79"}, ...]`` (``Cwe`` models or raw
        dicts); plain strings are accepted too.
        """
        if not isinstance(value, list):
            return None
        cwe_ids = []
        for item in value:
            entry = item if isinstance(item, str) else self._get_value(item, "entry")
            if isinstance(entry, str) and entry:
                cwe_ids.append(entry)
        return list(dict.fromkeys(cwe_ids)) or None

    def _cvss_severity(self, value: object | None) -> CvssSeverity | None:
        if not isinstance(value, str):
            return None
        try:
            return CvssSeverity(value.upper())
        except ValueError:
            return None

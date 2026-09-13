import datetime
import ipaddress

from censys_platform import (
    Certificate,
    Coordinates,
    HostDNS,
    HostEnrichmentService,
    Label,
    Reputation,
)
from connectors_sdk.models import (
    AdministrativeArea,
    AttackPattern,
    AutonomousSystem,
    BaseObject,
    City,
    Country,
    ExternalReference,
    Hostname,
    IPV4Address,
    IPV6Address,
    Malware,
    Note,
    Organization,
    OrganizationAuthor,
    Reference,
    Region,
    Relationship,
    Software,
    TLPMarking,
    Vulnerability,
    X509Certificate,
)
from connectors_sdk.models.enums import (
    CvssSeverity,
    HashAlgorithm,
    NoteType,
    RelationshipType,
    TLPLevel,
)


class CensysStixBuilder:
    def __init__(self) -> None:
        self.author = OrganizationAuthor(name="Censys EnrichmentAPIs Connector")
        self.marking = TLPMarking(level=TLPLevel.CLEAR)
        self.common_props = {"author": self.author, "markings": [self.marking]}
        self.bundle: list[BaseObject] = []

    def reset(self) -> None:
        self.bundle = []

    def add_author_and_marking(self) -> None:
        self.bundle.extend(
            [
                self.author,
                self.marking,
            ]
        )

    def add_city(self, observable: Reference, name: str | None) -> None:
        if not name:
            return

        city = City(
            name=name,
            **self.common_props,
        )
        self.bundle.extend(
            [
                city,
                Relationship(
                    source=observable,
                    target=city,
                    type=RelationshipType.LOCATED_AT,
                    **self.common_props,
                ),
            ]
        )

    def add_country(self, observable: Reference, name: str | None) -> Country | None:
        if not name:
            return None

        country = Country(
            name=name,
            **self.common_props,
        )
        self.bundle.extend(
            [
                country,
                Relationship(
                    source=observable,
                    target=country,
                    type=RelationshipType.LOCATED_AT,
                    **self.common_props,
                ),
            ]
        )
        return country

    def add_region(self, observable: Reference, name: str | None) -> None:
        if not name:
            return

        region = Region(
            name=name,
            **self.common_props,
        )
        self.bundle.extend(
            [
                region,
                Relationship(
                    source=observable,
                    target=region,
                    type=RelationshipType.LOCATED_AT,
                    **self.common_props,
                ),
            ]
        )

    def add_administrative_area(
        self,
        observable: Reference,
        name: str | None,
        coordinates: Coordinates | None,
    ) -> None:
        if not name:
            return

        administrative_area = (
            AdministrativeArea(
                name=name,
                latitude=coordinates.latitude,
                longitude=coordinates.longitude,
                **self.common_props,
            )
            if coordinates
            else AdministrativeArea(
                name=name,
                **self.common_props,
            )
        )

        self.bundle.extend(
            [
                administrative_area,
                Relationship(
                    source=observable,
                    target=administrative_area,
                    type=RelationshipType.LOCATED_AT,
                    **self.common_props,
                ),
            ]
        )

    def add_hostnames(self, observable: Reference, dns: HostDNS | None) -> None:
        if not dns:
            return

        for name in dns.names or []:
            host_name = Hostname(
                value=name,
                **self.common_props,
            )
            self.bundle.extend(
                [
                    host_name,
                    Relationship(
                        source=host_name,
                        target=observable,
                        type=RelationshipType.RESOLVES_TO,
                        **self.common_props,
                    ),
                ]
            )

    def add_organization(
        self,
        observable: Reference,
        name: str | None,
    ) -> Organization | None:
        if not name:
            return None

        organization = Organization(
            name=name,
            **self.common_props,
        )
        self.bundle.extend(
            [
                organization,
                Relationship(
                    source=observable,
                    target=organization,
                    type=RelationshipType.RELATED_TO,
                    **self.common_props,
                ),
            ]
        )
        return organization

    def add_autonomous_system(
        self,
        observable: Reference,
        number: int | None,
        name: str | None,
        description: str | None,
    ) -> AutonomousSystem | None:
        if not number:
            return None

        autonomous_system = AutonomousSystem(
            name=name,
            description=description,
            number=number,
            **self.common_props,
        )
        self.bundle.extend(
            [
                autonomous_system,
                Relationship(
                    source=observable,
                    target=autonomous_system,
                    type=RelationshipType.BELONGS_TO,
                    **self.common_props,
                ),
            ]
        )
        return autonomous_system

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
        """Add a Censys service vulnerability and link it to its software.

        Censys returns vulnerabilities below an individual service.  Modelling
        the relation from Software to Vulnerability retains that meaning while
        the existing IP-to-Software relation makes the CVEs discoverable from
        the enriched host observable.
        """
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

    def _add_certificate_parsed_fields(
        self, certificate: X509Certificate, cert: Certificate
    ) -> None:
        certificate.serial_number = cert.parsed.serial_number
        certificate.issuer = cert.parsed.issuer_dn
        certificate.subject = cert.parsed.subject_dn
        if cert.parsed.signature:
            certificate.signature_algorithm = (
                cert.parsed.signature.signature_algorithm.name
            )
        if cert.parsed.validity_period:
            certificate.validity_not_before = cert.parsed.validity_period.not_before
            certificate.validity_not_after = cert.parsed.validity_period.not_after
        if cert.parsed.subject_key_info:
            certificate.subject_public_key_algorithm = (
                cert.parsed.subject_key_info.key_algorithm.name
            )
            if cert.parsed.subject_key_info.rsa:
                certificate.subject_public_key_modulus = (
                    cert.parsed.subject_key_info.rsa.modulus
                )
                certificate.subject_public_key_exponent = (
                    cert.parsed.subject_key_info.rsa.exponent
                )

    def _add_certificate_extensions(
        self, certificate: X509Certificate, cert: Certificate
    ) -> None:
        if cert.parsed.extensions.key_usage:
            certificate.key_usage = cert.parsed.extensions.key_usage.model_dump_json()
        if cert.parsed.extensions.basic_constraints:
            certificate.basic_constraints = (
                cert.parsed.extensions.basic_constraints.model_dump_json()
            )
        certificate.crl_distribution_points = str(
            cert.parsed.extensions.crl_distribution_points
        )
        certificate.authority_key_identifier = cert.parsed.extensions.authority_key_id
        if cert.parsed.extensions.extended_key_usage:
            certificate.extended_key_usage = (
                cert.parsed.extensions.extended_key_usage.model_dump_json()
            )
        certificate.certificate_policies = str(
            cert.parsed.extensions.certificate_policies
        )

    def add_certificate(self, cert: Certificate | None) -> X509Certificate | None:
        # An X509Certificate observable is identified by its fingerprints. The
        # SDK model rejects empty ``hashes`` at serialization (stix2 raises
        # "hashes must not be empty"), so a certificate with no fingerprint at
        # all cannot be represented — skip it rather than emit an unserializable
        # object, even if ``parsed`` metadata is present.
        if not cert or not (
            cert.fingerprint_sha256 or cert.fingerprint_sha1 or cert.fingerprint_md5
        ):
            return None
        # Only keep fingerprints that are actually present. The SDK model types
        # ``hashes`` as ``dict[HashAlgorithm, str] | None`` (with min_length=1),
        # so ``None`` values would fail validation and an empty dict is invalid
        # too — pass ``None`` when the certificate carries no fingerprint.
        hashes = {
            algorithm: fingerprint
            for algorithm, fingerprint in (
                (HashAlgorithm.SHA1, cert.fingerprint_sha1),
                (HashAlgorithm.SHA256, cert.fingerprint_sha256),
                (HashAlgorithm.MD5, cert.fingerprint_md5),
            )
            if fingerprint
        }
        certificate = X509Certificate(
            hashes=hashes or None,
            **self.common_props,
        )
        if cert.parsed:
            self._add_certificate_parsed_fields(certificate=certificate, cert=cert)
            if cert.parsed.extensions:
                self._add_certificate_extensions(certificate=certificate, cert=cert)
        self.bundle.append(certificate)
        return certificate

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
                authors=[self.author.name],
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

        # Add evidence features from the reputation model
        self._add_reputation_evidence_features(reputation, content_parts)

        if not content_parts:
            return

        self.bundle.append(
            Note(
                abstract="Censys host reputation",
                content="\n".join(content_parts),
                note_types=[NoteType.EXTERNAL],
                labels=[score_label] if score_label else None,
                authors=[self.author.name],
                objects=[observable],
                **self.common_props,
            )
        )

    def _add_reputation_evidence_features(
        self, reputation: Reputation, content_parts: list[str]
    ) -> None:
        """Extract and format evidence features from the reputation model.

        Uses ReputationEvidence model objects from the SDK.
        """
        if not reputation.evidence or not isinstance(reputation.evidence, list):
            return

        content_parts.append("\n**Evidence Features:**")
        for evidence in reputation.evidence:
            if evidence.feature:
                self._format_evidence_feature(evidence.feature, content_parts)

    def _format_evidence_feature(
        self, feature: object, content_parts: list[str]
    ) -> None:
        """Format a reputation evidence feature.

        Handles ReputationEvidenceFeature model objects with:
        - name, value, contribution, category
        """
        name = self._get_value(feature, "name") or "Unknown"
        value = self._get_value(feature, "value")
        contribution = self._get_value(feature, "contribution")
        category = self._get_value(feature, "category")

        contribution_str = self._format_contribution(contribution) if contribution is not None else ""

        parts = [f"- {name}"]
        if value:
            parts.append(f"value={value}")
        if contribution_str:
            parts.append(f"contribution={contribution_str}")
        if category:
            parts.append(f"category={category}")

        content_parts.append(": ".join([parts[0], ", ".join(parts[1:])]) if len(parts) > 1 else parts[0])

    @staticmethod
    def _format_contribution(contribution: object) -> str:
        """Format contribution value as a signed percentage.

        Examples:
        - 8.708259985239051 -> "+8.71%"
        - -3.738838369305972 -> "-3.74%"
        """
        if isinstance(contribution, (int, float)):
            return f"{contribution:+.2f}%"
        return str(contribution)

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
        if service.threats:
            for threat in service.threats:
                threat_details = []
                if hasattr(threat, 'name') and threat.name:
                    threat_details.append(threat.name)
                if hasattr(threat, 'severity') and threat.severity:
                    threat_details.append(f"Severity: {threat.severity}")
                if threat_details:
                    threats_info.append("- " + " | ".join(threat_details))

        if threats_info:
            if content_parts:
                content_parts.append("")
            content_parts.append("### Threats")
            content_parts.extend(threats_info)

        return "\n".join(content_parts)

    def add_services(
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
                    abstract=f"Service information on port {service.port} ({service.protocol or 'Unknown'})",
                    content=content,
                    note_types=[NoteType.EXTERNAL],
                    publication_date=datetime.datetime.fromisoformat(service.scan_time),
                    authors=[self.author.name],
                    objects=[observable],
                    **self.common_props,
                )
            )

    def add_service_threats(
        self,
        observable: Reference,
        threats: list[object] | None,
        port: int | None,
        protocol: str | None,
    ) -> None:
        """Create Malware, Attack-Pattern, and Note objects from service threats."""
        for threat in threats or []:
            threat_name = self._get_value(threat, "name")
            threat_id = self._get_value(threat, "id")
            if not threat_name or not threat_id:
                continue

            malware = self._add_threat_malware(threat)
            if malware:
                self.bundle.extend([
                    malware,
                    Relationship(
                        source=observable,
                        target=malware,
                        type=RelationshipType.RELATED_TO,
                        **self.common_props,
                    )
                ])

            for tactic in self._get_value(threat, "tactic") or []:
                attack_pattern = self._add_threat_attack_pattern(tactic)
                if attack_pattern:
                    self.bundle.extend([
                        attack_pattern,
                        Relationship(
                            source=observable,
                            target=attack_pattern,
                            type=RelationshipType.RELATED_TO,
                            **self.common_props,
                        )
                    ])

            threat_note = self._build_threat_note(
                observable=observable,
                threat=threat,
                port=port,
                protocol=protocol,
            )
            if threat_note:
                self.bundle.append(threat_note)

    def _add_threat_malware(self, threat: object) -> Malware | None:
        """Create a Malware object from threat data if known malware exists."""
        malware_data = self._get_value(threat, "malware")
        if not isinstance(malware_data, dict):
            return None

        primary_name = malware_data.get("primary_name")
        if not primary_name:
            return None

        threat_types = self._get_value(threat, "type") or []
        malware_type_enums = []
        for threat_type in threat_types:
            if isinstance(threat_type, str):
                try:
                    from connectors_sdk.models.enums import MalwareType
                    normalized = threat_type.lower().replace("_", "-")
                    malware_type_enums.append(MalwareType(normalized))
                except (ValueError, KeyError):
                    pass

        malware = Malware(
            name=primary_name,
            is_family=False,
            aliases=malware_data.get("all_names", []),
            types=malware_type_enums or None,
            description=f"{self._get_value(threat, 'id')}: {self._get_value(threat, 'name')}",
            **self.common_props,
        )
        return malware

    def _add_threat_attack_pattern(self, tactic: str) -> AttackPattern | None:
        """Create an Attack-Pattern object for MITRE ATT&CK tactic."""
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

        attack_pattern = AttackPattern(
            name=tactic_name,
            external_references=external_refs or None,
            **self.common_props,
        )
        return attack_pattern

    def _build_threat_note(
        self,
        observable: Reference,
        threat: object,
        port: int | None,
        protocol: str | None,
    ) -> Note | None:
        """Create a Note object with detailed threat evidence and context."""
        threat_name = self._get_value(threat, "name")
        threat_id = self._get_value(threat, "id")
        if not threat_name:
            return None

        content_parts = []
        content_parts.append(f"- **Threat ID:** {threat_id}")
        content_parts.append(f"- **Name:** {threat_name}")

        if source := self._get_value(threat, "source"):
            content_parts.append(f"- **Source:** {source}")

        if confidence := self._get_value(threat, "confidence"):
            content_parts.append(f"- **Confidence:** {confidence}")

        threat_types = self._get_value(threat, "type") or []
        if threat_types:
            types_str = ", ".join(
                t.replace("_", " ") for t in threat_types
                if isinstance(t, str)
            )
            content_parts.append(f"- **Threat Types:** {types_str}")

        tactics = self._get_value(threat, "tactic") or []
        if tactics:
            tactics_str = ", ".join(
                t.replace("_", " ").title() for t in tactics
                if isinstance(t, str)
            )
            content_parts.append(f"- **Tactics:** {tactics_str}")

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
                content_parts.append(f"\n- **Malware:** {malware_data['primary_name']}")
                if aliases := malware_data.get("all_names"):
                    aliases_str = ", ".join(aliases)
                    content_parts.append(f"- **Aliases:** {aliases_str}")
                if updated := malware_data.get("last_updated_at"):
                    content_parts.append(f"- **Last Updated:** {updated}")

        threat_note = Note(
            abstract=f"Service Threat: {threat_name}" + (
                f" (Port {port}/{protocol})" if port and protocol else ""
            ),
            content="\n".join(content_parts),
            note_types=[NoteType.EXTERNAL],
            labels=[
                t.lower().replace("_", "-") for t in threat_types
                if isinstance(t, str)
            ] or None,
            authors=[self.author.name],
            objects=[observable],
            **self.common_props,
        )
        return threat_note

    @staticmethod
    def _get_mitre_tactic_id(tactic: str) -> str | None:
        """Map Censys tactic names to MITRE ATT&CK tactic IDs."""
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


    def add_ip(self, observable: Reference, ip: str) -> IPV4Address | IPV6Address:
        ip_version = ipaddress.ip_network(ip, strict=False).version
        if ip_version == 4:
            ip_address = IPV4Address(value=ip, **self.common_props)
        else:
            ip_address = IPV6Address(value=ip, **self.common_props)
        self.bundle.extend(
            [
                ip_address,
                Relationship(
                    source=observable,
                    target=ip_address,
                    type=RelationshipType.RELATED_TO,
                    **self.common_props,
                ),
            ]
        )
        return ip_address

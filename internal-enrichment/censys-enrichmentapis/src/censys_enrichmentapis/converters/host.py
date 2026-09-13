import re

from censys_enrichmentapis.converters.base import CensysConverter, ObservableLike
from censys_platform import HostEnrichment
from connectors_sdk.models import Reference, Relationship, Software
from connectors_sdk.models.enums import RelationshipType


class HostConverter(CensysConverter):
    def _fetch_data(self, observable: ObservableLike) -> HostEnrichment:
        return self._require_client().fetch_ip(observable["value"])

    def _convert_labels(self, data: HostEnrichment) -> list[str]:
        label_values = [label.value for label in data.labels or []]
        label_values.extend(
            label.value
            for service in data.services or []
            for label in service.labels or []
        )
        threat_names = [
            self._value(threat, "name")
            for service in data.services or []
            for threat in self._value(service, "threats") or []
        ]
        label_values.extend(name for name in threat_names if name)
        if data.reputation and data.reputation.label:
            label_values.append(data.reputation.label)
        return list(
            dict.fromkeys(
                f"Censys_{self._to_snake_case(label_value.strip())}"
                for label_value in label_values
                if label_value and label_value.strip()
            )
        )

    def _convert(self, observable: ObservableLike, data: HostEnrichment) -> None:
        stix_entity = observable
        observable = Reference(id=stix_entity.get("id"))
        self.primary_observable_labels = self._convert_labels(data)

        self.builder.add_author_and_marking()
        self.builder.add_city(
            observable=observable,
            name=data.location.city if data.location else None,
        )
        self.builder.add_region(
            observable=observable,
            name=data.location.continent if data.location else None,
        )
        self.builder.add_administrative_area(
            observable=observable,
            name=data.location.province if data.location else None,
            coordinates=data.location.coordinates if data.location else None,
        )

        country = self.builder.add_country(
            observable=observable,
            name=data.location.country if data.location else None,
        )
        organization = self.builder.add_organization(
            observable=observable,
            name=data.autonomous_system.name if data.autonomous_system else None,
        )
        autonomous_system = self.builder.add_autonomous_system(
            observable=observable,
            name=data.autonomous_system.name if data.autonomous_system else None,
            description=(
                data.autonomous_system.description if data.autonomous_system else None
            ),
            number=data.autonomous_system.asn if data.autonomous_system else None,
        )
        if autonomous_system and organization:
            self.builder.bundle.append(
                Relationship(
                    source=autonomous_system,
                    target=organization,
                    type=RelationshipType.RELATED_TO,
                    **self.builder.common_props,
                )
            )
        if autonomous_system and country:
            self.builder.bundle.append(
                Relationship(
                    source=autonomous_system,
                    target=country,
                    type=RelationshipType.RELATED_TO,
                    **self.builder.common_props,
                )
            )

        self.builder.add_hostnames(
            observable=observable,
            dns=data.dns,
        )

        self.builder.add_services(
            observable=observable,
            services=data.services,
        )

        self.builder.add_reputation_note(
            observable=observable,
            reputation=data.reputation,
        )
    
        self._add_service_vulnerabilities(observable, data.services)
        self._add_service_threats(observable, data.services)
       
    def _add_service_vulnerabilities(
        self, observable: Reference, services: object | None
    ) -> None:
        """Create the IP -> Software -> Vulnerability path from Censys services."""
        for service in services or []:
            software_by_cpe: dict[str, Software] = {}
            for software_data in self._value(service, "software") or []:
                software = self.builder.add_software(
                    observable=observable,
                    name=self._value(software_data, "product"),
                    vendor=self._value(software_data, "vendor"),
                    cpe=self._value(software_data, "cpe"),
                    version=self._value(software_data, "version"),
                )
                cpe = self._value(software_data, "cpe")
                if software and isinstance(cpe, str):
                    software_by_cpe[cpe] = software

            for vulnerability in self._value(service, "vulns") or []:
                for cpe in self._vulnerability_cpes(vulnerability):
                    software = software_by_cpe.get(cpe)
                    if software is None:
                        software = self._add_software_from_cpe(observable, cpe)
                        if software is not None:
                            software_by_cpe[cpe] = software
                    if software is not None:
                        self.builder.add_vulnerability(software, vulnerability)

    def _add_service_threats(
        self, observable: Reference, services: object | None
    ) -> None:
        """Create Malware, Attack-Pattern, and Note objects from service threats."""
        for service in services or []:
            threats = self._value(service, "threats")
            port = self._value(service, "port")
            protocol = self._value(service, "protocol")
            self.builder.add_service_threats(
                observable=observable,
                threats=threats,
                port=port,
                protocol=protocol,
            )

    def _add_software_from_cpe(
        self, observable: Reference, cpe: str
    ) -> Software | None:
        # Censys CVE evidence uses CPE 2.3 strings.  We only need vendor,
        # product, and version to create the corresponding OpenCTI Software.
        parts = cpe.split(":")
        if len(parts) < 6 or parts[0:2] != ["cpe", "2.3"]:
            return None
        return self.builder.add_software(
            observable=observable,
            vendor=parts[3],
            name=parts[4],
            version=parts[5] if parts[5] != "*" else None,
            cpe=cpe,
        )

    def _vulnerability_cpes(self, vulnerability: object) -> set[str]:
        cpes = set()
        for evidence in self._value(vulnerability, "evidence") or []:
            cpe = self._value(evidence, "found_value")
            if isinstance(cpe, str) and cpe.startswith("cpe:2.3:"):
                cpes.add(cpe)
        return cpes

    @staticmethod
    def _to_snake_case(text: str) -> str:
        """Convert text to snake_case format."""
        # Replace spaces and hyphens with underscores
        text = re.sub(r'[\s\-]+', '_', text)
        return text

    @staticmethod
    def _value(value: object, field: str) -> object | None:
        if isinstance(value, dict):
            return value.get(field)
        return getattr(value, field, None)

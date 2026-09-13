import re

from censys_enrichmentapis.converters.base import CensysConverter, ObservableLike
from censys_platform import HostEnrichment
from connectors_sdk.models import Reference


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
        self.builder.geography.add_city(
            observable=observable,
            name=data.location.city if data.location else None,
        )
        self.builder.geography.add_region(
            observable=observable,
            name=data.location.continent if data.location else None,
        )
        self.builder.geography.add_administrative_area(
            observable=observable,
            name=data.location.province if data.location else None,
            coordinates=data.location.coordinates if data.location else None,
        )

        country = self.builder.geography.add_country(
            observable=observable,
            name=data.location.country if data.location else None,
        )
        organization = self.builder.network.add_organization(
            observable=observable,
            name=data.autonomous_system.name if data.autonomous_system else None,
        )
        self.builder.network.add_autonomous_system(
            observable=observable,
            name=data.autonomous_system.name if data.autonomous_system else None,
            description=(
                data.autonomous_system.description if data.autonomous_system else None
            ),
            number=data.autonomous_system.asn if data.autonomous_system else None,
            organization=organization,
            country=country,
        )

        self.builder.network.add_hostnames(
            observable=observable,
            dns=data.dns,
        )

        self.builder.services.add_service_notes(
            observable=observable,
            services=data.services,
        )

        self.builder.services.add_reputation_note(
            observable=observable,
            reputation=data.reputation,
        )
        self.builder.services.add_service_vulnerabilities(
            observable=observable,
            services=data.services,
        )
        self.builder.services.add_service_threats(
            observable=observable,
            services=data.services,
        )

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

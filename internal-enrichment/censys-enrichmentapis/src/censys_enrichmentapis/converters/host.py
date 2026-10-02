from censys_enrichmentapis.converters.base import CensysConverter, ObservableLike
from censys_platform import Host, HostEnrichment, Reputation
from connectors_sdk.models import Reference


class HostConverter(CensysConverter):
    def _fetch_data(self, observable: ObservableLike) -> HostEnrichment:
        return self._require_client().fetch_ip(observable["value"])

    def _convert_labels(self, data: Host | HostEnrichment) -> list[str]:
        label_values = [
            label_value
            for label in self._value(data, "labels") or []
            if isinstance((label_value := self._value(label, "value")), str)
        ]
        label_values.extend(
            label_value
            for service in self._value(data, "services") or []
            for label in self._value(service, "labels") or []
            if isinstance((label_value := self._value(label, "value")), str)
        )
        threat_names = [
            self._value(threat, "name")
            for service in self._value(data, "services") or []
            for threat in self._value(service, "threats") or []
        ]
        labels = self._format_censys_labels(label_values)
        labels.extend(self._format_censys_labels(threat_names, category="Threat"))
        reputation = self._value(data, "reputation")
        reputation_label = self._value(reputation, "label")
        if isinstance(reputation_label, str):
            labels.extend(self._format_censys_labels([reputation_label]))
        return list(dict.fromkeys(labels))

    def _convert(self, observable: ObservableLike, data: Host | HostEnrichment) -> None:
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

        reputation = self._value(data, "reputation")
        self.builder.services.add_reputation_note(
            observable=observable,
            observable_value=stix_entity.get("value"),
            reputation=reputation if isinstance(reputation, Reputation) else None,
        )
        self.builder.services.add_service_vulnerabilities(
            observable=observable,
            services=data.services,
        )
        self.builder.services.add_service_threats(
            observable=observable,
            observable_value=stix_entity.get("value"),
            services=data.services,
        )

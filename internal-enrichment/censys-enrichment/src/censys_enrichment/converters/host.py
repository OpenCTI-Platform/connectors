from censys_enrichment.converters.base import CensysConverter, ObservableLike
from censys_platform import Host
from connectors_sdk.models import Reference, Relationship
from connectors_sdk.models.enums import RelationshipType


class HostConverter(CensysConverter):
    def _fetch_data(self, observable: ObservableLike) -> Host:
        return self._require_client().fetch_ip(observable["value"])

    def _convert(self, observable: ObservableLike, data: Host) -> None:
        stix_entity = observable
        observable = Reference(id=stix_entity.get("id"))

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
        self.builder.add_hostnames(
            observable=observable,
            dns=data.dns,
        )
        self.builder.add_services(
            observable=observable,
            services=data.services,
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
        if autonomous_system:
            if organization:
                self.builder.bundle.append(
                    Relationship(
                        source=autonomous_system,
                        target=organization,
                        type=RelationshipType.RELATED_TO,
                        **self.builder.common_props,
                    )
                )
            if country:
                self.builder.bundle.append(
                    Relationship(
                        source=autonomous_system,
                        target=country,
                        type=RelationshipType.RELATED_TO,
                        **self.builder.common_props,
                    )
                )

import ipaddress

from censys_enrichmentapis.builders.base import AreaStixBuilder
from censys_platform import HostDNS
from connectors_sdk.models import (
    AutonomousSystem,
    Country,
    Hostname,
    IPV4Address,
    IPV6Address,
    Organization,
    Reference,
    Relationship,
)
from connectors_sdk.models.enums import RelationshipType


class NetworkStixBuilder(AreaStixBuilder):
    def add_hostnames(self, observable: Reference, dns: HostDNS | None) -> None:
        if not dns:
            return

        for name in dns.names or []:
            host_name = Hostname(value=name, **self.common_props)
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

        organization = Organization(name=name, **self.common_props)
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
        *,
        organization: Organization | None = None,
        country: Country | None = None,
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
        if organization:
            self.add_relationship(
                autonomous_system, organization, RelationshipType.RELATED_TO
            )
        if country:
            self.add_relationship(
                autonomous_system, country, RelationshipType.RELATED_TO
            )
        return autonomous_system

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

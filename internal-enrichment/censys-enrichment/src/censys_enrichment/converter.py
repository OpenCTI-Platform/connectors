import datetime
import ipaddress
from typing import Any, Generator

from censys_platform import (
    Certificate,
    Coordinates,
    Host,
    HostDNS,
    Service,
)
from connectors_sdk.models import (
    AdministrativeArea,
    AutonomousSystem,
    BaseIdentifiedEntity,
    BaseObject,
    City,
    Country,
    Hostname,
    IPV4Address,
    IPV6Address,
    Note,
    Organization,
    OrganizationAuthor,
    Region,
    Relationship,
    Software,
    TLPMarking,
    X509Certificate,
)
from connectors_sdk.models.enums import HashAlgorithm, RelationshipType, TLPLevel
from pydantic import Field


class EmbeddedIdentifiedStixObject(BaseIdentifiedEntity):
    """Embedded Identified STIX Object representation.

    This class encapsulates a STIX object with an id as a dictionary and provides
    access to the object without copying or modifying the original data.

    Use when you only need to read or forward the STIX object, not alter it.
    """

    stix_object: dict[str, Any] = Field()

    @property
    def id(self) -> str:
        """Return the STIX object's ID."""
        return self.stix_object["id"]

    def to_stix2_object(self) -> dict[str, Any]:
        """Return the STIX2 object representation."""
        return self.stix_object


class Converter:
    def __init__(self) -> None:
        self.author = OrganizationAuthor(name="Censys Enrichment Connector")
        self.marking = TLPMarking(level=TLPLevel.CLEAR)
        self._common_props = {"author": self.author, "markings": [self.marking]}

    def _generate_city(
        self, observable: EmbeddedIdentifiedStixObject, name: str | None
    ) -> Generator[BaseObject, None, None]:
        if not name:
            return

        city = City(
            name=name,
            **self._common_props,
        )
        yield from [
            city,
            Relationship(
                source=observable,
                target=city,
                type=RelationshipType.LOCATED_AT,
                **self._common_props,
            ),
        ]

    def _generate_country(
        self, observable: EmbeddedIdentifiedStixObject, name: str | None
    ) -> Generator[BaseObject, None, Country | None]:
        if not name:
            return None

        country = Country(
            name=name,
            **self._common_props,
        )
        yield from [
            country,
            Relationship(
                source=observable,
                target=country,
                type=RelationshipType.LOCATED_AT,
                **self._common_props,
            ),
        ]
        return country

    def _generate_region(
        self, observable: EmbeddedIdentifiedStixObject, name: str | None
    ) -> Generator[BaseObject, None, None]:
        if not name:
            return

        region = Region(
            name=name,
            **self._common_props,
        )
        yield from [
            region,
            Relationship(
                source=observable,
                target=region,
                type=RelationshipType.LOCATED_AT,
                **self._common_props,
            ),
        ]

    def _generate_administrative_area(
        self,
        observable: EmbeddedIdentifiedStixObject,
        name: str | None,
        coordinates: Coordinates | None,
    ) -> Generator[BaseObject, None, None]:
        if not name:
            return

        administrative_area = (
            AdministrativeArea(
                name=name,
                latitude=coordinates.latitude,
                longitude=coordinates.longitude,
                **self._common_props,
            )
            if coordinates
            else AdministrativeArea(
                name=name,
                **self._common_props,
            )
        )

        yield from [
            administrative_area,
            Relationship(
                source=observable,
                target=administrative_area,
                type=RelationshipType.LOCATED_AT,
                **self._common_props,
            ),
        ]

    def _generate_hostnames(
        self, observable: EmbeddedIdentifiedStixObject, dns: HostDNS | None
    ) -> Generator[BaseObject, None, None]:
        if not dns:
            return

        for name in dns.names or []:
            host_name = Hostname(
                value=name,
                **self._common_props,
            )
            yield from [
                host_name,
                Relationship(
                    source=host_name,
                    target=observable,
                    type=RelationshipType.RESOLVES_TO,
                    **self._common_props,
                ),
            ]

    def _generate_organization(
        self,
        observable: EmbeddedIdentifiedStixObject,
        name: str | None,
    ) -> Generator[BaseObject, None, Organization | None]:
        if not name:
            return None

        organization = Organization(
            name=name,
            **self._common_props,
        )
        yield from [
            organization,
            Relationship(
                source=observable,
                target=organization,
                type=RelationshipType.RELATED_TO,
                **self._common_props,
            ),
        ]
        return organization

    def _generate_autonomous_system(
        self,
        observable: EmbeddedIdentifiedStixObject,
        number: int | None,
        name: str | None,
        description: str | None,
    ) -> Generator[BaseObject, None, AutonomousSystem | None]:
        if not number:
            return None

        autonomous_system = AutonomousSystem(
            name=name,
            description=description,
            number=number,
            **self._common_props,
        )
        yield from [
            autonomous_system,
            Relationship(
                source=observable,
                target=autonomous_system,
                type=RelationshipType.BELONGS_TO,
                **self._common_props,
            ),
        ]
        return autonomous_system

    def _generate_software(
        self,
        observable: EmbeddedIdentifiedStixObject,
        name: str | None,
        vendor: str | None,
        cpe: str | None,
    ) -> Generator[BaseObject, None, None]:
        if not name:
            return

        software = Software(
            name=name,
            vendor=vendor,
            cpe=cpe,
            **self._common_props,
        )
        yield from [
            software,
            Relationship(
                source=observable,
                target=software,
                type=RelationshipType.RELATED_TO,
                **self._common_props,
            ),
        ]

    def _generate_certificate(
        self, cert: Certificate | None
    ) -> Generator[BaseObject, None, X509Certificate | None]:
        if not cert or not (
            cert.fingerprint_sha256
            or cert.fingerprint_sha1
            or cert.fingerprint_md5
            or cert.parsed
        ):
            return None
        certificate = X509Certificate(
            hashes={
                HashAlgorithm.SHA1: cert.fingerprint_sha1,
                HashAlgorithm.SHA256: cert.fingerprint_sha256,
                HashAlgorithm.MD5: cert.fingerprint_md5,
            },
            **self._common_props,
        )
        if cert.parsed:
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
            if cert.parsed.extensions:
                if cert.parsed.extensions.key_usage:
                    certificate.key_usage = (
                        cert.parsed.extensions.key_usage.model_dump_json()
                    )
                if cert.parsed.extensions.basic_constraints:
                    certificate.basic_constraints = (
                        cert.parsed.extensions.basic_constraints.model_dump_json()
                    )
                certificate.crl_distribution_points = str(
                    cert.parsed.extensions.crl_distribution_points
                )
                certificate.authority_key_identifier = (
                    cert.parsed.extensions.authority_key_id
                )
                if cert.parsed.extensions.extended_key_usage:
                    certificate.extended_key_usage = (
                        cert.parsed.extensions.extended_key_usage.model_dump_json()
                    )
                certificate.certificate_policies = str(
                    cert.parsed.extensions.certificate_policies
                )
        yield certificate
        return certificate

    def _generate_note(
        self,
        observable: EmbeddedIdentifiedStixObject,
        content: str | None,
        publication_date: str | None,
        port: int | None,
    ) -> Generator[BaseObject, None, None]:
        if not (content and publication_date and port):
            return

        yield Note(
            abstract=f"Service banner on port {port}",
            content=content,
            publication_date=datetime.datetime.fromisoformat(publication_date),
            authors=[self.author.name],
            objects=[observable],
            **self._common_props,
        )

    def _generate_services(
        self, observable: EmbeddedIdentifiedStixObject, services: list[Service] | None
    ) -> Generator[BaseObject, None, None]:
        for service in services or []:
            for software in service.software or []:
                yield from self._generate_software(
                    observable=observable,
                    name=software.product,
                    vendor=software.vendor,
                    cpe=software.cpe,
                )
            if service.cert:
                certificate = yield from self._generate_certificate(
                    cert=service.cert,
                )
                yield Relationship(
                    source=observable,
                    target=certificate,
                    type=RelationshipType.RELATED_TO,
                    **self._common_props,
                )
            yield from self._generate_note(
                observable=observable,
                port=service.port,
                content=service.banner,
                publication_date=service.scan_time,
            )

    def _generate_ip(
        self, observable: EmbeddedIdentifiedStixObject, ip: str
    ) -> Generator[BaseObject, None, None | IPV4Address | IPV6Address]:
        ip_version = ipaddress.ip_network(ip, strict=False).version
        if ip_version == 4:
            ip_address = IPV4Address(value=ip, **self._common_props)
        else:
            ip_address = IPV6Address(value=ip, **self._common_props)
        yield from [
            ip_address,
            Relationship(
                source=observable,
                target=ip_address,
                type=RelationshipType.RELATED_TO,
                **self._common_props,
            ),
        ]
        return ip_address

    def generate_octi_objects(
        self, stix_entity: dict[str, Any], data: Host
    ) -> Generator[BaseObject, None, None]:
        observable = EmbeddedIdentifiedStixObject(stix_object=stix_entity)

        yield from [
            self.author,
            self.marking,
        ]
        yield from self._generate_city(
            observable=observable,
            name=data.location.city if data.location else None,
        )
        yield from self._generate_region(
            observable=observable,
            name=data.location.continent if data.location else None,
        )
        yield from self._generate_administrative_area(
            observable=observable,
            name=data.location.province if data.location else None,
            coordinates=data.location.coordinates if data.location else None,
        )
        yield from self._generate_hostnames(
            observable=observable,
            dns=data.dns,
        )
        yield from self._generate_services(
            observable=observable,
            services=data.services,
        )
        country = yield from self._generate_country(
            observable=observable,
            name=data.location.country if data.location else None,
        )
        organization = yield from self._generate_organization(
            observable=observable,
            name=data.autonomous_system.name if data.autonomous_system else None,
        )
        autonomous_system = yield from self._generate_autonomous_system(
            observable=observable,
            name=data.autonomous_system.name if data.autonomous_system else None,
            description=(
                data.autonomous_system.description if data.autonomous_system else None
            ),
            number=data.autonomous_system.asn if data.autonomous_system else None,
        )
        if autonomous_system:
            if organization:
                yield Relationship(
                    source=autonomous_system,
                    target=organization,
                    type=RelationshipType.RELATED_TO,
                    **self._common_props,
                )
            if country:
                yield Relationship(
                    source=autonomous_system,
                    target=country,
                    type=RelationshipType.RELATED_TO,
                    **self._common_props,
                )

    def generate_octi_objects_from_certs(
        self, certs: list[Certificate]
    ) -> Generator[BaseObject, None, None]:
        yield from [
            self.author,
            self.marking,
        ]

        for cert in certs:
            yield from self._generate_certificate(
                cert=cert,
            )

    def generate_octi_objects_from_hosts(
        self, stix_entity: dict[str, Any], hosts: list[Host]
    ) -> Generator[BaseObject, None, None]:
        for host in hosts:
            ip_stix = yield from self._generate_ip(
                observable=EmbeddedIdentifiedStixObject(stix_object=stix_entity),
                ip=host.ip,
            )
            yield from self.generate_octi_objects(
                stix_entity=ip_stix.to_stix2_object(), data=host
            )

    def generate_octi_objects_from_domain_certs(
        self, stix_entity: dict[str, Any], certs: list[Certificate]
    ) -> Generator[BaseObject, None, None]:
        """Generate OpenCTI objects from certificates associated with a domain

        Args:
            stix_entity: The domain STIX entity
            certs: List of Certificate objects from Censys

        Yields:
            BaseObject: STIX objects representing certificates and their relationships
        """
        observable = EmbeddedIdentifiedStixObject(stix_object=stix_entity)

        yield from [
            self.author,
            self.marking,
        ]

        for cert in certs:
            certificate = yield from self._generate_certificate(cert=cert)
            if certificate:
                yield Relationship(
                    source=certificate,
                    target=observable,
                    type=RelationshipType.RELATED_TO,
                    **self._common_props,
                )

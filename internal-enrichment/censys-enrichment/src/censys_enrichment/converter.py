from typing import Any, Generator

from censys_platform import (
    Attribute,
    AutonomousSystem,
    Certificate,
    Coordinates,
    Host,
    HostDNS,
    Location,
    Service,
)
from connectors_sdk.models import (
    AdministrativeArea,
    BaseIdentifiedObject,
    BaseObject,
    City,
    Country,
    Hostname,
    Organization,
    OrganizationAuthor,
    Region,
    Relationship,
    Software,
    TLPMarking,
    X509Certificate,
    X509V3Extensions,
)
from connectors_sdk.models.enums import HashAlgorithm, RelationshipType, TLPLevel
from pydantic import Field


class EmbeddedIdentifiedStixObject(BaseIdentifiedObject):
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
        self._props = {"author": self.author, "markings": [self.marking]}

    def _generate_city(
        self, observable: EmbeddedIdentifiedStixObject, name: str | None
    ) -> Generator[BaseObject, None, None]:
        if not name:
            return
        city = City(name=name, **self._props)
        yield from [
            city,
            Relationship(
                source=observable,
                target=city,
                type=RelationshipType.LOCATED_AT,
                **self._props,
            ),
        ]

    def _generate_country(
        self, observable: EmbeddedIdentifiedStixObject, name: str | None
    ) -> Generator[BaseObject, None, None]:
        if not name:
            return
        country = Country(name=name, **self._props)
        yield from [
            country,
            Relationship(
                source=observable,
                target=country,
                type=RelationshipType.LOCATED_AT,
                **self._props,
            ),
        ]

    def _generate_region(
        self, observable: EmbeddedIdentifiedStixObject, name: str | None
    ) -> Generator[BaseObject, None, None]:
        if not name:
            return
        region = Region(name=name, **self._props)
        yield from [
            region,
            Relationship(
                source=observable,
                target=region,
                type=RelationshipType.LOCATED_AT,
                **self._props,
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
                **self._props,
            )
            if coordinates
            else AdministrativeArea(name=name, **self._props)
        )

        yield from [
            administrative_area,
            Relationship(
                source=observable,
                target=administrative_area,
                type=RelationshipType.LOCATED_AT,
                **self._props,
            ),
        ]

    def _generate_locations(
        self, observable: EmbeddedIdentifiedStixObject, location: Location | None
    ) -> Generator[BaseObject, None, None]:
        if not location:
            return

        yield from self._generate_city(observable=observable, name=location.city)
        yield from self._generate_country(observable=observable, name=location.country)
        yield from self._generate_region(observable=observable, name=location.continent)
        yield from self._generate_administrative_area(
            observable=observable,
            name=location.province,
            coordinates=location.coordinates,
        )

    def _generate_hostnames(
        self, observable: EmbeddedIdentifiedStixObject, dns: HostDNS | None
    ) -> Generator[BaseObject, None, None]:
        if not dns:
            return

        for name in dns.names or []:
            host_name = Hostname(value=name, **self._props)
            yield from [
                host_name,
                Relationship(
                    source=observable,
                    target=host_name,
                    type=RelationshipType.RELATED_TO,
                    **self._props,
                ),
            ]

    def _generate_organization(
        self,
        observable: EmbeddedIdentifiedStixObject,
        autonomous_system: AutonomousSystem | None,
    ) -> Generator[BaseObject, None, None]:
        if not autonomous_system or not autonomous_system.name:
            return
        organization = Organization(name=autonomous_system.name, **self._props)
        yield from [
            organization,
            Relationship(
                source=observable,
                target=organization,
                type=RelationshipType.RELATED_TO,
                **self._props,
            ),
        ]

    def _generate_software(
        self, observable: EmbeddedIdentifiedStixObject, software: Attribute
    ) -> Generator[BaseObject, None, None]:
        software = Software(
            name=software.product,
            vendor=software.vendor,
            cpe=software.cpe,
            **self._props,
        )
        yield from [
            software,
            Relationship(
                source=observable,
                target=software,
                type=RelationshipType.RELATED_TO,
                **self._props,
            ),
        ]

    def _generate_certificate(
        self, observable: EmbeddedIdentifiedStixObject, cert: Certificate | None
    ) -> Generator[BaseObject, None, None]:
        if not cert or not (
            cert.fingerprint_sha256
            or cert.fingerprint_sha1
            or cert.fingerprint_md5
            or cert.parsed
        ):
            return
        certificate = X509Certificate(
            hashes={
                HashAlgorithm.SHA1: cert.fingerprint_sha1,
                HashAlgorithm.SHA256: cert.fingerprint_sha256,
                HashAlgorithm.MD5: cert.fingerprint_md5,
            },
            **self._props,
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
                certificate.validity_not_before = (
                    cert.parsed.validity_period.not_before
                )  # FIXME
                certificate.validity_not_after = (
                    cert.parsed.validity_period.not_after
                )  # FIXME
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
                certificate.x509_v3_extensions = X509V3Extensions(
                    key_usage=cert.parsed.extensions.key_usage.model_dump_json(),
                    basic_constraints=cert.parsed.extensions.basic_constraints.model_dump_json(),
                    crl_distribution_points=str(
                        cert.parsed.extensions.crl_distribution_points
                    ),
                    authority_key_identifier=cert.parsed.extensions.authority_key_id,
                    extended_key_usage=cert.parsed.extensions.extended_key_usage.model_dump_json(),
                    certificate_policies=str(
                        cert.parsed.extensions.certificate_policies
                    ),
                )
        yield from [
            certificate,
            Relationship(
                source=observable,
                target=certificate,
                type=RelationshipType.RELATED_TO,
                **self._props,
            ),
        ]

    def _generate_services(
        self, observable: EmbeddedIdentifiedStixObject, services: Service | None
    ) -> Generator[BaseObject, None, None]:
        for service in services or []:
            for software in service.software or []:
                yield from self._generate_software(
                    observable=observable, software=software
                )
            yield from self._generate_certificate(
                observable=observable, cert=service.cert
            )

    def generate_octi_objects(
        self, stix_entity: dict[str, Any], data: Host
    ) -> Generator[BaseObject, None, None]:
        observable = EmbeddedIdentifiedStixObject(stix_object=stix_entity)

        yield from [self.author, self.marking]
        yield from self._generate_locations(
            observable=observable, location=data.location
        )
        yield from self._generate_organization(
            observable=observable, autonomous_system=data.autonomous_system
        )
        yield from self._generate_hostnames(observable=observable, dns=data.dns)
        yield from self._generate_services(
            observable=observable, services=data.services
        )

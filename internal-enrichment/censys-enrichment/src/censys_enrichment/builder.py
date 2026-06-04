import datetime
import ipaddress

from censys_platform import (
    Certificate,
    Coordinates,
    HostDNS,
    Service,
)
from connectors_sdk.models import (
    AdministrativeArea,
    AutonomousSystem,
    BaseObject,
    City,
    Country,
    Hostname,
    IPV4Address,
    IPV6Address,
    Note,
    Organization,
    OrganizationAuthor,
    Reference,
    Region,
    Relationship,
    Software,
    TLPMarking,
    X509Certificate,
)
from connectors_sdk.models.enums import HashAlgorithm, RelationshipType, TLPLevel


class CensysStixBuilder:
    def __init__(self) -> None:
        self.author = OrganizationAuthor(name="Censys Enrichment Connector")
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
    ) -> None:
        if not name:
            return

        software = Software(
            name=name,
            vendor=vendor,
            cpe=cpe,
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

    def add_services(
        self, observable: Reference, services: list[Service] | None
    ) -> None:
        for service in services or []:
            for software in service.software or []:
                self.add_software(
                    observable=observable,
                    name=software.product,
                    vendor=software.vendor,
                    cpe=software.cpe,
                )
            if service.cert:
                certificate = self.add_certificate(
                    cert=service.cert,
                )
                if certificate:
                    self.bundle.append(
                        Relationship(
                            source=observable,
                            target=certificate,
                            type=RelationshipType.RELATED_TO,
                            **self.common_props,
                        )
                    )
            self.add_note(
                observable=observable,
                port=service.port,
                content=service.banner,
                publication_date=service.scan_time,
            )

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

from dataclasses import dataclass
from datetime import timezone

from censys_platform import (
    Attribute,
    BasicConstraints,
    Certificate,
    CertificateExtensions,
    CertificateParsed,
    CertificatePolicy,
    Coordinates,
    ExtendedKeyUsage,
    Host,
    HostDNS,
    KeyAlgorithm,
    KeyUsage,
    Location,
    Routing,
    Service,
    Signature,
    SubjectKeyInfo,
    ValidityPeriod,
)
from factory import (
    Factory,
    Faker,
    LazyAttribute,
    List,
    SelfAttribute,
    Sequence,
    SubFactory,
    fuzzy,
)


class CoordinatesFactory(Factory):
    class Meta:
        model = Coordinates

    latitude = Faker("latitude")
    longitude = Faker("longitude")


class LocationFactory(Factory):
    class Meta:
        model = Location

    city = Faker("city")
    continent = fuzzy.FuzzyChoice(
        [
            "Africa",
            "Antarctica",
            "Asia",
            "Europe",
            "North America",
            "Oceania",
            "South America",
        ]
    )
    coordinates = SubFactory(CoordinatesFactory)
    country = Faker("country")
    province = Faker("state")


class HostDNSFactory(Factory):
    class Meta:
        model = HostDNS

    names = List([Faker("domain_name"), Faker("domain_name")])


class RoutingFactory(Factory):
    class Meta:
        model = Routing

    asn = Faker("random_int", min=1, max=65535)
    bgp_prefix = Faker("ipv4")
    country_code = Faker("country_code")
    description = Faker("company")
    name = Faker("company")


class KeyAlgorithmFactory(Factory):
    class Meta:
        model = KeyAlgorithm

    name = Faker("word")


class SignatureFactory(Factory):
    class Meta:
        model = Signature

    signature_algorithm = SubFactory(KeyAlgorithmFactory)


class ValidityPeriodFactory(Factory):
    class Meta:
        model = ValidityPeriod

    not_before = Faker("iso8601", tzinfo=timezone.utc)
    not_after = Faker("iso8601", tzinfo=timezone.utc)


class SubjectKeyInfoFactory(Factory):
    class Meta:
        model = SubjectKeyInfo

    key_algorithm = SubFactory(KeyAlgorithmFactory)


class CertificatePolicyFactory(Factory):
    class Meta:
        model = CertificatePolicy

    cps = List([Faker("uri"), Faker("uri")])
    id = Faker("bothify", text="2.23.140.1.2.?")


class KeyUsageFactory(Factory):
    class Meta:
        model = KeyUsage


class BasicConstraintsFactory(Factory):
    class Meta:
        model = BasicConstraints


class ExtendedKeyUsageFactory(Factory):
    class Meta:
        model = ExtendedKeyUsage


class CertificateExtensionsFactory(Factory):
    class Meta:
        model = CertificateExtensions

    key_usage = SubFactory(KeyUsageFactory)
    basic_constraints = SubFactory(BasicConstraintsFactory)
    crl_distribution_points = List([Faker("uri"), Faker("uri")])
    authority_key_id = Faker("sha1")
    extended_key_usage = SubFactory(ExtendedKeyUsageFactory)
    certificate_policies = List([SubFactory(CertificatePolicyFactory)])


class CertificateParsedFactory(Factory):
    class Meta:
        model = CertificateParsed

    serial_number = Sequence(lambda n: str(100000000 + n))
    issuer_dn = Faker("sentence", nb_words=6)
    subject_dn = Faker("sentence", nb_words=3)
    signature = SubFactory(SignatureFactory)
    validity_period = SubFactory(ValidityPeriodFactory)
    subject_key_info = SubFactory(SubjectKeyInfoFactory)
    extensions = SubFactory(CertificateExtensionsFactory)


class CertificateFactory(Factory):
    class Meta:
        model = Certificate

    fingerprint_md5 = Faker("md5")
    fingerprint_sha1 = Faker("sha1")
    fingerprint_sha256 = Faker("sha256")
    parsed = SubFactory(CertificateParsedFactory)


class AttributeFactory(Factory):
    class Meta:
        model = Attribute

    product = Faker("word")
    vendor = Faker("company")
    cpe = Faker("bothify", text="cpe:2.3:a:?????:*:*:*:*:*:*:*:*")


class ServiceFactory(Factory):
    class Meta:
        model = Service

    banner = Faker("sentence", nb_words=4)
    cert = SubFactory(CertificateFactory)
    port = Faker("random_int", min=1, max=65535)
    scan_time = Faker("iso8601", tzinfo=timezone.utc)
    software = List([SubFactory(AttributeFactory)])


class HostFactory(Factory):
    def __new__(cls, *args, **kwargs) -> Host:
        return super().__new__(*args, **kwargs)

    class Meta:
        model = Host

    ip = Faker("ipv4")
    location = SubFactory(LocationFactory)
    dns = SubFactory(HostDNSFactory)
    autonomous_system = SubFactory(RoutingFactory)
    services = List([ServiceFactory(), ServiceFactory()])


@dataclass
class StixExternalReference:
    description: str
    external_id: str
    source_name: str
    url: str


@dataclass
class StixIpv4Entity:
    id: str
    x_opencti_score: int
    x_opencti_description: str
    value: str
    x_opencti_id: str
    x_opencti_type: str
    type: str
    external_references: list[StixExternalReference]
    x_opencti_labels: list[str]
    spec_version: str = "2.1"


class StixExternalReferenceFactory(Factory):
    class Meta:
        model = StixExternalReference

    description = Faker("sentence")
    external_id = Faker("uuid4")
    source_name = "MISP"
    url = Faker("url")


class StixIpv4EntityFactory(Factory):
    class Meta:
        model = StixIpv4Entity

    id = Faker("uuid4")
    x_opencti_score = Faker("random_int", min=0, max=100)
    x_opencti_description = Faker("sentence")
    value = Faker("ipv4")
    x_opencti_id = SelfAttribute("id")
    x_opencti_type = "IPv4-Addr"
    type = "ipv4-addr"
    external_references = List([SubFactory(StixExternalReferenceFactory)])
    x_opencti_labels = List([Faker("word")])


@dataclass
class Creator:
    id: str
    name: str


class CreatorFactory(Factory):
    class Meta:
        model = Creator

    id = Faker("uuid4")
    name = Faker("name")


@dataclass
class Ipv4EnrichmentEntity:
    created_at: str
    creators: list[Creator]
    entity_type: str
    id: str
    indicators: list[dict]
    indicatorsIds: list[str]
    objectLabel: list
    objectLabelIds: list[str]
    objectMarking: list
    objectMarkingIds: list[str]
    objectOrganization: list[str]
    observable_value: str
    parent_types: list[str]
    spec_version: str
    standard_id: str
    updated_at: str
    value: str
    x_opencti_score: int
    createdBy: dict = None
    createdById: str | None = None
    x_opencti_description: str | None = None


class Ipv4EnrichmentEntityFactory(Factory):
    class Meta:
        model = Ipv4EnrichmentEntity

    created_at = Faker("iso8601", tzinfo=timezone.utc)
    creators = List([SubFactory(CreatorFactory)])
    entity_type = "IPv4-Addr"
    id = Faker("uuid4")
    indicators = []
    indicatorsIds = []
    objectLabel = []
    objectLabelIds = []
    objectMarking = []
    objectMarkingIds = LazyAttribute(lambda o: [m.id for m in o.objectMarking])
    objectOrganization = []
    observable_value = Faker("ipv4")
    parent_types = [
        "Basic-Object",
        "Stix-Object",
        "Stix-Core-Object",
        "Stix-Cyber-Observable",
    ]
    spec_version = "2.1"
    standard_id = LazyAttribute(lambda o: f"ipv4-addr--{o.id}")
    updated_at = Faker("iso8601", tzinfo=timezone.utc)
    value = SelfAttribute("observable_value")
    x_opencti_score = Faker("random_int", min=0, max=100)
    createdBy = None
    createdById = LazyAttribute(
        lambda o: o.createdBy.x_opencti_id if o.createdBy else None
    )
    x_opencti_description = Faker("sentence")


@dataclass
class EnrichmentMessage:
    id: str
    entity_id: str
    event_type: str
    entity_type: str
    enrichment_entity: Ipv4EnrichmentEntity
    stix_entity: StixIpv4Entity
    stix_objects: list[StixIpv4Entity]


class Ipv4EnrichmentFactory(Factory):
    def __new__(cls, *args, **kwargs) -> EnrichmentMessage:
        return super().__new__(*args, **kwargs)

    class Meta:
        model = EnrichmentMessage

    id = Faker("uuid4")
    entity_id = LazyAttribute(lambda o: f"ipv4-addr--{o.id}")
    entity_type = "IPv4-Addr"
    event_type = "INTERNAL_ENRICHMENT"
    enrichment_entity = SubFactory(Ipv4EnrichmentEntityFactory)
    stix_entity = SubFactory(StixIpv4EntityFactory, id=SelfAttribute("..entity_id"))
    stix_objects = LazyAttribute(lambda o: [o.stix_entity])


@dataclass
class MetaData:
    mimetype: str
    version: str


class MetaDataFactory(Factory):
    class Meta:
        model = MetaData

    mimetype = "application/json"
    version = Faker("iso8601")


@dataclass
class ImportFile:
    id: str
    name: str
    size: int
    metaData: MetaData
    createdById: str | None = None


@dataclass
class ExternalReference:
    id: str
    source_name: str
    url: str
    entity_type: str
    external_id: str | None = None
    description: str | None = None
    created: str | None = None
    modified: str | None = None
    createdById: str | None = None
    hash: str | None = None
    importFiles: list[ImportFile] | None = None
    importFilesIds: list[str] | None = None
    standard_id: str | None = None


@dataclass
class DomainNameEnrichmentEntity:
    created_at: str
    creators: list[Creator]
    entity_type: str
    externalReferences: list[ExternalReference]
    externalReferencesIds: list[str]
    id: str
    importFiles: list[ImportFile]
    importFilesIds: list[str]
    indicators: list[dict]
    indicatorsIds: list[str]
    objectLabel: list
    objectLabelIds: list[str]
    objectMarking: list
    objectMarkingIds: list[str]
    objectOrganization: list[str]
    observable_value: str
    parent_types: list[str]
    spec_version: str
    standard_id: str
    updated_at: str
    value: str
    x_opencti_score: int
    createdBy: dict = None
    createdById: str | None = None
    x_opencti_description: str | None = None


class ImportFileFactory(Factory):
    class Meta:
        model = ImportFile

    id = Faker("file_path")
    name = Faker("file_name")
    size = Faker("random_int", min=100, max=10000)
    metaData = SubFactory(MetaDataFactory)
    createdById = None


class ExternalReferenceFactory(Factory):
    class Meta:
        model = ExternalReference

    id = Faker("uuid4")
    source_name = "MISP"
    url = Faker("url")
    entity_type = "External-Reference"
    external_id = Faker("uuid4")
    description = Faker("sentence")
    created = Faker("iso8601")
    modified = Faker("iso8601")
    createdById = None
    hash = None
    importFiles = List([SubFactory(ImportFileFactory)])
    importFilesIds = LazyAttribute(
        lambda o: [f.id for f in o.importFiles] if o.importFiles else []
    )
    standard_id = LazyAttribute(lambda o: f"external-reference--{o.id}")


class DomainNameEnrichmentEntityFactory(Factory):
    class Meta:
        model = DomainNameEnrichmentEntity

    created_at = Faker("iso8601")
    creators = List([SubFactory(CreatorFactory)])
    entity_type = "Domain-Name"
    externalReferences = List([SubFactory(ExternalReferenceFactory)])
    externalReferencesIds = LazyAttribute(
        lambda o: [r.id for r in o.externalReferences]
    )
    id = Faker("uuid4")
    importFiles = []
    importFilesIds = []
    indicators = []
    indicatorsIds = []
    objectLabel = []
    objectLabelIds = []
    objectMarking = []
    objectMarkingIds = LazyAttribute(lambda o: [m.id for m in o.objectMarking])
    objectOrganization = []
    observable_value = Faker("domain_name")
    parent_types = [
        "Basic-Object",
        "Stix-Object",
        "Stix-Core-Object",
        "Stix-Cyber-Observable",
    ]
    spec_version = "2.1"
    standard_id = LazyAttribute(lambda o: f"domain-name--{o.id}")
    updated_at = Faker("iso8601")
    value = SelfAttribute("observable_value")
    x_opencti_score = Faker("random_int", min=0, max=100)
    createdBy = None
    createdById = LazyAttribute(
        lambda o: o.createdBy.x_opencti_id if o.createdBy else None
    )
    x_opencti_description = Faker("sentence")


@dataclass
class StixDomainNameEntity:
    id: str
    x_opencti_score: int
    x_opencti_description: str
    value: str
    x_opencti_id: str
    x_opencti_type: str
    type: str
    external_references: list[StixExternalReference]
    x_opencti_labels: list[str]
    spec_version: str = "2.1"


class StixDomainNameEntityFactory(Factory):
    class Meta:
        model = StixDomainNameEntity

    id = Faker("uuid4")
    x_opencti_score = Faker("random_int", min=0, max=100)
    x_opencti_description = Faker("sentence")
    value = Faker("domain_name")
    x_opencti_id = SelfAttribute("id")
    x_opencti_type = "Domain-Name"
    type = "domain-name"
    external_references = List([SubFactory(StixExternalReferenceFactory)])
    x_opencti_labels = List([Faker("word")])


class DomainNameEnrichmentFactory(Factory):
    def __new__(cls, *args, **kwargs) -> EnrichmentMessage:
        return super().__new__(*args, **kwargs)

    class Meta:
        model = EnrichmentMessage

    id = Faker("uuid4")
    entity_id = LazyAttribute(lambda o: f"domain-name--{o.id}")
    entity_type = "Domain-Name"
    event_type = "INTERNAL_ENRICHMENT"
    enrichment_entity = SubFactory(DomainNameEnrichmentEntityFactory)
    stix_entity = SubFactory(
        StixDomainNameEntityFactory, id=SelfAttribute("..entity_id")
    )
    stix_objects = LazyAttribute(lambda o: [o.stix_entity])

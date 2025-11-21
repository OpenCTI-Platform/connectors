import base64
from dataclasses import asdict, dataclass
from urllib.parse import urlparse

import factory
from factory import fuzzy

CLASSIFICATIONS = ["MALICIOUS", "SUSPICIOUS", "GOODWARE", "HARMLESS", "UNKNOWN"]
MALWARE_NAMES = [
    "Keitaro",
    "Tactical RMM",
    "Gophish",
]
MALWARE_SUBSYSTEMS = [
    "C2",
    "Exploit Server",
    "Infrastructure",
]


@dataclass
class DownloadedFile:
    sha1: str
    last_download_url: str
    classification: str
    first_download: str
    last_seen: str
    sample_size: int
    sample_available: bool
    last_download: str
    first_seen: str
    sha256: str
    md5: str
    risk_score: int
    sample_type: str
    threat_name: str
    malware_family: str
    malware_type: str
    platform: str
    subplatform: str


@dataclass
class DownloadedFilesResponse:
    next_page: str
    downloaded_files: list[DownloadedFile]
    requested_ip: str


class DownloadedFileFactory(factory.Factory):
    class Meta:
        model = DownloadedFile

    sha1 = factory.Faker("sha1")
    last_download_url = factory.Faker("uri")
    classification = "malicious"
    first_download = factory.Faker("iso8601")
    last_seen = factory.Faker("iso8601")
    sample_size = factory.Faker("random_int", min=1, max=100000)
    sample_available = factory.Faker("boolean")
    last_download = factory.Faker("iso8601")
    first_seen = factory.Faker("iso8601")
    sha256 = factory.Faker("sha256")
    md5 = factory.Faker("md5")
    risk_score = factory.Faker("random_int", min=1, max=10)
    sample_type = "Text/HTML/HTML"
    threat_name = factory.LazyAttribute(
        lambda o: f"{o.platform}-{o.subplatform}.{o.malware_type}.{o.malware_family}"
    )
    malware_family = fuzzy.FuzzyChoice(MALWARE_NAMES)
    malware_type = fuzzy.FuzzyChoice(MALWARE_SUBSYSTEMS)
    platform = "MacOS"
    subplatform = factory.Faker("mac_platform_token")


class DownloadedFilesResponseFactory(factory.Factory):
    class Meta:
        model = DownloadedFilesResponse

    next_page = None
    downloaded_files = factory.List(
        [factory.SubFactory(DownloadedFileFactory) for _ in range(3)]
    )
    requested_ip = factory.Faker("ipv4")


@dataclass
class ThirdPartySource:
    detection: str
    update_time: str
    detect_time: str
    categories: list[str]
    source: str


DETECTION_TYPES = ["malicious", "suspicious", "clean", "undetected"]
SOURCE_CATEGORIES = [
    "phishing",
    "spam",
    "suspicious",
    "scam_illegal_unethical",
    "business_economy",
    "uncategorized",
]
SOURCES = ["cyradar", "crdf", "levelblue", "asimily", "criminalip", "apwg", "cyren"]


class ThirdPartySourceFactory(factory.Factory):
    class Meta:
        model = ThirdPartySource

    detection = fuzzy.FuzzyChoice(DETECTION_TYPES)
    update_time = factory.Faker("iso8601")
    detect_time = factory.Faker("iso8601")
    categories = factory.List([fuzzy.FuzzyChoice(SOURCE_CATEGORIES) for _ in range(2)])
    source = fuzzy.FuzzyChoice(SOURCES)


@dataclass
class ThirdPartyStatistics:
    malicious: int
    suspicious: int
    clean: int
    undetected: int
    total: int


@dataclass
class ThirdPartyReputation:
    sources: list[ThirdPartySource]
    statistics: ThirdPartyStatistics


class ThirdPartyReputationFactory(factory.Factory):
    class Meta:
        model = ThirdPartyReputation

    sources = factory.List(
        [factory.SubFactory(ThirdPartySourceFactory) for _ in range(10)]
    )
    statistics = factory.LazyAttribute(
        lambda o: ThirdPartyStatistics(
            malicious=len([s for s in o.sources if s.detection == "malicious"]),
            suspicious=len([s for s in o.sources if s.detection == "suspicious"]),
            clean=len([s for s in o.sources if s.detection == "clean"]),
            undetected=len([s for s in o.sources if s.detection == "undetected"]),
            total=len(o.sources),
        )
    )


@dataclass
class DownloadedFilesStatistics:
    total: int
    unknown: int
    suspicious: int
    malicious: int
    goodware: int


class DownloadedFilesStatisticsFactory(factory.Factory):
    class Meta:
        model = DownloadedFilesStatistics

    unknown = factory.Faker("random_int", min=1, max=10)
    suspicious = factory.Faker("random_int", min=1, max=10)
    malicious = factory.Faker("random_int", min=1, max=10)
    goodware = factory.Faker("random_int", min=1, max=10)
    total = factory.LazyAttribute(
        lambda o: sum([o.unknown, o.suspicious, o.malicious, o.goodware])
    )


@dataclass
class TopThreat:
    risk_score: int
    files_count: int
    threat_name: str
    _malware_family: str
    _malware_type: str
    _subplatform: str


class TopThreatFactory(factory.Factory):
    class Meta:
        model = TopThreat

    risk_score = factory.Faker("random_int", min=1, max=10)
    files_count = factory.Faker("random_int", min=1, max=5)
    threat_name = factory.LazyAttribute(
        lambda o: f"MacOS-{o._subplatform}.{o._malware_type}.{o._malware_family}"
    )
    _malware_family = fuzzy.FuzzyChoice(MALWARE_NAMES)
    _malware_type = fuzzy.FuzzyChoice(MALWARE_SUBSYSTEMS)
    _subplatform = factory.Faker("mac_platform_token")


@dataclass
class ReportResponse:
    third_party_reputations: ThirdPartyReputation
    downloaded_files_statistics: DownloadedFilesStatistics
    top_threats: list[TopThreat]
    requested_ip: str
    modified_time: str


class ReportResponseFactory(factory.Factory):
    class Meta:
        model = ReportResponse

    third_party_reputations = ThirdPartyReputationFactory()
    downloaded_files_statistics = DownloadedFilesStatisticsFactory()
    top_threats = factory.List([factory.SubFactory(TopThreatFactory) for _ in range(3)])
    requested_ip = factory.Faker("ipv4")
    modified_time = factory.Faker("iso8601")


@dataclass
class Resolution:
    provider: str
    last_resolution_time: str
    host_name: str


class ResolutionFactory(factory.Factory):
    class Meta:
        model = Resolution

    provider = "ReversingLabs"
    last_resolution_time = factory.Faker("iso8601")
    host_name = factory.Faker("domain_name")


@dataclass
class ResolutionResponse:
    next_page: str
    resolutions: list[Resolution]
    requested_ip: str


class ResolutionResponseFactory(factory.Factory):
    class Meta:
        model = ResolutionResponse

    next_page = None
    resolutions = factory.List(
        [factory.SubFactory(ResolutionFactory) for _ in range(10)]
    )
    requested_ip = factory.Faker("ipv4")


@dataclass
class Url:
    url: str


class UrlFactory(factory.Factory):
    class Meta:
        model = Url

    url = factory.Faker("uri")


@dataclass
class UrlsResponse:
    next_page: str
    urls: list[Url]
    requested_ip: str


class UrlsResponseFactory(factory.Factory):
    class Meta:
        model = UrlsResponse

    next_page = None
    urls = factory.List([factory.SubFactory(UrlFactory) for _ in range(15)])
    requested_ip = factory.Faker("ipv4")


@dataclass
class DNSRecord:
    type: str
    value: str
    provider: str


class DNSRecordFactory(factory.Factory):
    class Meta:
        model = DNSRecord

    type = "A"
    value = factory.Faker("ipv4")
    provider = "ReversingLabs"


@dataclass
class DomainResponse:
    last_dns_records: list[DNSRecord]
    last_dns_records_time: str
    third_party_reputations: ThirdPartyReputation
    downloaded_files_statistics: DownloadedFilesStatistics
    top_threats: list[TopThreat]
    requested_domain: str


class DomainResponseFactory(factory.Factory):
    class Meta:
        model = DomainResponse

    last_dns_records = factory.List(
        [factory.SubFactory(DNSRecordFactory) for _ in range(3)]
    )
    last_dns_records_time = factory.Faker("iso8601")
    third_party_reputations = ThirdPartyReputationFactory()
    downloaded_files_statistics = DownloadedFilesStatisticsFactory()
    top_threats = factory.List([factory.SubFactory(TopThreatFactory) for _ in range(3)])
    requested_domain = factory.Faker("domain_name")


@dataclass
class AnalysisHistoryItem:
    analysis_id: str
    analysis_time: str
    http_response_code: int
    availability_status: str
    domain: str
    serving_ip_address: str


class AnalysisHistoryItemFactory(factory.Factory):
    class Meta:
        model = AnalysisHistoryItem

    analysis_id = factory.Faker("pystr")
    analysis_time = factory.Faker("iso8601")
    http_response_code = factory.Faker("random_int", min=1, max=200)
    availability_status = "online"
    domain = factory.Faker("domain_name")
    serving_ip_address = factory.Faker("ipv4")


@dataclass
class Analysis:
    first_analysis: str
    analysis_history: list[AnalysisHistoryItem]
    last_analysis: AnalysisHistoryItem
    analysis_count: int
    statistics: ThirdPartyStatistics


class AnalysisFactory(factory.Factory):
    class Meta:
        model = Analysis

    first_analysis = factory.Faker("iso8601")
    analysis_history = factory.List(
        [factory.SubFactory(AnalysisHistoryItemFactory) for _ in range(3)]
    )
    last_analysis = factory.LazyAttribute(lambda o: o.analysis_history[-1])
    analysis_count = 3
    statistics = factory.LazyAttribute(
        lambda o: ThirdPartyStatistics(
            malicious=len(
                [a for a in o.analysis_history if a.http_response_code <= 50]
            ),
            suspicious=len(
                [a for a in o.analysis_history if 50 < a.http_response_code <= 100]
            ),
            clean=len(
                [a for a in o.analysis_history if 100 < a.http_response_code <= 150]
            ),
            undetected=len(
                [a for a in o.analysis_history if 150 < a.http_response_code <= 200]
            ),
            total=len(o.analysis_history),
        )
    )


@dataclass
class AnalysisResponse:
    sha1: str
    base64: str
    requested_url: str
    analysis: Analysis
    third_party_reputations: ThirdPartyReputation
    last_seen: str
    first_seen: str
    classification: str
    reason: str
    threat_level: int

    def to_dict(self):
        result = asdict(self)
        domain = urlparse(result["requested_url"]).netloc
        for analysis in result["analysis"]["analysis_history"]:
            analysis["domain"] = domain
        result["analysis"]["last_analysis"] = domain
        return result


class AnalysisResponseFactory(factory.Factory):
    class Meta:
        model = AnalysisResponse

    sha1 = factory.Faker("sha1")
    base64 = factory.LazyAttribute(
        lambda o: base64.b64encode(o.requested_url.encode()).decode()
    )
    requested_url = factory.Faker("uri")
    analysis = factory.SubFactory(AnalysisFactory)
    third_party_reputations = ThirdPartyReputationFactory()
    last_seen = factory.Faker("iso8601")
    first_seen = factory.Faker("iso8601")
    classification = "malicious"
    reason = "file_reputation"
    threat_level = factory.Faker("random_int", min=1, max=10)


@dataclass
class UploadDetail:
    id: int
    sha1: str
    user: int
    created: str
    filename: str
    href: str


class UploadDetailFactory(factory.Factory):
    class Meta:
        model = UploadDetail

    id = factory.Faker("random_int", min=1, max=1000)
    sha1 = factory.Faker("sha1")
    user = factory.Faker("random_int", min=1, max=1000)
    created = factory.Faker("iso8601")
    filename = factory.Faker("file_name")
    href = factory.Faker("uri_path")


@dataclass
class Ticore:
    story: str


class TicoreFactory(factory.Factory):
    class Meta:
        model = Ticore

    story = factory.Faker("sentence")


@dataclass
class ReportIntelligence:
    aliases: list[str]
    classification: str
    sha256: str
    classification_result: str
    file_size: int
    file_type: str
    riskscore: int
    ticore: Ticore
    networkthreatintelligence: AnalysisResponse
    domainthreatintelligence: DomainResponse
    _malware_family: str
    _malware_type: str
    _subplatform: str


class ReportIntelligenceResponseFactory(factory.Factory):
    class Meta:
        model = ReportIntelligence

    aliases = factory.List([factory.Faker("file_name") for _ in range(2)])
    sha256 = factory.Faker("sha256")
    file_size = factory.Faker("random_int", min=1, max=100000)
    file_type = factory.Faker("file_extension")
    riskscore = factory.Faker("random_int", min=1, max=10)
    ticore = factory.SubFactory(TicoreFactory)
    networkthreatintelligence = factory.SubFactory(AnalysisResponseFactory)
    domainthreatintelligence = factory.SubFactory(DomainResponseFactory)
    classification = "malicious"
    classification_result = factory.LazyAttribute(
        lambda o: f"MacOS-{o._subplatform}.{o._malware_type}.{o._malware_family}"
    )
    _malware_family = fuzzy.FuzzyChoice(MALWARE_NAMES)
    _malware_type = fuzzy.FuzzyChoice(MALWARE_SUBSYSTEMS)
    _subplatform = factory.Faker("mac_platform_token")


@dataclass
class HashClassification:
    classification: str
    riskscore: int
    first_seen: str
    last_seen: str
    classification_result: str
    classification_reason: str
    classification_origin: str
    cloud_last_lookup: str
    data_source: str
    sha1: str
    sha256: str
    md5: str
    _malware_family: str
    _malware_type: str
    _subplatform: str


class HashClassificationFactory(factory.Factory):
    class Meta:
        model = HashClassification

    classification = "malicious"
    riskscore = factory.Faker("random_int", min=1, max=10)
    first_seen = factory.Faker("iso8601")
    last_seen = factory.Faker("iso8601")
    classification_result = factory.LazyAttribute(
        lambda o: f"MacOS-{o._subplatform}.{o._malware_type}.{o._malware_family}"
    )
    classification_reason = "file_reputation"
    classification_origin = None
    cloud_last_lookup = factory.Faker("iso8601")
    data_source = "LOCAL"
    sha1 = factory.Faker("sha1")
    sha256 = factory.Faker("sha256")
    md5 = factory.Faker("md5")
    _malware_family = fuzzy.FuzzyChoice(MALWARE_NAMES)
    _malware_type = fuzzy.FuzzyChoice(MALWARE_SUBSYSTEMS)
    _subplatform = factory.Faker("mac_platform_token")


@dataclass
class Creator:
    id: str
    name: str


class CreatorFactory(factory.Factory):
    class Meta:
        model = Creator

    id = factory.Faker("uuid4")
    name = factory.Faker("name")


@dataclass
class MetaData:
    mimetype: str
    version: str


class MetaDataFactory(factory.Factory):
    class Meta:
        model = MetaData

    mimetype = "application/json"
    version = factory.Faker("iso8601")


@dataclass
class ImportFile:
    id: str
    name: str
    size: int
    metaData: MetaData
    createdById: str | None = None


class ImportFileFactory(factory.Factory):
    class Meta:
        model = ImportFile

    id = factory.Faker("file_path")
    name = factory.Faker("file_name")
    size = factory.Faker("random_int", min=100, max=10000)
    metaData = factory.SubFactory(MetaDataFactory)
    createdById = None


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


class ExternalReferenceFactory(factory.Factory):
    class Meta:
        model = ExternalReference

    id = factory.Faker("uuid4")
    source_name = "MISP"
    url = factory.Faker("url")
    entity_type = "External-Reference"
    external_id = factory.Faker("uuid4")
    description = factory.Faker("sentence")
    created = factory.Faker("iso8601")
    modified = factory.Faker("iso8601")
    createdById = None
    hash = None
    importFiles = factory.List([factory.SubFactory(ImportFileFactory)])
    importFilesIds = factory.LazyAttribute(
        lambda o: [f.id for f in o.importFiles] if o.importFiles else []
    )
    standard_id = factory.LazyAttribute(lambda o: f"external-reference--{o.id}")


@dataclass
class Hash:
    algorithm: str
    hash: str


class HashFactory(factory.Factory):
    class Meta:
        model = Hash

    algorithm = "SHA-1"
    hash = factory.Faker("sha1")


@dataclass
class EnrichmentEntity:
    created_at: str
    creators: list[Creator]
    entity_type: str
    externalReferences: list[ExternalReference]
    externalReferencesIds: list[str]
    hashes: list[dict]
    id: str
    importFiles: list[ImportFile]
    importFilesIds: list[str]
    indicators: list[dict]
    indicatorsIds: list[str]
    magic_number_hex: str
    mime_type: str
    name: str
    name_enc: str
    objectLabel: list[str]
    objectLabelIds: list[str]
    objectMarking: list[str]
    objectMarkingIds: list[str]
    objectOrganization: list[str]
    observable_value: str
    parent_types: list[str]
    spec_version: str
    standard_id: str
    updated_at: str
    x_opencti_score: int
    atime: str | None = None
    createdBy: str | None = None
    createdById: str | None = None
    ctime: str | None = None
    extensions: str | None = None
    mtime: str | None = None
    size: int | None = None
    x_opencti_additional_names: list[str] | None = None
    x_opencti_description: str | None = None


class EnrichmentEntityFactory(factory.Factory):
    class Meta:
        model = EnrichmentEntity

    created_at = factory.Faker("iso8601")
    creators = factory.List([factory.SubFactory(CreatorFactory)])
    entity_type = "StixFile"
    externalReferences = factory.List([factory.SubFactory(ExternalReferenceFactory)])
    externalReferencesIds = factory.LazyAttribute(
        lambda o: [r.id for r in o.externalReferences]
    )
    hashes = factory.List([factory.SubFactory(HashFactory)])
    id = factory.Faker("uuid4")
    importFiles = factory.List([factory.SubFactory(ImportFileFactory)])
    importFilesIds = factory.LazyAttribute(lambda o: [f.id for f in o.importFiles])
    indicators = []
    indicatorsIds = []
    magic_number_hex = ""
    mime_type = ""
    name = factory.Faker("file_name")
    name_enc = ""
    objectLabel = []
    objectLabelIds = []
    objectMarking = []
    objectMarkingIds = []
    objectOrganization = []
    observable_value = factory.SelfAttribute("name")
    parent_types = [
        "Basic-Object",
        "Stix-Object",
        "Stix-Core-Object",
        "Stix-Cyber-Observable",
    ]
    spec_version = "2.1"
    standard_id = factory.LazyAttribute(lambda o: f"file--{o.id}")
    updated_at = factory.Faker("iso8601")
    x_opencti_score = factory.Faker("random_int", min=0, max=100)
    atime = None
    createdBy = None
    createdById = None
    ctime = None
    extensions = None
    mtime = None
    size = None
    x_opencti_additional_names = None
    x_opencti_description = None


@dataclass
class StixFile:
    data: str
    mime_type: str
    name: str
    version: str


class StixFileFactory(factory.Factory):
    class Meta:
        model = StixFile

    data = factory.Faker("pystr")
    mime_type = "image/jpeg"
    name = factory.Faker("file_name")
    version = factory.Faker("iso8601")


@dataclass
class StixExternalReference:
    description: str
    external_id: str
    source_name: str
    url: str
    x_opencti_files: list[StixFile]


class StixExternalReferenceFactory(factory.Factory):
    class Meta:
        model = StixExternalReference

    description = factory.Faker("sentence")
    external_id = factory.Faker("uuid4")
    source_name = "MISP"
    url = factory.Faker("url")
    x_opencti_files = factory.List([factory.SubFactory(StixFileFactory)])


@dataclass
class StixEntity:
    id: str
    x_opencti_score: int
    name: str
    x_opencti_id: str
    x_opencti_type: str
    type: str
    external_references: list[StixExternalReference]
    x_opencti_files: list[StixFile]
    spec_version: str = "2.1"


class StixEntityFactory(factory.Factory):
    class Meta:
        model = StixEntity

    id = factory.Faker("uuid4")
    x_opencti_score = factory.Faker("random_int", min=0, max=100)
    name = factory.Faker("file_name")
    x_opencti_id = factory.SelfAttribute("id")
    x_opencti_type = "StixFile"
    type = "File"
    external_references = factory.List(
        [factory.SubFactory(StixExternalReferenceFactory)]
    )
    x_opencti_files = factory.List([factory.SubFactory(StixFileFactory)])


@dataclass
class EnrichmentMessage:
    id: str
    entity_id: str
    event_type: str
    entity_type: str
    enrichment_entity: EnrichmentEntity
    stix_entity: StixEntity
    stix_objects: list[StixEntity]


class FileEnrichmentFactory(factory.Factory):
    class Meta:
        model = EnrichmentMessage

    id = factory.Faker("uuid4")
    entity_id = factory.LazyAttribute(lambda o: f"file--{o.id}")
    entity_type = "StixFile"
    event_type = "INTERNAL_ENRICHMENT"
    enrichment_entity = factory.SubFactory(EnrichmentEntityFactory)
    stix_entity = factory.SubFactory(
        StixEntityFactory, id=factory.SelfAttribute("..entity_id")
    )
    stix_objects = factory.LazyAttribute(lambda o: [o.stix_entity])

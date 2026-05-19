from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class IntCoercingStrEnum(StrEnum):
    @classmethod
    def _missing_(cls, value):
        """Try to coerce int to str before failing.

        :param value: Value passed to enum constructor.
        :return: Enum member if coercion succeeds.
        """
        if isinstance(value, int):
            return cls(str(value))
        return super()._missing_(value)


class AnalysisLevelId(IntCoercingStrEnum):
    level_0 = "0"
    level_1 = "1"
    level_2 = "2"


class AttributeType(StrEnum):
    md5 = "md5"
    sha1 = "sha1"
    sha256 = "sha256"
    filename = "filename"
    pdb = "pdb"
    filename_md5 = "filename|md5"
    filename_sha1 = "filename|sha1"
    filename_sha256 = "filename|sha256"
    ip_src = "ip-src"
    ip_dst = "ip-dst"
    hostname = "hostname"
    domain = "domain"
    domain_ip = "domain|ip"
    email = "email"
    email_src = "email-src"
    eppn = "eppn"
    email_dst = "email-dst"
    email_subject = "email-subject"
    email_attachment = "email-attachment"
    email_body = "email-body"
    float = "float"
    git_commit_id = "git-commit-id"
    url = "url"
    http_method = "http-method"
    user_agent = "user-agent"
    ja3_fingerprint_md5 = "ja3-fingerprint-md5"
    jarm_fingerprint = "jarm-fingerprint"
    favicon_mmh3 = "favicon-mmh3"
    hassh_md5 = "hassh-md5"
    hasshserver_md5 = "hasshserver-md5"
    regkey = "regkey"
    regkey_value = "regkey|value"
    AS = "AS"
    snort = "snort"
    bro = "bro"
    zeek = "zeek"
    community_id = "community-id"
    pattern_in_file = "pattern-in-file"
    pattern_in_traffic = "pattern-in-traffic"
    pattern_in_memory = "pattern-in-memory"
    pattern_filename = "pattern-filename"
    pgp_public_key = "pgp-public-key"
    pgp_private_key = "pgp-private-key"
    yara = "yara"
    stix2_pattern = "stix2-pattern"
    sigma = "sigma"
    gene = "gene"
    kusto_query = "kusto-query"
    mime_type = "mime-type"
    identity_card_number = "identity-card-number"
    cookie = "cookie"
    vulnerability = "vulnerability"
    cpe = "cpe"
    weakness = "weakness"
    attachment = "attachment"
    malware_sample = "malware-sample"
    link = "link"
    comment = "comment"
    text = "text"
    hex = "hex"
    other = "other"
    named_pipe = "named pipe"
    mutex = "mutex"
    process_state = "process-state"
    target_user = "target-user"
    target_email = "target-email"
    target_machine = "target-machine"
    target_org = "target-org"
    target_location = "target-location"
    target_external = "target-external"
    btc = "btc"
    dash = "dash"
    xmr = "xmr"
    iban = "iban"
    bic = "bic"
    bank_account_nr = "bank-account-nr"
    aba_rtn = "aba-rtn"
    bin = "bin"
    cc_number = "cc-number"
    prtn = "prtn"
    phone_number = "phone-number"
    threat_actor = "threat-actor"
    campaign_name = "campaign-name"
    campaign_id = "campaign-id"
    malware_type = "malware-type"
    uri = "uri"
    authentihash = "authentihash"
    vhash = "vhash"
    ssdeep = "ssdeep"
    imphash = "imphash"
    telfhash = "telfhash"
    pehash = "pehash"
    impfuzzy = "impfuzzy"
    sha224 = "sha224"
    sha384 = "sha384"
    sha512 = "sha512"
    sha512_224 = "sha512/224"
    sha512_256 = "sha512/256"
    sha3_224 = "sha3-224"
    sha3_256 = "sha3-256"
    sha3_384 = "sha3-384"
    sha3_512 = "sha3-512"
    tlsh = "tlsh"
    cdhash = "cdhash"
    filename_authentihash = "filename|authentihash"
    filename_vhash = "filename|vhash"
    filename_ssdeep = "filename|ssdeep"
    filename_imphash = "filename|imphash"
    filename_impfuzzy = "filename|impfuzzy"
    filename_pehash = "filename|pehash"
    filename_sha224 = "filename|sha224"
    filename_sha384 = "filename|sha384"
    filename_sha512 = "filename|sha512"
    filename_sha512_224 = "filename|sha512/224"
    filename_sha512_256 = "filename|sha512/256"
    filename_sha3_224 = "filename|sha3-224"
    filename_sha3_256 = "filename|sha3-256"
    filename_sha3_384 = "filename|sha3-384"
    filename_sha3_512 = "filename|sha3-512"
    filename_tlsh = "filename|tlsh"
    windows_scheduled_task = "windows-scheduled-task"
    windows_service_name = "windows-service-name"
    windows_service_displayname = "windows-service-displayname"
    whois_registrant_email = "whois-registrant-email"
    whois_registrant_phone = "whois-registrant-phone"
    whois_registrant_name = "whois-registrant-name"
    whois_registrant_org = "whois-registrant-org"
    whois_registrar = "whois-registrar"
    whois_creation_date = "whois-creation-date"
    x509_fingerprint_sha1 = "x509-fingerprint-sha1"
    x509_fingerprint_md5 = "x509-fingerprint-md5"
    x509_fingerprint_sha256 = "x509-fingerprint-sha256"
    dns_soa_email = "dns-soa-email"
    size_in_bytes = "size-in-bytes"
    counter = "counter"
    datetime = "datetime"
    port = "port"
    ip_dst_port = "ip-dst|port"
    ip_src_port = "ip-src|port"
    hostname_port = "hostname|port"
    mac_address = "mac-address"
    mac_eui_64 = "mac-eui-64"
    email_dst_display_name = "email-dst-display-name"
    email_src_display_name = "email-src-display-name"
    email_header = "email-header"
    email_reply_to = "email-reply-to"
    email_x_mailer = "email-x-mailer"
    email_mime_boundary = "email-mime-boundary"
    email_thread_index = "email-thread-index"
    email_message_id = "email-message-id"
    github_username = "github-username"
    github_repository = "github-repository"
    github_organisation = "github-organisation"
    jabber_id = "jabber-id"
    twitter_id = "twitter-id"
    dkim = "dkim"
    dkim_signature = "dkim-signature"
    first_name = "first-name"
    middle_name = "middle-name"
    last_name = "last-name"
    full_name = "full-name"
    date_of_birth = "date-of-birth"
    place_of_birth = "place-of-birth"
    gender = "gender"
    passport_number = "passport-number"
    passport_country = "passport-country"
    passport_expiration = "passport-expiration"
    redress_number = "redress-number"
    nationality = "nationality"
    visa_number = "visa-number"
    issue_date_of_the_visa = "issue-date-of-the-visa"
    primary_residence = "primary-residence"
    country_of_residence = "country-of-residence"
    special_service_request = "special-service-request"
    frequent_flyer_number = "frequent-flyer-number"
    travel_details = "travel-details"
    payment_details = "payment-details"
    place_port_of_original_embarkation = "place-port-of-original-embarkation"
    place_port_of_clearance = "place-port-of-clearance"
    place_port_of_onward_foreign_destination = (
        "place-port-of-onward-foreign-destination"
    )
    passenger_name_record_locator_number = "passenger-name-record-locator-number"
    mobile_application_id = "mobile-application-id"
    chrome_extension_id = "chrome-extension-id"
    cortex = "cortex"
    boolean = "boolean"
    anonymised = "anonymised"


class AttributeCategory(StrEnum):
    Internal_reference = "Internal reference"
    Targeting_data = "Targeting data"
    Antivirus_detection = "Antivirus detection"
    Payload_delivery = "Payload delivery"
    Artifacts_dropped = "Artifacts dropped"
    Payload_installation = "Payload installation"
    Persistence_mechanism = "Persistence mechanism"
    Network_activity = "Network activity"
    Payload_type = "Payload type"
    Attribution = "Attribution"
    External_analysis = "External analysis"
    Financial_fraud = "Financial fraud"
    Support_Tool = "Support Tool"
    Social_network = "Social network"
    Person = "Person"
    Other = "Other"


class DistributionLevelId(IntCoercingStrEnum):
    level_0 = "0"
    level_1 = "1"
    level_2 = "2"
    level_3 = "3"
    level_4 = "4"
    level_5 = "5"


class FeedSourceFormat(StrEnum):
    field_1 = "1"
    csv = "csv"
    freetext = "freetext"
    misp = "misp"


class FeedInputSource(StrEnum):
    local = "local"
    network = "network"


class Formula(StrEnum):
    Polynomial = "Polynomial"


class ThreatLevelId(IntCoercingStrEnum):
    level_1 = "1"
    level_2 = "2"
    level_3 = "3"
    level_4 = "4"


class MISPBaseModel(BaseModel):
    model_config = ConfigDict(
        extra="allow",
        frozen=True,
        arbitrary_types_allowed=True,
        use_enum_values=True,
        coerce_numbers_to_str=True,
    )


class DecayingModelParameters(MISPBaseModel):
    lifetime: float | None = Field(default=None)
    decay_speed: float | None = Field(default=None)
    threshold: float | None = Field(default=None)
    default_base_score: float | None = Field(default=None)
    base_score_config: dict[str, Any] | None = Field(
        default=None,
        example={
            "estimative-language:confidence-in-analytic-judgment": 0.25,
            "estimative-language:likelihood-probability": 0.25,
            "phishing:psychological-acceptability": 0.25,
            "phishing:state": 0.2,
        },
    )


class ExtendedDecayingModel(MISPBaseModel):
    id: str | None = Field(default=None)
    uuid: str | None = Field(default=None)
    name: str | None = Field(default=None)
    description: str | None = Field(None)
    parameters: DecayingModelParameters | None = Field(default=None)
    attribute_types: list[AttributeType] | None = Field(default=None)
    org_id: str | None = Field(default=None)
    enabled: bool | None = Field(default=None)
    all_orgs: bool | None = Field(default=None)
    ref: list[str] | None = Field(default=None)
    formula: Formula | None = Field(default=None)
    version: str | None = Field(default=None)
    default: bool | None = Field(default=None)
    isEditable: bool | None = Field(default=None)


class DecayScore(MISPBaseModel):
    score: float | None = Field(default=None)
    base_score: float | None = Field(default=None)
    decayed: bool | None = Field(default=None)
    DecayingModel: ExtendedDecayingModel | None = Field(default=None)


class ExtendedAttributeItem(MISPBaseModel):
    id: str | None = Field(default=None)
    event_id: str | None = Field(default=None)
    object_id: str | None = Field(default=None)
    object_relation: str | None = Field(default=None)
    category: AttributeCategory | None = Field(default=None)
    type: AttributeType | None = Field(default=None)
    value: str | None = Field(default=None)
    to_ids: bool | None = Field(default=True)
    uuid: str | None = Field(default=None)
    timestamp: str | None = Field(default="0")
    distribution: DistributionLevelId | None = Field(default=None)
    sharing_group_id: str | None = Field(default=None)
    comment: str | None = Field(default=None)
    deleted: bool | None = Field(default=False)
    disable_correlation: bool | None = Field(default=False)
    first_seen: str | datetime | None = Field(default=None)
    last_seen: str | datetime | None = Field(default=None)
    Tag: list["TagItem"] | None = Field(default=None)
    Galaxy: list["GalaxyItem"] | None = Field(default=None)
    data: str | None = Field(default=None)
    event_uuid: str | None = Field(default=None)
    decay_score: list[DecayScore] | None = Field(default=None)


class GalaxyItem(MISPBaseModel):
    id: str | None = Field(default=None)
    uuid: str | None = Field(default=None)
    name: str | None = Field(default=None)
    type: str | None = Field(default=None)
    description: str | None = Field(default=None)
    version: str | None = Field(default=None)
    icon: str | None = Field(default=None)
    namespace: str | None = Field(default=None)
    kill_chain_order: dict[str, Any] | None = Field(
        default=None,
        example={
            "fraud-tactics": [
                "Initiation",
                "Target Compromise",
                "Perform Fraud",
                "Obtain Fraudulent Assets",
                "Assets Transfer",
                "Monetisation",
            ]
        },
    )
    GalaxyCluster: list[dict[str, Any]] | None = Field(default=None)


class ObjectItemObjectReference(MISPBaseModel):
    id: str | None = Field(default=None)
    uuid: str | None = Field(default=None)
    timestamp: str | None = Field(default=None)
    object_id: str | None = Field(default=None)
    referenced_id: str | None = Field(default=None)
    referenced_uuid: str | None = Field(default=None)
    reference_type: str | None = Field(default=None)
    relationship_type: str | None = Field(default=None)
    comment: str | None = Field(default=None)
    deleted: bool | None = Field(default=None)
    event_id: str | None = Field(default=None)
    source_uuid: str | None = Field(default=None)
    Attribute: ExtendedAttributeItem | None = Field(default=None)


class ObjectItem(MISPBaseModel):
    id: str | None = Field(default=None)
    name: str | None = Field(default=None)
    meta_category: str | None = Field(default=None, alias="meta-category")
    description: str | None = Field(default=None)
    template_uuid: str | None = Field(default=None)
    template_version: str | None = Field(default=None)
    event_id: str | None = Field(default=None)
    uuid: str | None = Field(default=None)
    timestamp: str | None = Field(default="0")
    distribution: DistributionLevelId | None = Field(default=None)
    sharing_group_id: str | None = Field(default=None)
    comment: str | None = Field(default=None)
    deleted: bool | None = Field(default=None)
    first_seen: str | datetime | None = Field(default=None)
    last_seen: str | datetime | None = Field(default=None)
    Attribute: list[ExtendedAttributeItem] | None = Field(default=None)
    ObjectReference: list[ObjectItemObjectReference] | None = Field(default=None)


class TagItem(MISPBaseModel):
    id: str | None = Field(default=None)
    name: str | None = Field(default=None)
    colour: str | None = Field(default=None)
    exportable: bool | None = Field(default=True)
    org_id: str | None = Field(default=None)
    user_id: str | None = Field(default=None)
    hide_tag: bool | None = Field(default=False)
    numerical_value: str | None = Field(default=None)
    is_galaxy: bool | None = Field(default=True)
    is_custom_galaxy: bool | None = Field(default=True)
    inherited: bool | None = Field(default=True)


class EventFeed(MISPBaseModel):
    id: str | None = Field(default=None)
    name: str | None = Field(default=None)
    provider: str | None = Field(default=None)
    url: str | None = Field(default=None)
    rules: str | None = Field(default=None)
    enabled: bool | None = Field(default=None)
    distribution: DistributionLevelId | None = Field(default=None)
    sharing_group_id: str | None = Field(default=None)
    tag_id: str | None = Field(default=None)
    default: bool | None = Field(default=None)
    source_format: FeedSourceFormat | None = Field(default=None)
    fixed_event: bool | None = Field(default=None)
    delta_merge: bool | None = Field(default=None)
    event_id: str | None = Field(default=None)
    publish: bool | None = Field(default=False)
    override_ids: bool | None = Field(default=None)
    settings: str | None = Field(default=None)
    input_source: FeedInputSource | None = Field(default=None)
    delete_local_file: bool | None = Field(default=None)
    lookup_visible: bool | None = Field(default=None)
    headers: str | None = Field(default=None)
    caching_enabled: bool | None = Field(default=None)
    force_to_ids: bool | None = Field(default=None)
    orgc_id: str | None = Field(default=None)
    cache_timestamp: str | bool | None = Field(default=None)


class EventOrganisation(MISPBaseModel):
    id: str | None = Field(default=None)
    name: str | None = Field(default=None)
    uuid: str | None = Field(default=None)


class EventReportItem(MISPBaseModel):
    id: str | None = Field(default=None)
    uuid: str | None = Field(default=None)
    event_id: str | None = Field(default=None)
    name: str | None = Field(default=None)
    content: str | None = Field(default=None)
    distribution: DistributionLevelId | None = Field(default=None)
    sharing_group_id: str | None = Field(default=None)
    timestamp: str | None = Field(default="0")
    deleted: bool | None = Field(default=False)


class ExtendedEvent(MISPBaseModel):
    id: str | None = Field(default=None)
    org_id: str | None = Field(default=None)
    distribution: DistributionLevelId | None = Field(default=None)
    info: str | None = Field(default=None)
    orgc_id: str | None = Field(default=None)
    orgc_uuid: str | None = Field(default=None)  # from SlimEvent
    uuid: str | None = Field(default=None)
    date: str | None = Field(default=None, example="1991-01-15")
    published: bool | None = Field(default=False)
    analysis: AnalysisLevelId | None = Field(default=None)
    attribute_count: str | None = Field(default=None)
    timestamp: str | None = Field(default="0")
    sharing_group_id: str | None = Field(default=None)
    proposal_email_lock: bool | None = Field(default=None)
    locked: bool | None = Field(default=None)
    threat_level_id: ThreatLevelId | None = Field(default=None)
    publish_timestamp: str | None = Field(default="0")
    sighting_timestamp: str | None = Field(default="0")
    disable_correlation: bool | None = Field(default=False)
    extends_uuid: str | None = Field(default=None)
    event_creator_email: str | None = Field(default=None)
    Feed: EventFeed | None = Field(default=None)
    Org: EventOrganisation | None = Field(default=None)
    Orgc: EventOrganisation | None = Field(default=None)
    Attribute: list[ExtendedAttributeItem] | None = Field(default=None)
    ShadowAttribute: list[ExtendedAttributeItem] | None = Field(default=None)
    RelatedEvent: list["RelatedEventItem"] | None = Field(default=None)
    Galaxy: list[GalaxyItem] | None = Field(default=None)
    Object: list[ObjectItem] | None = Field(default=None)
    EventReport: list[EventReportItem] | None = Field(default=None)
    Tag: list[TagItem] | None = Field(default=None)


class RelatedEventItem(MISPBaseModel):
    Event: ExtendedEvent | None = Field(default=None)


class EventRestSearchListItem(MISPBaseModel):
    Event: ExtendedEvent | None = Field(default=None)

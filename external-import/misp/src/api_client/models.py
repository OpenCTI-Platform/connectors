from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Union

from pydantic import BaseModel, ConfigDict, Field


class AnalysisLevelId(Enum):
    field_0 = "0"
    field_1 = "1"
    field_2 = "2"


class AttributeType(Enum):
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


class AttributeCategory(Enum):
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


class DistributionLevelId(Enum):
    field_0 = "0"
    field_1 = "1"
    field_2 = "2"
    field_3 = "3"
    field_4 = "4"
    field_5 = "5"


class FeedSourceFormat(Enum):
    field_1 = "1"
    csv = "csv"
    freetext = "freetext"
    misp = "misp"


class FeedInputSource(Enum):
    local = "local"
    network = "network"


class Formula(Enum):
    Polynomial = "Polynomial"


class ThreatLevelId(Enum):
    field_1 = "1"
    field_2 = "2"
    field_3 = "3"
    field_4 = "4"


class MISPBaseModel(BaseModel):
    model_config = ConfigDict(
        extra="allow",
        frozen=True,
        arbitrary_types_allowed=True,
        use_enum_values=True,
    )


class DecayingModelParameters(MISPBaseModel):
    lifetime: Optional[float] = Field(default=None)
    decay_speed: Optional[float] = Field(default=None)
    threshold: Optional[float] = Field(default=None)
    default_base_score: Optional[float] = Field(default=None)
    base_score_config: Optional[Dict[str, Any]] = Field(
        default=None,
        example={
            "estimative-language:confidence-in-analytic-judgment": 0.25,
            "estimative-language:likelihood-probability": 0.25,
            "phishing:psychological-acceptability": 0.25,
            "phishing:state": 0.2,
        },
    )


class ExtendedDecayingModel(MISPBaseModel):
    id: Optional[str] = Field(default=None)
    uuid: Optional[str] = Field(default=None)
    name: Optional[str] = Field(default=None)
    description: Optional[str] = Field(None)
    parameters: Optional[DecayingModelParameters] = Field(default=None)
    attribute_types: Optional[List[AttributeType]] = Field(default=None)
    org_id: Optional[str] = Field(default=None)
    enabled: Optional[bool] = Field(default=None)
    all_orgs: Optional[bool] = Field(default=None)
    ref: Optional[List[str]] = Field(default=None)
    formula: Optional[Formula] = Field(default=None)
    version: Optional[str] = Field(default=None)
    default: Optional[bool] = Field(default=None)
    isEditable: Optional[bool] = Field(default=None)


class DecayScore(MISPBaseModel):
    score: Optional[float] = Field(default=None)
    base_score: Optional[float] = Field(default=None)
    decayed: Optional[bool] = Field(default=None)
    DecayingModel: Optional[ExtendedDecayingModel] = Field(default=None)


class ExtendedAttributeItem(MISPBaseModel):
    id: Optional[str] = Field(default=None)
    event_id: Optional[str] = Field(default=None)
    object_id: Optional[str] = Field(default=None)
    object_relation: Optional[str] = Field(default=None)
    category: Optional[AttributeCategory] = Field(default=None)
    type: Optional[AttributeType] = Field(default=None)
    value: Optional[str] = Field(default=None)
    to_ids: Optional[bool] = True
    uuid: Optional[str] = Field(default=None)
    timestamp: Optional[str] = "0"
    distribution: Optional[DistributionLevelId] = Field(default=None)
    sharing_group_id: Optional[str] = Field(default=None)
    comment: Optional[str] = Field(default=None)
    deleted: Optional[bool] = False
    disable_correlation: Optional[bool] = False
    first_seen: Optional[Union[str, datetime]] = Field(default=None)
    last_seen: Optional[Union[str, datetime]] = Field(default=None)
    Tag: Optional[List["TagItem"]] = Field(default=None)
    Galaxy: Optional[List["GalaxyItem"]] = Field(default=None)
    data: Optional[str] = Field(default=None)
    event_uuid: Optional[str] = Field(default=None)
    decay_score: Optional[List[DecayScore]] = Field(default=None)


class GalaxyItem(MISPBaseModel):
    id: Optional[str] = Field(default=None)
    uuid: Optional[str] = Field(default=None)
    name: Optional[str] = Field(default=None)
    type: Optional[str] = Field(default=None)
    description: Optional[str] = Field(default=None)
    version: Optional[str] = Field(default=None)
    icon: Optional[str] = Field(default=None)
    namespace: Optional[str] = Field(default=None)
    kill_chain_order: Optional[Dict[str, Any]] = Field(
        None,
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


class ObjectItem(MISPBaseModel):
    id: Optional[str] = Field(default=None)
    name: Optional[str] = Field(default=None)
    meta_category: Optional[str] = Field(default=None, alias="meta-category")
    description: Optional[str] = Field(default=None)
    template_uuid: Optional[str] = Field(default=None)
    template_version: Optional[str] = Field(default=None)
    event_id: Optional[str] = Field(default=None)
    uuid: Optional[str] = Field(default=None)
    timestamp: Optional[str] = "0"
    distribution: Optional[DistributionLevelId] = Field(default=None)
    sharing_group_id: Optional[str] = Field(default=None)
    comment: Optional[str] = Field(default=None)
    deleted: Optional[bool] = Field(default=None)
    first_seen: Optional[Union[str, datetime]] = Field(default=None)
    last_seen: Optional[Union[str, datetime]] = Field(default=None)
    Attribute: Optional[List[ExtendedAttributeItem]] = Field(default=None)


class TagItem(MISPBaseModel):
    id: Optional[str] = Field(default=None)
    name: Optional[str] = Field(default=None)
    colour: Optional[str] = Field(default=None)
    exportable: Optional[bool] = True
    org_id: Optional[str] = Field(default=None)
    user_id: Optional[str] = Field(default=None)
    hide_tag: Optional[bool] = False
    numerical_value: Optional[str] = Field(default=None)
    is_galaxy: Optional[bool] = True
    is_custom_galaxy: Optional[bool] = True
    inherited: Optional[bool] = True


class EventFeed(MISPBaseModel):
    id: Optional[str] = Field(default=None)
    name: Optional[str] = Field(default=None)
    provider: Optional[str] = Field(default=None)
    url: Optional[str] = Field(default=None)
    rules: Optional[str] = Field(default=None)
    enabled: Optional[bool] = Field(default=None)
    distribution: Optional[DistributionLevelId] = Field(default=None)
    sharing_group_id: Optional[str] = Field(default=None)
    tag_id: Optional[str] = Field(default=None)
    default: Optional[bool] = Field(default=None)
    source_format: Optional[FeedSourceFormat] = Field(default=None)
    fixed_event: Optional[bool] = Field(default=None)
    delta_merge: Optional[bool] = Field(default=None)
    event_id: Optional[str] = Field(default=None)
    publish: Optional[bool] = False
    override_ids: Optional[bool] = Field(default=None)
    settings: Optional[str] = Field(default=None)
    input_source: Optional[FeedInputSource] = Field(default=None)
    delete_local_file: Optional[bool] = Field(default=None)
    lookup_visible: Optional[bool] = Field(default=None)
    headers: Optional[str] = Field(default=None)
    caching_enabled: Optional[bool] = Field(default=None)
    force_to_ids: Optional[bool] = Field(default=None)
    orgc_id: Optional[str] = Field(default=None)
    cache_timestamp: Optional[str | bool] = Field(default=None)


class EventOrganisation(MISPBaseModel):
    id: Optional[str] = Field(default=None)
    name: Optional[str] = Field(default=None)
    uuid: Optional[str] = Field(default=None)


class EventReportItem(MISPBaseModel):
    id: Optional[str] = Field(default=None)
    uuid: Optional[str] = Field(default=None)
    event_id: Optional[str] = Field(default=None)
    name: Optional[str] = Field(default=None)
    content: Optional[str] = Field(default=None)
    distribution: Optional[DistributionLevelId] = Field(default=None)
    sharing_group_id: Optional[str] = Field(default=None)
    timestamp: Optional[str] = "0"
    deleted: Optional[bool] = False


class ExtendedEvent(MISPBaseModel):
    id: Optional[str] = Field(default=None)
    org_id: Optional[str] = Field(default=None)
    distribution: Optional[DistributionLevelId] = Field(default=None)
    info: Optional[str] = Field(default=None)
    orgc_id: Optional[str] = Field(default=None)
    orgc_uuid: Optional[str] = Field(default=None)  # from SlimEvent
    uuid: Optional[str] = Field(default=None)
    date: Optional[str] = Field(default=None, example="1991-01-15")
    published: Optional[bool] = False
    analysis: Optional[AnalysisLevelId] = Field(default=None)
    attribute_count: Optional[str] = Field(default=None)
    timestamp: Optional[str] = "0"
    sharing_group_id: Optional[str] = Field(default=None)
    proposal_email_lock: Optional[bool] = Field(default=None)
    locked: Optional[bool] = Field(default=None)
    threat_level_id: Optional[ThreatLevelId] = Field(default=None)
    publish_timestamp: Optional[str] = "0"
    sighting_timestamp: Optional[str] = "0"
    disable_correlation: Optional[bool] = False
    extends_uuid: Optional[str] = Field(default=None)
    event_creator_email: Optional[str] = Field(default=None)
    Feed: Optional[EventFeed] = Field(default=None)
    Org: Optional[EventOrganisation] = Field(default=None)
    Orgc: Optional[EventOrganisation] = Field(default=None)
    Attribute: Optional[List[ExtendedAttributeItem]] = Field(default=None)
    ShadowAttribute: Optional[List[ExtendedAttributeItem]] = Field(default=None)
    RelatedEvent: Optional[List["RelatedEventItem"]] = Field(default=None)
    Galaxy: Optional[List[GalaxyItem]] = Field(default=None)
    Object: Optional[List[ObjectItem]] = Field(default=None)
    EventReport: Optional[List[EventReportItem]] = Field(default=None)
    Tag: Optional[List[TagItem]] = Field(default=None)


class RelatedEventItem(MISPBaseModel):
    Event: Optional[ExtendedEvent] = Field(default=None)


class EventRestSearchListItem(MISPBaseModel):
    Event: Optional[ExtendedEvent] = Field(default=None)

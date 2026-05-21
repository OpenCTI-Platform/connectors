from dataclasses import asdict, dataclass
from enum import StrEnum
from typing import Any


@dataclass
class BaseEvent:
    uid: str
    type: str
    flare_url: str
    created_at: str
    matched_at: str
    severity: str
    notes: str


def base_event_from_event(event: dict[str, Any]) -> BaseEvent:
    data = event.get("data", {})
    metadata = event.get("metadata", {})
    tenant_metadata = event.get("tenant_metadata", {})
    data_metadata = data.get("metadata", {})
    return BaseEvent(
        uid=data.get("uid", ""),
        type=data.get("index", ""),
        flare_url=data_metadata.get("flare_url", ""),
        created_at=data_metadata.get("estimated_created_at", ""),
        matched_at=metadata.get("matched_at", ""),
        severity=tenant_metadata.get("severity", ""),
        notes=tenant_metadata.get("notes", ""),
    )


@dataclass
class StealerLogEvent(BaseEvent):
    emails: list[str]
    usernames: list[str]
    ip_addresses: list[str]
    malware_family: str | None


def stealer_log_from_event(event: dict[str, Any]) -> StealerLogEvent:
    base = base_event_from_event(event)
    data = event.get("data", {})
    features = data.get("features", {})
    return StealerLogEvent(
        **asdict(base),
        emails=features.get("emails", []),
        usernames=features.get("usernames", []),
        ip_addresses=features.get("ip_addresses", []),
        malware_family=data.get("malware_information", {}).get("malware_family"),
    )


@dataclass
class RansomleakEvent(BaseEvent):
    title: str
    url: str | None
    victim_name: str | None


def ransomleak_from_event(event: dict[str, Any]) -> RansomleakEvent:
    base = base_event_from_event(event)
    data = event.get("data", {})
    victim_metadata = data.get("victim_metadata")
    return RansomleakEvent(
        **asdict(base),
        title=data.get("docmeta", {}).get("title", "N/A"),
        url=data.get("url") or data.get("response_url"),
        victim_name=(
            (victim_metadata.get("name") or victim_metadata.get("display_name"))
            if victim_metadata
            else None
        ),
    )


@dataclass
class LookalikeDomainEvent(BaseEvent):
    original_domain: str
    lookalike_domain: str


def lookalike_domain_from_event(event: dict[str, Any]) -> LookalikeDomainEvent:
    base = base_event_from_event(event)
    data = event.get("data", {})
    return LookalikeDomainEvent(
        **asdict(base),
        original_domain=(
            data.get("identifier_domain")[0] if data.get("identifier_domain") else ""
        ),
        lookalike_domain=data.get("name", ""),
    )


@dataclass
class LeakedCredentialEvent(BaseEvent):
    username: str
    identity_name: str


def leaked_credentials_from_event(event: dict[str, Any]) -> LeakedCredentialEvent:
    base = base_event_from_event(event)
    data = event.get("data", {})
    return LeakedCredentialEvent(
        **asdict(base),
        username=data.get("id", ""),
        identity_name=data.get("identity_name", ""),
    )


def get_event_from_event_json(
    event: dict[str, Any],
) -> LeakedCredentialEvent | LookalikeDomainEvent | StealerLogEvent | RansomleakEvent:
    match event["data"]["index"]:
        case EventTypes.LEAK | EventTypes.LEAKED_CREDENTIAL:
            return leaked_credentials_from_event(event)
        case EventTypes.STEALER_LOG | EventTypes.BOT:
            return stealer_log_from_event(event)
        case EventTypes.DOMAIN:
            return lookalike_domain_from_event(event)
        case EventTypes.RANSOMLEAK | EventTypes.DOCUMENT:
            return ransomleak_from_event(event)
        case _:
            raise ValueError(f"Unsupported event type: {event['data']['index']!r}")


class EventTypes(StrEnum):
    ACCOUNT = "account"
    ACTOR = "actor"
    ACTOR_SUMMARY = "actor_summary"
    AD = "ad"
    ATTACHMENT = "attachment"
    BLOG_POST = "blog_post"
    BOT = "bot"
    BUCKET = "bucket"
    BUCKET_OBJECT = "bucket_object"
    CC = "cc"
    CC_BASES = "cc_bases"
    CHAT_MESSAGE = "chat_message"
    COOKIE = "cookie"
    DOCKER_IMAGE = "docker_image"
    DOCKER_REPOSITORY = "docker_repository"
    DOCUMENT = "document"
    DOMAIN = "domain"
    DRILLER = "driller"
    DRILLER_FORUM_POST = "driller_forum_post"
    DRILLER_FORUM_TOPIC = "driller_forum_topic"
    DRILLER_GOOGLE = "driller_google"
    DRILLER_PROFILE = "driller_profile"
    DRILLER_SOURCE_CODE = "driller_source_code"
    EVENT = "event"
    EXPERIMENTAL = "experimental"
    FORUM_CATEGORY = "forum_category"
    FORUM_POST = "forum_post"
    FORUM_PROFILE = "forum_profile"
    FORUM_TOPIC = "forum_topic"
    FORUM_THREAD_SUMMARY = "forum_thread_summary"
    HOST = "host"
    LEAK = "leak"
    LEAKED_CREDENTIAL = "leaked_credential"
    LEAKED_DATA = "leaked_data"
    LEAKED_FILE = "leaked_file"
    LISTING = "listing"
    LOOKALIKE = "lookalike"
    PASTE = "paste"
    RANSOMLEAK = "ransomleak"
    RANSOMLEAK_FILE_LISTING = "ransomleak_file_listing"
    SCORE_EVENT = "score_event"
    SELLER = "seller"
    SERVICE = "service"
    SOCIAL_MEDIA_ACCOUNT = "social_media_account"
    SOURCE_CODE_SECRET = "source_code_secret"
    STEALER_LOG = "stealer_log"
    TELEGRAM_ATTACHMENT = ATTACHMENT + "/telegram"
    THREAT_FLOW_SUMMARY = "threat_flow_summary"
    WHOIS = "whois"


def get_incident_type_from_event_type(event_type: str) -> str:
    try:
        et = EventTypes(event_type)
    except ValueError as e:
        raise ValueError(f"Unknown event_type: {event_type!r}") from e

    match et:
        case (
            EventTypes.LEAKED_CREDENTIAL
            | EventTypes.LEAK
            | EventTypes.STEALER_LOG
            | EventTypes.BOT
        ):
            return "credential-compromise"

        case EventTypes.RANSOMLEAK | EventTypes.DOCUMENT:
            return "ransomware"

        case EventTypes.DOMAIN | EventTypes.LOOKALIKE:
            return "typosquatting"

        case _:
            return "other"


_EVENT_TITLES: dict[EventTypes, str] = {
    EventTypes.ACCOUNT: "Account",
    EventTypes.ACTOR: "Threat Actor",
    EventTypes.ACTOR_SUMMARY: "Actor Summary",
    EventTypes.AD: "Advertisement",
    EventTypes.ATTACHMENT: "Attachment",
    EventTypes.BLOG_POST: "Blog Post",
    EventTypes.BOT: "Infected Device",
    EventTypes.BUCKET: "Cloud Storage Bucket",
    EventTypes.BUCKET_OBJECT: "Bucket Object",
    EventTypes.CC: "Credit Card",
    EventTypes.CC_BASES: "Credit Card Base",
    EventTypes.CHAT_MESSAGE: "Chat Message",
    EventTypes.COOKIE: "Session Cookie",
    EventTypes.DOCKER_IMAGE: "Docker Image",
    EventTypes.DOCKER_REPOSITORY: "Docker Repository",
    EventTypes.DOCUMENT: "Ransomleak",
    EventTypes.DOMAIN: "Lookalike Domain",
    EventTypes.DRILLER: "Driller",
    EventTypes.DRILLER_FORUM_POST: "Forum Post",
    EventTypes.DRILLER_FORUM_TOPIC: "Forum Topic",
    EventTypes.DRILLER_GOOGLE: "Google",
    EventTypes.DRILLER_PROFILE: "Profile",
    EventTypes.DRILLER_SOURCE_CODE: "Source Code",
    EventTypes.EVENT: "Event",
    EventTypes.EXPERIMENTAL: "Experimental",
    EventTypes.FORUM_CATEGORY: "Forum Category",
    EventTypes.FORUM_POST: "Forum Post",
    EventTypes.FORUM_PROFILE: "Forum Profile",
    EventTypes.FORUM_TOPIC: "Forum Topic",
    EventTypes.FORUM_THREAD_SUMMARY: "Forum Thread Summary",
    EventTypes.HOST: "Host",
    EventTypes.LEAK: "Leaked Credential",
    EventTypes.LEAKED_CREDENTIAL: "Leaked Credential",
    EventTypes.LEAKED_DATA: "Leaked Data",
    EventTypes.LEAKED_FILE: "Leaked File",
    EventTypes.LISTING: "Marketplace Listing",
    EventTypes.LOOKALIKE: "Lookalike Domain",
    EventTypes.PASTE: "Paste",
    EventTypes.RANSOMLEAK: "Ransomleak",
    EventTypes.RANSOMLEAK_FILE_LISTING: "Ransomleak",
    EventTypes.SCORE_EVENT: "Score Event",
    EventTypes.SELLER: "Seller",
    EventTypes.SERVICE: "Service",
    EventTypes.SOCIAL_MEDIA_ACCOUNT: "Social Media Account",
    EventTypes.SOURCE_CODE_SECRET: "Source Code Secret",
    EventTypes.STEALER_LOG: "Infected Device",
    EventTypes.TELEGRAM_ATTACHMENT: "Telegram Attachment",
    EventTypes.THREAT_FLOW_SUMMARY: "Threat Flow Summary",
    EventTypes.WHOIS: "WHOIS Record",
}


def get_event_title_from_event_type(event_type: str) -> str:
    try:
        parsed_event_type = EventTypes(event_type)
    except ValueError as e:
        raise ValueError(f"Unknown event_type: {event_type!r}") from e
    return _EVENT_TITLES[parsed_event_type]

from datetime import UTC, datetime
from datetime import date as dt_date
from enum import StrEnum
from urllib.parse import unquote, urlsplit
from uuid import NAMESPACE_URL, uuid5

import pycti  # type: ignore[import-untyped]
from pydantic import BaseModel, ConfigDict, Field, field_validator
from stix2 import TLP_AMBER  # type: ignore[import-untyped]
from stix2 import v21 as stix2


class AnnouncementType(StrEnum):
    AI = "AI"
    CUSTOMERS = "CUSTOMERS"
    DEFENSE = "DEFENSE"
    EMPLOYEES = "EMPLOYEES"
    FINANCIAL = "FINANCIAL"
    INTERNAL = "INTERNAL"
    IP = "IP"
    MEDICAL = "MEDICAL"
    PARTNERS = "PARTNERS"
    PII = "PII"
    SENSITIVES = "SENSITIVES"


class PrimaryObject(StrEnum):
    REPORT = "report"
    INCIDENT = "incident"


class LeakRecord(BaseModel):
    model_config = ConfigDict(extra="allow", frozen=True, populate_by_name=True)

    date: dt_date
    hashid: str

    victim: str | None = None
    sector: str | None = None
    actor: str | None = None
    country: str | None = None

    revenue: str | None = None

    site: str | None = None
    ann_link: str | None = Field(default=None, alias="annLink")
    ann_title: str | None = Field(default=None, alias="annTitle")
    victim_domain: str | None = Field(default=None, alias="victimDomain")
    ann_description: str | None = Field(default=None, alias="annDescription")

    announcement_types: list[AnnouncementType] = Field(
        default_factory=list,
        alias="annDataTypes",
    )

    @field_validator("ann_link")
    @classmethod
    def annlink_repair_common_scrape_bug(cls, v: str | None) -> str | None:
        if v is None:
            return None
        if v.startswith("https//"):
            return "https://" + v[len("https//") :]
        if v.startswith("http//"):
            return "http://" + v[len("http//") :]
        return v

    @field_validator("site", "victim_domain")
    @classmethod
    def strip_optional_text(cls, v: str | None) -> str | None:
        if v is None:
            return None
        stripped = v.strip()
        return stripped or None

    @staticmethod
    def _normalize_domain(value: str | None) -> str | None:
        if not value:
            return None
        parsed = urlsplit(value if "://" in value else f"https://{value}")
        domain = parsed.hostname or ""
        normalized = domain.strip().lower()
        return normalized or None

    @property
    def normalized_hashid(self) -> str:
        return self.hashid.strip().lower()

    @property
    def indicator_domain(self) -> str | None:
        return self._normalize_domain(self.victim_domain) or self._normalize_domain(
            self.site
        )

    @field_validator("sector", "actor", "country")
    @classmethod
    def normalize_named_field(cls, v: str | None) -> str | None:
        if v is None:
            return None
        normalized = " ".join(v.split()).strip()
        if not normalized:
            return None
        if normalized.lower() in {"n/a", "none"}:
            return None
        return normalized


GENERIC_ACTOR_VALUES = frozenset(
    {
        "unknown",
        "unk",
        "anonymous",
        "unattributed",
        "undisclosed",
        "not disclosed",
        "not-disclosed",
        "ransomware group",
        "ransomware gang",
        "threat actor",
        "attacker",
    }
)


def _ensure_scheme(url: str) -> str:
    return url if url.startswith("http") else f"https://{url}"


def _external_reference(
    source_name: str,
    *,
    url: str | None = None,
    description: str | None = None,
) -> dict[str, str]:
    reference = {"source_name": source_name}
    if url is not None:
        reference["url"] = url
    if description is not None:
        reference["description"] = description
    return reference


def _primary_custom_properties(
    actor: str | None,
    country: str | None,
) -> dict[str, str]:
    properties: dict[str, str] = {}
    if actor is not None:
        properties["dep_actor"] = actor
    if country is not None:
        properties["dep_country"] = country
    return properties


class StixBuilder:
    def __init__(
        self,
        *,
        author_identity: stix2.Identity,
        confidence: int,
        label_value: str,
    ) -> None:
        self.author_identity = author_identity
        self.confidence = confidence
        self.label_value = label_value

    def create_victim_identity(
        self,
        item: LeakRecord,
        *,
        include_sector_in_description: bool,
    ) -> stix2.Identity | None:
        victim_name = item.victim
        if not victim_name:
            return None

        external_references: list[dict[str, str]] = []
        if item.ann_link:
            external_references.append(
                _external_reference(
                    "dep",
                    url=item.ann_link,
                    description=item.ann_title,
                )
            )
        if item.site and item.site != item.ann_link:
            external_references.append(
                _external_reference(
                    "victim-site",
                    url=_ensure_scheme(item.site),
                )
            )

        description_parts = []
        if item.sector and include_sector_in_description:
            description_parts.append(f"Industry sector: {item.sector}")
        if item.revenue:
            description_parts.append(f"Reported revenue: {item.revenue}")
        description = "\n".join(description_parts) or None

        return stix2.Identity(
            id=pycti.Identity.generate_id(victim_name, identity_class="organization"),
            name=victim_name,
            description=description,
            identity_class="organization",
            confidence=self.confidence,
            labels=[self.label_value],
            created_by_ref=self.author_identity,
            external_references=external_references or None,
            object_marking_refs=[TLP_AMBER],
        )

    def create_sector_identity(self, sector: str) -> stix2.Identity:
        sector_key = sector.lower()
        return stix2.Identity(
            id=pycti.Identity.generate_id(sector_key, identity_class="class"),
            name=sector,
            identity_class="class",
            created_by_ref=self.author_identity,
            confidence=self.confidence,
            labels=[self.label_value],
            object_marking_refs=[TLP_AMBER],
        )

    def create_intrusion_set(self, actor: str) -> stix2.IntrusionSet:
        actor_key = actor.lower()
        intrusion_set_id = (
            f"intrusion-set--{uuid5(NAMESPACE_URL, f'dep-actor:{actor_key}')}"
        )
        return stix2.IntrusionSet(
            id=intrusion_set_id,
            name=actor,
            confidence=self.confidence,
            labels=[self.label_value],
            created_by_ref=self.author_identity,
            object_marking_refs=[TLP_AMBER],
        )

    def create_country_location(self, country: str) -> stix2.Location:
        country_key = country.lower()
        location_id = f"location--{uuid5(NAMESPACE_URL, f'dep-country:{country_key}')}"
        return stix2.Location(
            id=location_id,
            name=country,
            country=country,
            confidence=self.confidence,
            labels=[self.label_value],
            created_by_ref=self.author_identity,
            object_marking_refs=[TLP_AMBER],
            custom_properties={"x_opencti_location_type": "Country"},
            allow_custom=True,
        )

    def create_incident(self, item: LeakRecord) -> stix2.Incident:
        incident_name = self.build_primary_name(item)
        description = self.build_primary_description(item)
        first_seen = datetime.combine(item.date, datetime.min.time(), tzinfo=UTC)
        external_reference = self.build_primary_external_reference(item)
        incident_id = f"incident--{uuid5(NAMESPACE_URL, f'dep-announcement:{item.normalized_hashid}')}"
        custom_properties = {
            "incident_type": "cybercrime",
            "first_seen": first_seen,
            **self.build_primary_custom_properties(item),
        }

        return stix2.Incident(
            id=incident_id,
            name=incident_name,
            description=description,
            created=first_seen,
            confidence=self.confidence,
            labels=self.build_labels(item),
            created_by_ref=self.author_identity,
            external_references=[external_reference],
            object_marking_refs=[TLP_AMBER],
            custom_properties=custom_properties,
        )

    def create_report(self, item: LeakRecord, object_refs: list[str]) -> stix2.Report:
        report_name = self.build_primary_name(item)
        description = self.build_primary_description(item)
        published = datetime.combine(item.date, datetime.min.time(), tzinfo=UTC)
        external_reference = self.build_primary_external_reference(item)
        report_id = f"report--{uuid5(NAMESPACE_URL, f'dep-announcement:{item.normalized_hashid}')}"
        report_kwargs: dict[str, object] = {
            "id": report_id,
            "name": report_name,
            "description": description,
            "published": published,
            "report_types": ["threat-report"],
            "confidence": self.confidence,
            "labels": self.build_labels(item),
            "created_by_ref": self.author_identity,
            "external_references": [external_reference],
            "object_refs": object_refs,
            "object_marking_refs": [TLP_AMBER],
        }
        custom_properties = self.build_primary_custom_properties(item)
        if custom_properties:
            report_kwargs["custom_properties"] = custom_properties
        return stix2.Report(**report_kwargs)

    def build_labels(self, item: LeakRecord) -> list[str]:
        labels = {self.label_value}
        labels.update(
            f"dep:announcement-type:{announcement_type.value.lower()}"
            for announcement_type in item.announcement_types
        )
        return sorted(labels)

    def create_site_indicator(self, item: LeakRecord) -> stix2.Indicator | None:
        domain = item.indicator_domain
        if not domain:
            return None

        pattern = f"[domain-name:value = '{domain}']"
        return stix2.Indicator(
            id=pycti.Indicator.generate_id(pattern),
            name=f"Domain associated with {item.victim or 'unknown victim'}",
            description="Victim domain",
            pattern_type="stix",
            pattern=pattern,
            valid_from=datetime.now(UTC),
            confidence=self.confidence,
            labels=[self.label_value],
            created_by_ref=self.author_identity,
            object_marking_refs=[TLP_AMBER],
        )

    def create_hash_indicator(self, item: LeakRecord) -> stix2.Indicator | None:
        hash_value = item.normalized_hashid
        if not hash_value:
            return None
        hash_type = self.detect_hash_type(hash_value)
        if not hash_type:
            return None

        pattern = f"[file:hashes.'{hash_type}' = '{hash_value}']"
        return stix2.Indicator(
            id=pycti.Indicator.generate_id(pattern),
            name=f"Announcement hash for {item.victim or 'unknown victim'}",
            description="Hash identifier for tracking",
            pattern_type="stix",
            pattern=pattern,
            valid_from=datetime.now(UTC),
            confidence=self.confidence,
            labels=[self.label_value],
            created_by_ref=self.author_identity,
            object_marking_refs=[TLP_AMBER],
        )

    @staticmethod
    def detect_hash_type(hash_value: str) -> str | None:
        length_to_type = {32: "MD5", 40: "SHA-1", 64: "SHA-256"}
        length = len(hash_value)
        if length in length_to_type:
            return length_to_type[length]
        return None

    @staticmethod
    def is_low_quality_actor(actor: str) -> bool:
        normalized = " ".join(actor.lower().split())
        return normalized in GENERIC_ACTOR_VALUES

    def build_relationship(
        self,
        relationship_type: str,
        source_ref: str,
        target_ref: str,
    ) -> stix2.Relationship:
        return stix2.Relationship(
            id=pycti.StixCoreRelationship.generate_id(
                relationship_type, source_ref, target_ref
            ),
            relationship_type=relationship_type,
            source_ref=source_ref,
            target_ref=target_ref,
            created_by_ref=self.author_identity,
            confidence=self.confidence,
            labels=[self.label_value],
            object_marking_refs=[TLP_AMBER],
        )

    @staticmethod
    def build_primary_name(item: LeakRecord) -> str:
        victim_name = item.victim or item.victim_domain or "Unknown Victim"
        return f"DEP announcement - {victim_name}"

    @staticmethod
    def build_primary_description(item: LeakRecord) -> str | None:
        if item.ann_description:
            return unquote(item.ann_description)
        return None

    @staticmethod
    def build_primary_external_reference(item: LeakRecord) -> dict[str, str]:
        url = item.ann_link
        if url is None and item.site:
            url = _ensure_scheme(item.site)
        return _external_reference(
            "dep",
            url=url,
            description=item.ann_title,
        )

    @staticmethod
    def build_primary_custom_properties(item: LeakRecord) -> dict[str, str]:
        return _primary_custom_properties(item.actor, item.country)

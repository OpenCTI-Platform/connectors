import json
import os
import time
from datetime import UTC
from datetime import date as dt_date
from datetime import datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlsplit
from uuid import NAMESPACE_URL, uuid5

import pycti  # type: ignore[import-untyped]
import requests
import yaml
from pydantic import ConfigDict, Field, field_validator
from pydantic.dataclasses import dataclass
from stix2 import v21 as stix2  # type: ignore[import-untyped]


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


@dataclass(config=ConfigDict(extra="allow", frozen=True))
class LeakRecord:
    date: dt_date
    hashid: str

    victim: str | None = None
    sector: str | None = None

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
    def indicator_domain(self) -> str | None:
        return self._normalize_domain(self.victim_domain) or self._normalize_domain(
            self.site
        )


class DepConnector:
    def __init__(self) -> None:
        config = self._load_config()
        self.helper = pycti.OpenCTIConnectorHelper(config)
        self.label_value = "DigIntLab"
        self.author_identity = stix2.Identity(
            id=pycti.Identity.generate_id(
                self.label_value, identity_class="organization"
            ),
            name=self.label_value,
            description="We Track and Monitor the Cyber Space",
            contact_information="https://doubleextortion.com/",
            identity_class="organization",
        )

        self.interval = pycti.get_config_variable(
            "CONNECTOR_RUN_INTERVAL",
            ["connector", "interval"],
            config,
            default=3600,
            isNumber=True,
        )
        self.lookback_days = pycti.get_config_variable(
            "DEP_LOOKBACK_DAYS",
            ["dep", "lookback_days"],
            config,
            default=7,
            isNumber=True,
        )
        self.overlap_hours = pycti.get_config_variable(
            "DEP_OVERLAP_HOURS",
            ["dep", "overlap_hours"],
            config,
            default=72,
            isNumber=True,
        )
        self.confidence = pycti.get_config_variable(
            "DEP_CONFIDENCE", ["dep", "confidence"], config, default=70, isNumber=True
        )
        self.api_key = pycti.get_config_variable(
            "DEP_API_KEY", ["dep", "api_key"], config
        )
        self.username = pycti.get_config_variable(
            "DEP_USERNAME", ["dep", "username"], config
        )
        self.password = pycti.get_config_variable(
            "DEP_PASSWORD", ["dep", "password"], config
        )
        self.client_id = pycti.get_config_variable(
            "DEP_CLIENT_ID", ["dep", "client_id"], config, default=""
        )
        if not self.client_id:
            error = "DEP client ID must be provided via configuration"
            raise ValueError(error)
        self.login_endpoint = pycti.get_config_variable(
            "DEP_LOGIN_ENDPOINT",
            ["dep", "login_endpoint"],
            config,
            default="https://cognito-idp.eu-west-1.amazonaws.com/",
        )

        self.api_endpoint = pycti.get_config_variable(
            "DEP_API_ENDPOINT",
            ["dep", "api_endpoint"],
            config,
            default="https://api.eu-ep1.doubleextortion.com/v1/dbtr/privlist",
        )
        self.dataset = pycti.get_config_variable(
            "DEP_DSET",
            ["dep", "dset"],
            config,
            default="ext",
        )
        self.extended_results = pycti.get_config_variable(
            "DEP_EXTENDED_RESULTS",
            ["dep", "extended_results"],
            config,
            default=True,
        )
        self.enable_site_indicator = pycti.get_config_variable(
            "DEP_ENABLE_SITE_INDICATOR",
            ["dep", "enable_site_indicator"],
            config,
            default=True,
        )

        self.enable_hash_indicator = pycti.get_config_variable(
            "DEP_ENABLE_HASH_INDICATOR",
            ["dep", "enable_hash_indicator"],
            config,
            default=True,
        )
        self.skip_empty_victim = pycti.get_config_variable(
            "DEP_SKIP_EMPTY_VICTIM",
            ["dep", "skip_empty_victim"],
            config,
            default=True,
        )

    @staticmethod
    def _load_config() -> dict[str, Any]:
        # Resolve config path from environment variable or fallback to config.yml next to this file
        config_path = os.environ.get(
            "OPENCTI_CONFIG_FILE",
            Path(__file__).resolve().parent / "config.yml",
        )
        config_path = Path(config_path)
        if config_path.exists():
            with config_path.open(encoding="utf-8") as config_file:
                return yaml.safe_load(config_file) or {}
        return {}

    def _authenticate(self) -> str:
        headers = {
            "Content-Type": "application/x-amz-json-1.1",
            "X-Amz-Target": "AWSCognitoIdentityProviderService.InitiateAuth",
        }
        payload = {
            "AuthParameters": {"USERNAME": self.username, "PASSWORD": self.password},
            "AuthFlow": "USER_PASSWORD_AUTH",
            "ClientId": self.client_id,
        }
        response = requests.post(
            self.login_endpoint,
            headers=headers,
            json=payload,
            timeout=30,
        )
        response.raise_for_status()
        data = response.json()
        try:
            token = str(data.get("AuthenticationResult").get("IdToken"))
        except Exception as e:
            error = "Unable to retrieve IdToken from authentication response"
            raise ValueError(error) from e
        return token

    def _fetch_data(self, start: datetime, end: datetime) -> list[LeakRecord]:
        token = self._authenticate()
        params = {
            "ts": start.strftime("%Y-%m-%d"),
            "te": end.strftime("%Y-%m-%d"),
            "dset": self.dataset,
            "full": "true",
        }
        if self.extended_results:
            params["extended"] = "true"

        headers = {
            "X-Api-Key": self.api_key,
            "Authorization": token,
        }

        response = requests.get(
            self.api_endpoint,
            headers=headers,
            params=params,
            timeout=60,
        )
        response.raise_for_status()
        try:
            data = response.json()
        except json.JSONDecodeError as exception:
            message = "Unable to decode DEP API response"
            raise ValueError(message) from exception

        if isinstance(data, list):
            parsed_items: list[LeakRecord] = []
            for index, raw_item in enumerate(data):
                if not isinstance(raw_item, dict):
                    self.helper.log_warning(
                        "Skipping DEP item at index "
                        f"{index}: expected object, got {type(raw_item).__name__}"
                    )
                    continue
                try:
                    parsed_items.append(LeakRecord(**raw_item))
                except Exception as error:  # pylint: disable=broad-except
                    self.helper.log_warning(
                        "Skipping invalid DEP item for victim "
                        f"{raw_item.get('victim')}: {error}"
                    )
            return parsed_items
        self.helper.log_warning("DEP API returned unexpected payload type")
        return []

    def _create_victim_identity(self, item: LeakRecord) -> stix2.Identity | None:
        victim_name = item.victim
        if not victim_name:
            return None

        external_references: list[dict[str, Any]] = []
        if item.ann_link:
            external_references.append(
                {
                    "source_name": "dep",
                    "url": item.ann_link,
                    "description": item.ann_title,
                }
            )
        if item.site and item.site != item.ann_link:
            external_references.append(
                {
                    "source_name": "victim-site",
                    "url": (
                        f"https://{item.site}"
                        if not item.site.startswith("http")
                        else item.site
                    ),
                }
            )

        description_parts = []
        if item.sector:
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
        )

    def _create_incident(self, item: LeakRecord) -> stix2.Incident:
        victim_name = item.victim or item.victim_domain
        if not victim_name:
            victim_name = "Unknown Victim"
        incident_name = f"DEP announcement - {victim_name}"
        description = item.ann_description
        if description:
            description = unquote(description)
        first_seen = datetime.combine(item.date, datetime.min.time(), tzinfo=UTC)
        external_reference = {"source_name": "dep"}
        if item.ann_link:
            external_reference["url"] = item.ann_link
        elif item.site:
            site = item.site
            external_reference["url"] = (
                site if site.startswith("http") else f"https://{site}"
            )
        if item.ann_title:
            external_reference["description"] = item.ann_title
        # incident_id must be deterministic to allow updates
        incident_id = f"incident--{uuid5(NAMESPACE_URL, f'dep-announcement:{item.hashid.strip().lower()}')}"
        return stix2.Incident(
            id=incident_id,
            name=incident_name,
            description=description,
            created=first_seen,
            confidence=self.confidence,
            labels=self._build_incident_labels(item),
            created_by_ref=self.author_identity,
            external_references=[external_reference],
            custom_properties={
                "incident_type": "cybercrime",
                "first_seen": first_seen,
            },
        )

    def _build_incident_labels(self, item: LeakRecord) -> list[str]:
        labels = {self.label_value}
        labels.update(
            f"dep:announcement-type:{announcement_type.value.lower()}"
            for announcement_type in item.announcement_types
        )
        return sorted(labels)

    def _create_site_indicator(self, item: LeakRecord) -> stix2.Indicator | None:
        if not self.enable_site_indicator:
            return None
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
        )

    def _create_hash_indicator(self, item: LeakRecord) -> stix2.Indicator | None:
        if not self.enable_hash_indicator:
            return None
        hash_value = item.hashid.strip().lower()
        if not hash_value:
            return None
        hash_type = self._detect_hash_type(hash_value)
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
        )

    @staticmethod
    def _detect_hash_type(hash_value: str) -> str | None:
        length_to_type = {32: "MD5", 40: "SHA-1", 64: "SHA-256"}
        return length_to_type.get(len(hash_value))

    def _build_relationship(
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
        )

    def _send_objects(self, objects: list[stix2._STIXBase21]) -> None:
        if not objects:
            return
        deduped = {obj.id: obj for obj in objects if getattr(obj, "id", None)}
        bundle = stix2.Bundle(objects=list(deduped.values()), allow_custom=True)
        self.helper.send_stix2_bundle(bundle.serialize(), update=True)

    def _should_skip_item(self, victim: str | None) -> bool:
        if not self.skip_empty_victim:
            return False
        normalized = (victim or "").strip().lower()
        return normalized in {"", "n/a", "none"}

    def _process_item(self, item: LeakRecord) -> None:
        if self._should_skip_item(item.victim):
            self.helper.log_info(
                "Skipping DEP item with empty or placeholder victim value"
            )
            return
        victim = self._create_victim_identity(item)
        incident = self._create_incident(item)

        indicators: list[stix2.Indicator] = []
        site_indicator = self._create_site_indicator(item)
        if site_indicator:
            indicators.append(site_indicator)
        hash_indicator = self._create_hash_indicator(item)
        if hash_indicator:
            indicators.append(hash_indicator)

        objects: list[stix2._STIXBase21] = [self.author_identity]
        if victim:
            objects.append(victim)
        objects.append(incident)
        if victim:
            objects.append(self._build_relationship("targets", incident.id, victim.id))
        for indicator in indicators:
            objects.append(indicator)
            objects.append(
                self._build_relationship("indicates", indicator.id, incident.id)
            )
        self._send_objects(objects)

    def _run_cycle(self) -> None:
        now = datetime.now(UTC)
        start = now - timedelta(days=self.lookback_days)
        state = self.helper.get_state() or {}
        last_run = state.get("last_run")
        if isinstance(last_run, str):
            try:
                start = datetime.fromisoformat(last_run) - timedelta(
                    hours=self.overlap_hours
                )
            except ValueError:
                self.helper.log_warning(
                    f"Ignoring invalid last_run state value: {last_run}"
                )
        elif last_run is not None:
            self.helper.log_warning(
                "Ignoring non-string last_run state value returned by OpenCTI helper"
            )
        end = now

        self.helper.log_info(
            "Fetching DEP data from "
            f"{start.isoformat()} to {end.isoformat()} "
            f"(overlap: {self.overlap_hours}h)"
        )

        try:
            items = self._fetch_data(start, end)
        except Exception as error:  # pylint: disable=broad-except
            self.helper.log_error(f"Failed to fetch DEP data: {error}")
            return

        self.helper.log_info(f"Received {len(items)} entries from DEP API")

        for item in items:
            try:
                self._process_item(item)
            except Exception as error:  # pylint: disable=broad-except
                self.helper.log_error(
                    f"Failed to process DEP item for victim {item.victim}: {error}"
                )

        self.helper.log_info("Persisting connector state")
        self.helper.set_state({"last_run": end.isoformat()})
        self.helper.log_info("DEP run completed")

    def run(self) -> None:
        self.helper.log_info("Starting DEP connector")
        while True:
            self._run_cycle()
            time.sleep(self.interval)


if __name__ == "__main__":
    DepConnector().run()

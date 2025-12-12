import json
import os
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import unquote

import pycti  # type: ignore[import-untyped]
import requests
import yaml
from stix2 import v21 as stix2  # type: ignore[import-untyped]


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

    def _fetch_data(self, start: datetime, end: datetime) -> list[dict[str, Any]]:
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
            return data
        self.helper.log_warning("DEP API returned unexpected payload type")
        return []

    def _create_victim_identity(self, item: dict[str, Any]) -> stix2.Identity | None:
        victim_name = item.get("victim")
        if not victim_name:
            return None

        external_references: list[dict[str, Any]] = []
        if item.get("annLink"):
            external_references.append(
                {
                    "source_name": "dep",
                    "url": item["annLink"],
                    "description": item.get("annTitle"),
                }
            )
        if item.get("site") and item.get("site") != item.get("annLink"):
            external_references.append(
                {
                    "source_name": "victim-site",
                    "url": (
                        f"https://{item['site']}"
                        if not item["site"].startswith("http")
                        else item["site"]
                    ),
                }
            )

        description_parts = []
        if item.get("sector"):
            description_parts.append(f"Industry sector: {item['sector']}")
        if item.get("revenue"):
            description_parts.append(f"Reported revenue: {item['revenue']}")
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

    def _create_incident(self, item: dict[str, Any]) -> stix2.Incident | None:
        victim_name = item.get("victim") or item.get("victimDomain")
        if not victim_name:
            victim_name = "Unknown Victim"
        incident_name = f"DEP announcement - {victim_name}"
        description = item.get("annDescription") or item.get("description")
        if description:
            description = unquote(description)
        announcement_date = item.get("date")
        first_seen: datetime | None = None
        if announcement_date:
            first_seen = datetime.strptime(
                announcement_date.strip(), "%Y-%m-%d"
            ).replace(tzinfo=UTC)
        external_reference = {"source_name": "dep"}
        if item.get("annLink"):
            external_reference["url"] = item["annLink"]
        elif item.get("site"):
            site = item["site"]
            external_reference["url"] = (
                site if site.startswith("http") else f"https://{site}"
            )
        if item.get("annTitle"):
            external_reference["description"] = item["annTitle"]
        return stix2.Incident(
            id=pycti.Incident.generate_id(incident_name, first_seen),
            name=incident_name,
            description=description,
            created=first_seen,
            confidence=self.confidence,
            labels=[self.label_value],
            created_by_ref=self.author_identity,
            external_references=[external_reference],
            custom_properties={
                "incident_type": "cybercrime",
                "first_seen": first_seen,
            },
        )

    def _create_site_indicator(self, item: dict[str, Any]) -> stix2.Indicator | None:
        if not self.enable_site_indicator:
            return None
        domain = item.get("victimDomain") or item.get("site")
        if not domain:
            return None
        domain = domain.lower().strip()
        domain = domain.replace("https://", "").replace("http://", "")
        if not domain:
            return None

        pattern = f"[domain-name:value = '{domain}']"
        return stix2.Indicator(
            id=pycti.Indicator.generate_id(pattern),
            name=f"Domain associated with {item.get('victim', 'unknown victim')}",
            description="Victim domain",
            pattern_type="stix",
            pattern=pattern,
            valid_from=datetime.now(UTC),
            confidence=self.confidence,
            labels=[self.label_value],
            created_by_ref=self.author_identity,
        )

    def _create_hash_indicator(self, item: dict[str, Any]) -> stix2.Indicator | None:
        if not self.enable_hash_indicator:
            return None
        hash_value = item.get("hashid")
        if not hash_value:
            return None
        hash_value = hash_value.lower().strip()
        if not hash_value:
            return None
        hash_type = self._detect_hash_type(hash_value)
        if not hash_type:
            return None

        pattern = f"[file:hashes.'{hash_type}' = '{hash_value}']"
        return stix2.Indicator(
            id=pycti.Indicator.generate_id(pattern),
            name=f"Announcement hash for {item.get('victim', 'unknown victim')}",
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

    def _process_item(self, item: dict[str, Any]) -> None:
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
        if incident:
            objects.append(incident)
        if incident and victim:
            objects.append(self._build_relationship("targets", incident.id, victim.id))
        if incident:
            for indicator in indicators:
                objects.append(indicator)
                objects.append(
                    self._build_relationship("indicates", indicator.id, incident.id)
                )
        self._send_objects(objects)

    def _run_cycle(self) -> None:
        now = datetime.now(UTC)
        start = now - timedelta(days=self.lookback_days)
        try:
            last_run = self.helper.get_state().get("last_run")
            if last_run:
                parsed = datetime.fromisoformat(last_run)
                start = parsed
        except Exception:  # noqa: S110
            pass
        end = now

        self.helper.log_info(
            f"Fetching DEP data from {start.isoformat()} to {end.isoformat()}"
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
                    f"Failed to process DEP item for victim {item.get('victim')}: {error}"
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

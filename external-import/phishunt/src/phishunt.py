import os
import re
import ssl
import sys
import traceback
import urllib.error
import urllib.request
from datetime import UTC, datetime
from typing import Any

import requests
import stix2
import yaml
from pycti import (
    Identity,
    Indicator,
    Location,
    OpenCTIConnectorHelper,
    StixCoreRelationship,
    get_config_variable,
)


class Phishunt:
    def __init__(self):
        # Instantiate the connector helper from config
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        self.config = {}
        if os.path.isfile(config_file_path):
            with open(config_file_path) as f:
                self.config = yaml.load(f, Loader=yaml.FullLoader)

        self.helper = OpenCTIConnectorHelper(self.config)

        # Extra config
        self.connector_duration_period = get_config_variable(
            env_var="CONNECTOR_DURATION_PERIOD",
            yaml_path=["connector", "duration_period"],
            config=self.config,
        )

        self.phishunt_interval = get_config_variable(
            env_var="PHISHUNT_INTERVAL",
            yaml_path=["phishunt", "interval"],
            config=self.config,
            isNumber=True,
            default=3,
        )

        self.phishunt_api_key = get_config_variable(
            env_var="PHISHUNT_API_KEY",
            yaml_path=["phishunt", "api_key"],
            config=self.config,
        )

        self.create_indicators = get_config_variable(
            env_var="PHISHUNT_CREATE_INDICATORS",
            yaml_path=["phishunt", "create_indicators"],
            config=self.config,
            default=True,
        )
        self.default_x_opencti_score = get_config_variable(
            env_var="PHISHUNT_DEFAULT_X_OPENCTI_SCORE",
            yaml_path=["phishunt", "default_x_opencti_score"],
            config=self.config,
            isNumber=True,
            default=40,
        )
        self.x_opencti_score_domain = get_config_variable(
            env_var="PHISHUNT_X_OPENCTI_SCORE_DOMAIN",
            yaml_path=["phishunt", "x_opencti_score_domain"],
            config=self.config,
            isNumber=True,
        )
        self.x_opencti_score_ip = get_config_variable(
            env_var="PHISHUNT_X_OPENCTI_SCORE_IP",
            yaml_path=["phishunt", "x_opencti_score_ip"],
            config=self.config,
            isNumber=True,
        )
        self.x_opencti_score_url = get_config_variable(
            env_var="PHISHUNT_X_OPENCTI_SCORE_URL",
            yaml_path=["phishunt", "x_opencti_score_url"],
            config=self.config,
            isNumber=True,
        )

        self.last_run = None
        self.last_run_datetime_with_ingested_data = None

        self.stix_created_by = stix2.Identity(
            id=Identity.generate_id(name="Phishunt", identity_class="organization"),
            name="Phishunt",
            identity_class="organization",
            description="Phishunt is providing URLs of potential malicious payload.",
            custom_properties={
                "x_opencti_organization_type": "vendor",
            },
        )

    def _process_public_feed(self, work_id):
        url = "https://phishunt.io/feed.txt"
        try:
            bundle_objects = []

            with urllib.request.urlopen(
                url=url, context=ssl.create_default_context()
            ) as fp:

                for count, line in enumerate(fp, 1):
                    count += 1
                    if count <= 3:
                        continue
                    line = line.decode("utf-8").strip()
                    match_html_tag = re.search(r"^<\/?\w+>", line)
                    if match_html_tag:
                        continue
                    match_blank_line = re.search(r"^\s*$", line)
                    if match_blank_line:
                        continue

                    stix_observable = stix2.URL(
                        value=line,
                        object_marking_refs=[stix2.TLP_WHITE],
                        custom_properties={
                            "x_opencti_description": "Phishunt malicious URL",
                            "x_opencti_score": self.x_opencti_score_url
                            or self.default_x_opencti_score,
                            "x_opencti_labels": ["osint", "phishing"],
                            "x_opencti_created_by_ref": self.stix_created_by["id"],
                        },
                    )
                    bundle_objects.append(stix_observable)

                    if self.create_indicators:
                        pattern = "[url:value = '" + line + "']"
                        stix_indicator = stix2.Indicator(
                            id=Indicator.generate_id(pattern),
                            name=line,
                            description="Phishunt malicious URL",
                            pattern_type="stix",
                            created_by_ref=self.stix_created_by["id"],
                            pattern=pattern,
                            labels=["osint", "phishing"],
                            object_marking_refs=[stix2.TLP_WHITE],
                            custom_properties={
                                "x_opencti_main_observable_type": "Url",
                            },
                        )
                        bundle_objects.append(stix_indicator)

                        stix_relationship = stix2.Relationship(
                            id=StixCoreRelationship.generate_id(
                                "based-on", stix_indicator.id, stix_observable.id
                            ),
                            source_ref=stix_indicator.id,
                            target_ref=stix_observable.id,
                            relationship_type="based-on",
                            allow_custom=True,
                        )
                        bundle_objects.append(stix_relationship)

            if bundle_objects:
                bundle = self.helper.stix2_create_bundle(
                    [self.stix_created_by] + bundle_objects
                )
                self.helper.send_stix2_bundle(
                    bundle,
                    work_id=work_id,
                )
                self.last_run_datetime_with_ingested_data = datetime.now(
                    tz=UTC
                ).isoformat(timespec="seconds")
        except urllib.error.URLError as urllib_error:
            self.helper.connector_logger.error(
                "Error retrieving url", {"url": url, "error": urllib_error}
            )

    def _process_private_feed(self, work_id):
        try:
            resp = requests.request(
                "GET",
                "https://api.phishunt.io/suspicious/feed_json",
                headers={"x-api-key": self.phishunt_api_key},
            )
            resp.raise_for_status()
            data = resp.json()
            bundle_objects = []

            for url in data:
                stix_url = stix2.URL(
                    value=url["url"],
                    object_marking_refs=[stix2.TLP_WHITE],
                    custom_properties={
                        "x_opencti_description": "Phishunt malicious URL",
                        "x_opencti_score": self.x_opencti_score_url
                        or self.default_x_opencti_score,
                        "x_opencti_labels": ["osint", "phishing"],
                        "x_opencti_created_by_ref": self.stix_created_by["id"],
                    },
                )
                bundle_objects.append(stix_url)

                if self.create_indicators:
                    pattern = "[url:value = '" + url["url"] + "']"
                    stix_indicator = stix2.Indicator(
                        id=Indicator.generate_id(pattern),
                        name=url["url"],
                        description="Phishunt malicious URL",
                        pattern_type="stix",
                        created_by_ref=self.stix_created_by["id"],
                        pattern=pattern,
                        labels=["osint", "phishing"],
                        object_marking_refs=[stix2.TLP_WHITE],
                        custom_properties={
                            "x_opencti_main_observable_type": "Url",
                        },
                    )
                    bundle_objects.append(stix_indicator)

                    stix_relationship = stix2.Relationship(
                        id=StixCoreRelationship.generate_id(
                            "based-on", stix_indicator.id, stix_url.id
                        ),
                        source_ref=stix_indicator.id,
                        target_ref=stix_url.id,
                        relationship_type="based-on",
                        allow_custom=True,
                    )
                    bundle_objects.append(stix_relationship)

                    stix_domain = stix2.DomainName(
                        value=url["domain"],
                        object_marking_refs=[stix2.TLP_WHITE],
                        custom_properties={
                            "x_opencti_description": "Phishunt domain based on malicious URL",
                            "x_opencti_score": self.x_opencti_score_domain
                            or self.default_x_opencti_score,
                            "x_opencti_labels": ["osint", "phishing"],
                            "x_opencti_created_by_ref": self.stix_created_by["id"],
                        },
                    )
                    bundle_objects.append(stix_domain)

                    stix_relationship_url_domain = stix2.Relationship(
                        id=StixCoreRelationship.generate_id(
                            "related-to", stix_url.id, stix_domain.id
                        ),
                        source_ref=stix_url.id,
                        target_ref=stix_domain.id,
                        relationship_type="related-to",
                        object_marking_refs=[stix2.TLP_WHITE],
                        allow_custom=True,
                    )
                    bundle_objects.append(stix_relationship_url_domain)

                    stix_organization = stix2.Identity(
                        id=Identity.generate_id(
                            url["company"].capitalize(), "organization"
                        ),
                        name=url["company"].capitalize(),
                        identity_class="organization",
                        object_marking_refs=[stix2.TLP_WHITE],
                        created_by_ref=self.stix_created_by["id"],
                    )
                    bundle_objects.append(stix_organization)

                    stix_relationship_organization_url = stix2.Relationship(
                        id=StixCoreRelationship.generate_id(
                            "related-to", stix_url.id, stix_domain.id
                        ),
                        source_ref=stix_url.id,
                        target_ref=stix_organization.id,
                        relationship_type="related-to",
                        object_marking_refs=[stix2.TLP_WHITE],
                        allow_custom=True,
                    )
                    bundle_objects.append(stix_relationship_organization_url)

                    stix_ip = stix2.IPv4Address(
                        value=url["ip"],
                        object_marking_refs=[stix2.TLP_WHITE],
                        custom_properties={
                            "x_opencti_description": "Phishunt domain based on malicious URL",
                            "x_opencti_score": self.x_opencti_score_ip
                            or self.default_x_opencti_score,
                            "x_opencti_labels": ["osint", "phishing"],
                            "x_opencti_created_by_ref": self.stix_created_by["id"],
                        },
                    )
                    bundle_objects.append(stix_ip)

                    stix_relationship_domain_ip = stix2.Relationship(
                        id=StixCoreRelationship.generate_id(
                            "resolves-to", stix_domain.id, stix_ip.id
                        ),
                        source_ref=stix_domain.id,
                        target_ref=stix_ip.id,
                        relationship_type="resolves-to",
                        object_marking_refs=[stix2.TLP_WHITE],
                        allow_custom=True,
                    )
                    bundle_objects.append(stix_relationship_domain_ip)

                    if url.get("country") and url["country"] != "-":
                        stix_location = stix2.Location(
                            id=Location.generate_id(url["country"], "Country"),
                            name=url["country"],
                            country=url["country"],
                            created_by_ref=self.stix_created_by["id"],
                            allow_custom=True,
                            custom_properties={"x_opencti_location_type": "Country"},
                        )
                        bundle_objects.append(stix_location)

                        stix_relationship_ip_location = stix2.Relationship(
                            id=StixCoreRelationship.generate_id(
                                "located-at", stix_ip.id, stix_location.id
                            ),
                            source_ref=stix_ip.id,
                            target_ref=stix_location.id,
                            relationship_type="located-at",
                            object_marking_refs=[stix2.TLP_WHITE],
                            allow_custom=True,
                        )
                        bundle_objects.append(stix_relationship_ip_location)

            if bundle_objects:
                bundle = self.helper.stix2_create_bundle(
                    [self.stix_created_by] + bundle_objects
                )
                self.helper.send_stix2_bundle(
                    bundle,
                    work_id=work_id,
                )
                self.last_run_datetime_with_ingested_data = datetime.now(
                    tz=UTC
                ).isoformat(timespec="seconds")
        except requests.exceptions.HTTPError as err:
            self.helper.connector_logger.error(
                "[Phishunt] Http error during private feed process.", {"error": err}
            )

    def run(self):
        if self.connector_duration_period:
            self.helper.schedule_iso(
                message_callback=self.process_message,
                duration_period=self.connector_duration_period,
            )
        else:
            self.helper.schedule_unit(
                message_callback=self.process_message,
                duration_period=self.phishunt_interval,
                time_unit=self.helper.TimeUnit.DAYS,
            )

    def _load_state(self) -> dict[str, Any]:
        return self.helper.get_state() or {}

    def process_message(self):
        """Run Phishunt connector"""
        self.helper.connector_logger.info("Fetching Phishunt dataset...")

        try:
            # Get the current timestamp and check
            now = datetime.now(tz=UTC)
            current_state = self._load_state()

            self.helper.connector_logger.info(
                "Loaded state", {"current state": current_state}
            )

            if current_state and "last_run" in current_state:
                if isinstance(current_state["last_run"], int):
                    self.last_run = datetime.fromtimestamp(current_state["last_run"])
                else:
                    self.last_run = datetime.fromisoformat(current_state["last_run"])

            self.last_run_datetime_with_ingested_data = (
                current_state.get("last_run_datetime_with_ingested_data")
                if current_state
                else None
            )

            self.helper.connector_logger.info(
                "[CONNECTOR] Starting connector...",
                {
                    "connector_name": self.helper.connect_name,  # self.helper.connect_name
                    "connector_start_time": now.isoformat(timespec="seconds"),
                    "last_run": (
                        self.last_run if self.last_run else "Connector has never run"
                    ),
                    "last_run_datetime_with_ingested_data": (
                        self.last_run_datetime_with_ingested_data
                        if self.last_run_datetime_with_ingested_data
                        else "Connector has never ingested data"
                    ),
                },
            )

            friendly_name = "Phishunt run"
            work_id = self.helper.api.work.initiate_work(
                self.helper.connect_id, friendly_name
            )

            if self.phishunt_api_key:
                self._process_private_feed(work_id)
            else:
                self._process_public_feed(work_id)

            # Store the current start utc isoformat as a last run
            self.helper.connector_logger.info(
                "[CONNECTOR] Getting current state and update it with last run of the connector.",
                {
                    "current_state": self.last_run,
                    "new_last_run_start_datetime": now.isoformat(timespec="seconds"),
                },
            )

            current_state["last_run"] = now.isoformat(timespec="seconds")

            if self.last_run_datetime_with_ingested_data:
                current_state["last_run_datetime_with_ingested_data"] = (
                    self.last_run_datetime_with_ingested_data
                )

            self.helper.set_state(current_state)
            message = "Connector successfully run, storing last_run as" + now.isoformat(
                timespec="seconds"
            )

            self.helper.api.work.to_processed(work_id, message)

        except (KeyboardInterrupt, SystemExit):
            self.helper.connector_logger.info(
                "[CONNECTOR] Connector stopped...",
                {"connector_name": self.helper.connect_name},
            )
            sys.exit(0)
        except Exception as error:
            self.helper.connector_logger.error(
                "Phishunt connector internal error", {"error": error}
            )


if __name__ == "__main__":
    try:
        PhishuntConnector = Phishunt()
        PhishuntConnector.run()
    except Exception:
        traceback.print_exc()
        sys.exit(1)

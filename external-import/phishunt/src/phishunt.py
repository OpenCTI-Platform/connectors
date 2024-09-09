import os
import re
import ssl
import sys
import time
import urllib.request
from datetime import datetime

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

PHISHUNT_PUBLIC_FEED = "https://phishunt.io/feed.txt"
PHISHUNT_PRIVATE_FEED = "https://api.phishunt.io/suspicious/feed_json"


class Phishunt:
    def __init__(self):
        # Instantiate the connector helper from config
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config)
        # Extra config
        self.phishunt_api_key = get_config_variable(
            "PHISHUNT_API_KEY", ["phishunt", "api_key"], config, default=""
        )
        self.phishunt_interval = get_config_variable(
            "PHISHUNT_INTERVAL", ["phishunt", "interval"], config, True, default=3
        )
        self.create_indicators = get_config_variable(
            "PHISHUNT_CREATE_INDICATORS",
            ["phishunt", "create_indicators"],
            config,
            False,
            default=True,
        )
        self.default_x_opencti_score = get_config_variable(
            "PHISHUNT_DEFAULT_X_OPENCTI_SCORE",
            ["phishunt", "default_x_opencti_score"],
            config,
            isNumber=True,
            default=40,
            required=False,
        )
        self.x_opencti_score_domain = get_config_variable(
            "PHISHUNT_X_OPENCTI_SCORE_DOMAIN",
            ["phishunt", "x_opencti_score_domain"],
            config,
            isNumber=True,
            default=None,
            required=False,
        )
        self.x_opencti_score_ip = get_config_variable(
            "PHISHUNT_X_OPENCTI_SCORE_IP",
            ["phishunt", "x_opencti_score_ip"],
            config,
            isNumber=True,
            default=None,
            required=False,
        )
        self.x_opencti_score_url = get_config_variable(
            "PHISHUNT_X_OPENCTI_SCORE_URL",
            ["phishunt", "x_opencti_score_url"],
            config,
            isNumber=True,
            default=None,
            required=False,
        )
        self.update_existing_data = get_config_variable(
            "CONNECTOR_UPDATE_EXISTING_DATA",
            ["connector", "update_existing_data"],
            config,
        )
        self.identity = self.helper.api.identity.create(
            type="Organization",
            name="Phishunt",
            description="Phishunt is providing URLs of potential malicious payload.",
        )

    def get_interval(self):
        return int(self.phishunt_interval) * 60 * 60 * 24

    def next_run(self, seconds):
        return

    def _process_public_feed(self, work_id):
        try:
            response = urllib.request.urlopen(
                "https://phishunt.io/feed.txt",
                context=ssl.create_default_context(),
            )
            image = response.read()
            with open(
                os.path.dirname(os.path.abspath(__file__)) + "/data.txt",
                "wb",
            ) as file:
                file.write(image)
            count = 0
            bundle_objects = []
            with open(os.path.dirname(os.path.abspath(__file__)) + "/data.txt") as fp:
                for line in fp:
                    count += 1
                    if count <= 3:
                        continue
                    line = line.strip()
                    matchHtmlTag = re.search(r"^<\/?\w+>", line)
                    if matchHtmlTag:
                        continue
                    matchBlankLine = re.search(r"^\s*$", line)
                    if matchBlankLine:
                        continue
                    stix_observable = stix2.URL(
                        value=line,
                        object_marking_refs=[stix2.TLP_WHITE],
                        custom_properties={
                            "x_opencti_description": "Phishunt malicious URL",
                            "x_opencti_score": self.x_opencti_score_url
                            or self.default_x_opencti_score,
                            "x_opencti_labels": ["osint", "phishing"],
                            "x_opencti_created_by_ref": self.identity["standard_id"],
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
                            created_by_ref=self.identity["standard_id"],
                            confidence=self.helper.connect_confidence_level,
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
            bundle = self.helper.stix2_create_bundle(bundle_objects)
            self.helper.send_stix2_bundle(
                bundle,
                update=self.update_existing_data,
                work_id=work_id,
            )
            if os.path.exists(os.path.dirname(os.path.abspath(__file__)) + "/data.txt"):
                os.remove(os.path.dirname(os.path.abspath(__file__)) + "/data.txt")
        except Exception as error:
            self.helper.log_error(str(error))

    def _process_private_feed(self, work_id):
        try:
            resp = requests.request(
                "GET",
                "https://api.phishunt.io/suspicious/feed_json",
                headers={"x-api-key": self.phishunt_api_key},
            )
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
                        "x_opencti_created_by_ref": self.identity["standard_id"],
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
                        created_by_ref=self.identity["standard_id"],
                        confidence=self.helper.connect_confidence_level,
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
                            "x_opencti_created_by_ref": self.identity["standard_id"],
                        },
                    )
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
                        created_by_ref=self.identity["standard_id"],
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
                            "x_opencti_created_by_ref": self.identity["standard_id"],
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
                    stix_location = stix2.Location(
                        id=Location.generate_id(url["country"], "Country"),
                        name=url["country"],
                        country=url["country"],
                        created_by_ref=self.identity["standard_id"],
                        allow_custom=True,
                        custom_properties={"x_opencti_location_type": "Country"},
                    )
                    bundle_objects.append(stix_relationship_domain_ip)
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
            bundle = self.helper.stix2_create_bundle(bundle_objects)
            self.helper.send_stix2_bundle(
                bundle,
                update=self.update_existing_data,
                work_id=work_id,
            )
        except Exception as error:
            self.helper.log_error(str(error))

    def run(self):
        self.helper.log_info("Fetching Phishunt dataset...")
        while True:
            try:
                # Get the current timestamp and check
                timestamp = int(time.time())
                current_state = self.helper.get_state()
                if current_state is not None and "last_run" in current_state:
                    last_run = current_state["last_run"]
                    self.helper.log_info(
                        "Connector last run: "
                        + datetime.utcfromtimestamp(last_run).strftime(
                            "%Y-%m-%d %H:%M:%S"
                        )
                    )
                else:
                    last_run = None
                    self.helper.log_info("Connector has never run")
                # If the last_run is more than interval-1 day
                if last_run is None or (
                    (timestamp - last_run)
                    > ((int(self.phishunt_interval) - 1) * 60 * 60 * 24)
                ):
                    self.helper.log_info("Connector will run!")
                    now = datetime.utcfromtimestamp(timestamp)
                    friendly_name = "Phishunt run @ " + now.strftime(
                        "%Y-%m-%d %H:%M:%S"
                    )
                    work_id = self.helper.api.work.initiate_work(
                        self.helper.connect_id, friendly_name
                    )

                    if len(self.phishunt_api_key) > 0:
                        self._process_private_feed(work_id)
                    else:
                        self._process_public_feed(work_id)

                    # Store the current timestamp as a last run
                    message = "Connector successfully run, storing last_run as " + str(
                        timestamp
                    )
                    self.helper.log_info(message)
                    self.helper.set_state({"last_run": timestamp})
                    self.helper.api.work.to_processed(work_id, message)
                    self.helper.log_info(
                        "Last_run stored, next run in: "
                        + str(round(self.get_interval() / 60 / 60 / 24, 2))
                        + " days"
                    )
                else:
                    new_interval = self.get_interval() - (timestamp - last_run)
                    self.helper.log_info(
                        "Connector will not run, next run in: "
                        + str(round(new_interval / 60 / 60 / 24, 2))
                        + " days"
                    )
            except (KeyboardInterrupt, SystemExit):
                self.helper.log_info("Connector stop")
                sys.exit(0)
            except Exception as error:
                self.helper.log_error(str(error))

            if self.helper.connect_run_and_terminate:
                self.helper.log_info("Connector stop")
                self.helper.force_ping()
                sys.exit(0)

            time.sleep(60)


if __name__ == "__main__":
    try:
        PhishuntConnector = Phishunt()
        PhishuntConnector.run()
    except Exception as e:
        print(e)
        time.sleep(10)
        sys.exit(0)

import datetime as dt
import os
import time
import traceback
from datetime import datetime

import requests
import stix2
import yaml
from dateutil.parser import parse
from pycti import (
    Indicator,
    Malware,
    OpenCTIConnectorHelper,
    StixCoreRelationship,
    get_config_variable,
)


class LIAFileFeed:
    def __init__(self):
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"

        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )

        self.helper = OpenCTIConnectorHelper(config)

        self.api_url = get_config_variable(
            "LIA_BASE_API_URL", ["lia_file_feed", "api_base_url"], config
        )
        self.api_key = get_config_variable(
            "LIA_API_KEY", ["lia_file_feed", "api_key"], config
        )

        self.duration_period = get_config_variable(
            "CONNECTOR_DURATION_PERIOD", ["connector", "duration_period"], config
        )

        self.identity = self.helper.api.identity.create(
            type="Organization",
            name="Loader Insight Agency",
            description="The Loader Insight Agency is a platform that tracks activities of malware loaders through C2 traffic emulation",
        )

    def generate_relationship(self, source_id, target_id, relation_type="based-on"):
        return stix2.Relationship(
            id=StixCoreRelationship.generate_id(relation_type, source_id, target_id),
            relationship_type=relation_type,
            source_ref=source_id,
            target_ref=target_id,
            created_by_ref=self.identity["standard_id"],
            # object_marking_refs=[self.tlp],
        )

    def get_feed_data(self):

        headers = {"Authorization": self.api_key}
        response = requests.get(self.api_url, headers=headers)

        if response.status_code != 200:
            self.helper.connector_logger.error(
                f"Failed to fetch data, status code: {response.status_code}"
            )
            return None

        try:
            return response.json()
        except ValueError as e:
            self.helper.connector_logger.error(f"Error parsing JSON response: {e}")
            return None

    def process_data(self, data):

        stix_objects = []
        relationships = []

        current_time = datetime.now(dt.UTC)

        lia_external_reference = stix2.ExternalReference(
            source_name="Loader Insight Agency",
            url="https://loaderinsight.agency/",
            description="Loader Insight Agency URL",
        )

        for item in data["results"]:
            sha256 = item.get("sha256")
            filetype = item.get("filetype")
            first_seen = item.get("first_seen")
            source_family = item.get("source_family").capitalize()
            source_botnet = item.get("source_botnet")
            size = item.get("size")
            source_url = item.get("source_url")
            detected_as = item.get("detected_as").capitalize()
            external_link = item["external_link"]

            valid_from = parse(first_seen).strftime("%Y-%m-%dT%H:%M:%SZ")

            source_malware_id = Malware.generate_id(source_family)
            source_malware = stix2.Malware(
                id=source_malware_id,
                name=source_family,
                is_family=True,
                last_seen=current_time,
                labels=["malware", "threat"],
                created_by_ref=self.identity["standard_id"],
                external_references=[lia_external_reference],
            )

            stix_objects.append(source_malware)

            detected_malware = None

            if detected_as != "Unknown":
                detected_malware_id = Malware.generate_id(detected_as)
                detected_malware = stix2.Malware(
                    id=detected_malware_id,
                    name=detected_as,
                    is_family=True,
                    last_seen=current_time,
                    labels=["malware", "threat"],
                    created_by_ref=self.identity["standard_id"],
                    external_references=[lia_external_reference],
                )

                stix_objects.append(detected_malware)

            file_observable = stix2.File(
                hashes={"SHA-256": sha256},
                name=f"{detected_as} malware downloaded by {source_family}",
                size=size,
                mime_type=filetype,
            )

            pattern = f"[file:hashes.'SHA-256'='{sha256}']"
            file_indicator = stix2.Indicator(
                pattern=pattern,
                pattern_type="stix",
                id=Indicator.generate_id(pattern),
                valid_from=valid_from,
                name=f"{detected_as} malware downloaded by {source_family}",
                description=f"This indicator represents a file hash observed from downloaded by {source_family}. The payload is detected as {detected_as}",
                labels=["malicious", "file", source_family, source_botnet, detected_as],
                created_by_ref=self.identity["standard_id"],
                custom_properties={"x_opencti_main_observable_type": "File"},
                external_references=[
                    {
                        "source_name": "Loader Insight Agency",
                        "description": f"Payload view of {sha256}",
                        "url": external_link,
                    }
                ],
            )

            pattern = f"[url:value='{source_url}']"
            url_indicator = stix2.Indicator(
                pattern=pattern,
                pattern_type="stix",
                id=Indicator.generate_id(pattern),
                valid_from=valid_from,
                name=f"Malicious source URL indicator: {source_url}",
                description=f"This indicator represents a source URL distributed by a threat actor to the {source_family} malware",
                labels=["malicious", "url", source_family, source_botnet, detected_as],
                created_by_ref=self.identity["standard_id"],
                external_references=[lia_external_reference],
                custom_properties={"x_opencti_main_observable_type": "URL"},
            )

            url_object = stix2.URL(value=source_url)

            stix_objects.extend(
                [file_observable, file_indicator, url_indicator, url_object]
            )

            relationships.append(
                self.generate_relationship(
                    file_indicator.id, file_observable.id, "based-on"
                )
            )
            relationships.append(
                self.generate_relationship(url_indicator.id, url_object.id, "based-on")
            )

            relationships.append(
                self.generate_relationship(
                    source_malware.id, file_observable.id, "downloads"
                )
            )

            relationships.append(
                self.generate_relationship(
                    source_malware.id, url_object.id, "communicates-with"
                )
            )

            if detected_malware:
                relationships.append(
                    self.generate_relationship(
                        source_malware.id, detected_malware.id, "downloads"
                    )
                )
                relationships.append(
                    self.generate_relationship(
                        file_indicator.id, detected_malware.id, "indicates"
                    )
                )

        if stix_objects or relationships:
            bundle = stix2.Bundle(
                objects=stix_objects + relationships, allow_custom=True
            )
            self.helper.send_stix2_bundle(bundle.serialize(), work_id=self.work_id)
            self.helper.connector_logger.info(
                f"Sent bundle with {len(stix_objects)} observables and {len(relationships)} relationships."
            )

    def run_collection(self):

        try:

            # Get the current timestamp and check
            timestamp = int(time.time())
            current_state = self.helper.get_state()
            if current_state is not None and "last_run" in current_state:
                self.helper.connector_logger.info(
                    "Connector last run: "
                    + datetime.fromtimestamp(timestamp, dt.UTC).strftime(
                        "%Y-%m-%d %H:%M:%S %Z"
                    )
                )
            else:
                self.helper.connector_logger.info("Connector has never run")

            timestamp = int(time.time())
            now = datetime.fromtimestamp(timestamp, dt.UTC)
            friendly_name = "Loader Insight Agency File Feed run @ " + now.strftime(
                "%Y-%m-%d %H:%M:%S"
            )

            self.work_id = self.helper.api.work.initiate_work(
                self.helper.connect_id, friendly_name
            )

            self.helper.connector_logger.info(
                f"Starting data fetch @ {now.strftime('%Y-%m-%d %H:%M:%S')}"
            )

            self.helper.connector_logger.debug("Fetching external data...")
            data = self.get_feed_data()
            if "results" in data.keys():
                self.process_data(data)
            else:
                self.helper.connector_logger.info(
                    f"No data retrieved or invalid response: {data}"
                )

            message = "Connector successfully run, storing last_run as " + str(
                timestamp
            )
            self.helper.connector_logger.info(message)
            self.helper.set_state({"last_run": timestamp})
            self.helper.api.work.to_processed(self.work_id, message)

            self.helper.connector_logger.info("Last_run stored")

        except Exception as e:
            self.helper.connector_logger.error(
                f"Error in connector run: {str(e)}, traceback: {traceback.format_exc()}"
            )

    def run(self):
        self.helper.schedule_iso(
            message_callback=self.run_collection,
            duration_period=self.duration_period,
        )


if __name__ == "__main__":
    try:
        connector = LIAFileFeed()
        connector.run()
    except:
        traceback.print_exc()
        exit(1)

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
            "LIA_BASE_API_URL", ["liafilefeed", "api_base_url"], config
        )
        self.api_key = get_config_variable(
            "LIA_API_KEY", ["liafilefeed", "api_key"], config
        )

        self.interval = get_config_variable(
            "LIA_INTERVAL",
            ["liafilefeed", "interval"],
            config,
            True,
        )

        self.identity = self.helper.api.identity.create(
            type="Organization",
            name="Loader Insight Agency",
            description="The Loader Insight Agency is a platform that tracks activities of malware loaders through C2 traffic emulation",
        )

    def get_interval(self):
        return int(self.interval) * 60

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
            self.helper.log_error(
                f"Failed to fetch data, status code: {response.status_code}"
            )
            return None

        try:
            return response.json()
        except ValueError as e:
            self.helper.log_error(f"Error parsing JSON response: {e}")
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

            file_indicator = stix2.Indicator(
                pattern=f"[file:hashes.'SHA-256'='{sha256}']",
                pattern_type="stix",
                valid_from=valid_from,
                name=f"{detected_as} malware downloaded by {source_family}",
                description=f"This indicator represents a file hash observed from downloaded by {source_family}. The payload is detected as {detected_as}",
                labels=["malicious", "file", source_family, source_botnet, detected_as],
                created_by_ref=self.identity["standard_id"],
                external_references=[
                    {
                        "source_name": "Loader Insight Agency",
                        "description": f"Payload view of {sha256}",
                        "url": external_link,
                    }
                ],
            )

            url_indicator = stix2.Indicator(
                pattern=f"[url:value='{source_url}']",
                pattern_type="stix",
                valid_from=valid_from,
                name=f"Malicious source URL indicator: {source_url}",
                description=f"This indicator represents a source URL distributed by a threat actor to the {source_family} malware",
                labels=["malicious", "url", source_family, source_botnet, detected_as],
                created_by_ref=self.identity["standard_id"],
                external_references=[lia_external_reference],
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
            bundle = stix2.Bundle(objects=stix_objects + relationships)
            self.helper.send_stix2_bundle(bundle.serialize(), work_id=self.work_id)
            self.helper.log_info(
                f"Sent bundle with {len(stix_objects)} observables and {len(relationships)} relationships."
            )

    def run(self):
        while True:
            try:

                # Get the current timestamp and check
                timestamp = int(time.time())
                current_state = self.helper.get_state()
                if current_state is not None and "last_run" in current_state:
                    last_run = current_state["last_run"]
                    self.helper.log_info(
                        "Connector last run: "
                        + datetime.fromtimestamp(timestamp, dt.UTC).strftime(
                            "%Y-%m-%d %H:%M:%S %Z"
                        )
                    )
                else:
                    last_run = None
                    self.helper.log_info("Connector has never run")

                if last_run is None or (
                    (timestamp - last_run) > (int(self.interval) * 60)
                ):

                    timestamp = int(time.time())
                    now = datetime.fromtimestamp(timestamp, dt.UTC)
                    friendly_name = (
                        "Loader Insight Agency File Feed run @ "
                        + now.strftime("%Y-%m-%d %H:%M:%S")
                    )

                    self.work_id = self.helper.api.work.initiate_work(
                        self.helper.connect_id, friendly_name
                    )

                    self.helper.log_info(
                        f"Starting data fetch @ {now.strftime('%Y-%m-%d %H:%M:%S')}"
                    )

                    self.helper.log_debug("Fetching external data...")
                    data = self.get_feed_data()
                    if "results" in data.keys():
                        self.process_data(data)
                    else:
                        self.helper.log_info(
                            f"No data retrieved or invalid response: {data}"
                        )

                    message = "Connector successfully run, storing last_run as " + str(
                        timestamp
                    )
                    self.helper.log_info(message)
                    self.helper.set_state({"last_run": timestamp})
                    self.helper.api.work.to_processed(self.work_id, message)

                    self.helper.log_info("Last_run stored")
                else:

                    # wait for next run
                    new_interval = self.get_interval() - (timestamp - last_run)
                    self.helper.log_info(
                        "Connector will not run, next run in: "
                        + str(round(new_interval / 60, 2))
                        + " minutes"
                    )
                    time.sleep(60)

            except Exception as e:
                self.helper.log_error(
                    f"Error in connector run: {str(e)}, traceback: {traceback.format_exc()}"
                )

            # Sleep for the configured interval
            time.sleep(self.interval)


if __name__ == "__main__":
    connector = LIAFileFeed()
    connector.run()

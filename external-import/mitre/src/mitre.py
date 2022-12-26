"""Mitre connector module."""
import json
import os
import ssl
import sys
import time
import urllib
from datetime import datetime
from typing import Optional

import certifi
import yaml
from pycti import OpenCTIConnectorHelper, get_config_variable


class Mitre:
    """Mitre connector."""

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
        self.mitre_enterprise_file_url = get_config_variable(
            "MITRE_ENTERPRISE_FILE_URL", ["mitre", "enterprise_file_url"], config
        )
        self.mitre_pre_attack_file_url = get_config_variable(
            "MITRE_PRE_ATTACK_FILE_URL", ["mitre", "pre_attack_file_url"], config
        )
        self.mitre_mobile_attack_file_url = get_config_variable(
            "MITRE_MOBILE_ATTACK_FILE_URL", ["mitre", "mobile_attack_file_url"], config
        )
        self.mitre_ics_attack_file_url = get_config_variable(
            "MITRE_ICS_ATTACK_FILE_URL", ["mitre", "ics_attack_file_url"], config
        )
        self.mitre_capec_file_url = get_config_variable(
            "MITRE_CAPEC_FILE_URL", ["mitre", "capeck_file_url"], config
        )
        self.mitre_interval = get_config_variable(
            "MITRE_INTERVAL", ["mitre", "interval"], config, True
        )
        self.update_existing_data = get_config_variable(
            "CONNECTOR_UPDATE_EXISTING_DATA",
            ["connector", "update_existing_data"],
            config,
        )

    def get_interval(self):
        return int(self.mitre_interval) * 60 * 60 * 24

    def retrieve_data(self, url: str) -> Optional[dict]:
        """
        Retrieve data from the given url.

        Parameters
        ----------
        url : str
            Url to retrieve.

        Returns
        -------
        str
            A string with the content or None in case of failure.
        """
        try:
            # Fetch json bundle from MITRE
            serialized_bundle = (
                urllib.request.urlopen(
                    url,
                    context=ssl.create_default_context(cafile=certifi.where()),
                )
                .read()
                .decode("utf-8")
            )
            # Convert the data to python dictionary
            stix_bundle = json.loads(serialized_bundle)
            # Filter every revoked MITRE elements
            not_revoked_objects = list(
                filter(
                    lambda stix: stix["revoked"] is False
                    if "revoked" in stix
                    else True,
                    stix_bundle["objects"],
                )
            )
            stix_bundle["objects"] = not_revoked_objects
            # Add default confidence for each object that require this field
            self.add_confidence_to_bundle_objects(stix_bundle)
            return stix_bundle
        except (
            urllib.error.URLError,
            urllib.error.HTTPError,
            urllib.error.ContentTooShortError,
        ) as urllib_error:
            self.helper.log_error(f"Error retrieving url {url}: {urllib_error}")
        return None

    # Add confidence to every object in a bundle
    def add_confidence_to_bundle_objects(self, stix_bundle: dict):
        # the list of object types for which the confidence has to be added
        # (skip marking-definition, identity, external-reference-as-report)
        object_types_with_confidence = [
            "attack-pattern",
            "course-of-action",
            "threat-actor",
            "intrusion-set",
            "campaign",
            "malware",
            "tool",
            "vulnerability",
            "report",
            "relationship",
        ]
        for obj in stix_bundle["objects"]:
            object_type = obj["type"]
            if object_type in object_types_with_confidence:
                # self.helper.log_info(f"Adding confidence to {object_type} object")
                obj["confidence"] = int(self.helper.connect_confidence_level)

    def process_data(self):
        try:
            # Get the current timestamp and check
            timestamp = int(time.time())
            current_state = self.helper.get_state()
            if current_state is not None and "last_run" in current_state:
                last_run = current_state["last_run"]
                self.helper.log_info(
                    "Connector last run: "
                    + datetime.utcfromtimestamp(last_run).strftime("%Y-%m-%d %H:%M:%S")
                )
            else:
                last_run = None
                self.helper.log_info("Connector has never run")
            # If the last_run is more than interval-1 day
            if last_run is None or (
                (timestamp - last_run) > ((int(self.mitre_interval) - 1) * 60 * 60 * 24)
            ):
                self.helper.log_info("Connector will run!")

                now = datetime.utcfromtimestamp(timestamp)
                friendly_name = "MITRE run @ " + now.strftime("%Y-%m-%d %H:%M:%S")
                work_id = self.helper.api.work.initiate_work(
                    self.helper.connect_id, friendly_name
                )
                # MITRE enterprise file url
                if (
                    self.mitre_enterprise_file_url is not None
                    and len(self.mitre_enterprise_file_url) > 0
                ):
                    enterprise_data = self.retrieve_data(self.mitre_enterprise_file_url)
                    self.send_bundle(work_id, enterprise_data)

                # MITRE mobile attack file url
                if (
                    self.mitre_mobile_attack_file_url is not None
                    and len(self.mitre_mobile_attack_file_url) > 0
                ):
                    mobile_attack_data = self.retrieve_data(
                        self.mitre_mobile_attack_file_url
                    )
                    self.send_bundle(work_id, mobile_attack_data)

                # MITRE ICS attack file url
                if (
                    self.mitre_ics_attack_file_url is not None
                    and len(self.mitre_ics_attack_file_url) > 0
                ):
                    ics_attack_data = self.retrieve_data(self.mitre_ics_attack_file_url)
                    self.send_bundle(work_id, ics_attack_data)

                # MITRE CAPEC attack file url
                if (
                    self.mitre_capec_file_url is not None
                    and len(self.mitre_capec_file_url) > 0
                ):
                    capec_data = self.retrieve_data(self.mitre_capec_file_url)
                    self.send_bundle(work_id, capec_data)

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
        except Exception as e:
            self.helper.log_error(str(e))

    def run(self):
        self.helper.log_info("Fetching MITRE datasets...")
        get_run_and_terminate = getattr(self.helper, "get_run_and_terminate", None)
        if callable(get_run_and_terminate) and self.helper.get_run_and_terminate():
            self.process_data()
            self.helper.force_ping()
        else:
            while True:
                self.process_data()
                time.sleep(60)

    def send_bundle(self, work_id: str, stix_bundle: dict) -> None:
        try:
            self.helper.send_stix2_bundle(
                json.dumps(stix_bundle),
                entities_types=self.helper.connect_scope,
                update=self.update_existing_data,
                work_id=work_id,
            )
        except Exception as e:
            self.helper.log_error(f"Error while sending bundle: {e}")


if __name__ == "__main__":
    try:
        mitreConnector = Mitre()
        mitreConnector.run()
    except Exception as e:
        print(e)
        time.sleep(10)
        sys.exit(0)

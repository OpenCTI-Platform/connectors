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

MITRE_ENTERPRISE_FILE_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
MITRE_MOBILE_ATTACK_FILE_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/mobile-attack/mobile-attack.json"
MITRE_ICS_ATTACK_FILE_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/ics-attack/ics-attack.json"
MITRE_CAPEC_FILE_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/capec/2.1/stix-capec.json"
)


def time_from_unixtime(timestamp):
    if not timestamp:
        return None
    return datetime.utcfromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S")


def get_unixtime_now():
    return int(time.time())


def days_to_seconds(days):
    return int(days) * 24 * 60 * 60


def filter_stix_revoked(revoked_ids, stix):
    # Pure revoke
    if stix["id"] in revoked_ids:
        return False
    # Side of relationship revoked
    if stix["type"] == "relationship" and (
        stix["source_ref"] in revoked_ids or stix["target_ref"] in revoked_ids
    ):
        return False
    # Side of sighting revoked
    if stix["type"] == "sighting" and (
        stix["sighting_of_ref"] in revoked_ids
        or any(ref in revoked_ids for ref in stix["where_sighted_refs"])
    ):
        return False
    return True


class Mitre:
    """Mitre connector."""

    def __init__(self):
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config)
        self.update_existing_data = get_config_variable(
            "CONNECTOR_UPDATE_EXISTING_DATA",
            ["connector", "update_existing_data"],
            config,
        )
        self.mitre_interval = get_config_variable(
            "MITRE_INTERVAL", ["mitre", "interval"], config, isNumber=True
        )
        urls = [
            get_config_variable(
                "MITRE_ENTERPRISE_FILE_URL",
                ["mitre", "enterprise_file_url"],
                config,
                default=MITRE_ENTERPRISE_FILE_URL,
            ),
            get_config_variable(
                "MITRE_MOBILE_ATTACK_FILE_URL",
                ["mitre", "mobile_attack_file_url"],
                config,
                default=MITRE_MOBILE_ATTACK_FILE_URL,
            ),
            get_config_variable(
                "MITRE_ICS_ATTACK_FILE_URL",
                ["mitre", "ics_attack_file_url"],
                config,
                default=MITRE_ICS_ATTACK_FILE_URL,
            ),
            get_config_variable(
                "MITRE_CAPEC_FILE_URL",
                ["mitre", "capec_file_url"],
                config,
                default=MITRE_CAPEC_FILE_URL,
            ),
        ]
        self.mitre_urls = list(filter(lambda url: url is not False, urls))
        self.interval = days_to_seconds(self.mitre_interval)

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
            stix_objects = stix_bundle["objects"]
            # First find all revoked ids
            revoked_objects = list(
                filter(
                    lambda stix: stix.get("revoked", False) is True
                    or stix.get("x_capec_status", "") == "Deprecated",
                    stix_objects,
                )
            )
            revoked_ids = list(map(lambda stix: stix["id"], revoked_objects))

            # Filter every revoked MITRE elements
            not_revoked_objects = list(
                filter(
                    lambda stix: filter_stix_revoked(revoked_ids, stix), stix_objects
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
        unixtime_now = get_unixtime_now()
        time_now = time_from_unixtime(unixtime_now)

        current_state = self.helper.get_state()
        last_run = current_state.get("last_run", None) if current_state else None
        self.helper.log_debug(f"Connector last run: {time_from_unixtime(last_run)}")

        if last_run and self.interval > unixtime_now - last_run:
            self.helper.log_debug("Connector will not run this time.")
            return

        self.helper.log_info(f"Connector will run now {time_now}.")
        friendly_name = f"MITRE run @ {time_now}"
        work_id = self.helper.api.work.initiate_work(
            self.helper.connect_id, friendly_name
        )

        self.helper.log_info("Fetching MITRE datasets...")
        for url in self.mitre_urls:
            self.helper.log_debug(f"Fetching {url}...")
            data = self.retrieve_data(url)

            if not data:
                continue

            self.helper.send_stix2_bundle(
                json.dumps(data),
                entities_types=self.helper.connect_scope,
                update=self.update_existing_data,
                work_id=work_id,
            )

        message = f"Connector successfully run, storing last_run as {time_now}"
        self.helper.log_info(message)
        self.helper.set_state({"last_run": unixtime_now})
        self.helper.api.work.to_processed(work_id, message)

    def run(self):
        get_run_and_terminate = getattr(self.helper, "get_run_and_terminate", None)

        if callable(get_run_and_terminate) and self.helper.get_run_and_terminate():
            self.process_data()
            self.helper.force_ping()
            return

        while True:
            try:
                self.process_data()
            except (KeyboardInterrupt, SystemExit):
                self.helper.log_info("Connector stop")
                sys.exit(0)
            except Exception as e:
                self.helper.log_error(str(e))
            finally:
                time.sleep(60)


if __name__ == "__main__":
    try:
        mitreConnector = Mitre()
        mitreConnector.run()
    except Exception as e:
        print(e)
        time.sleep(10)
        sys.exit(0)

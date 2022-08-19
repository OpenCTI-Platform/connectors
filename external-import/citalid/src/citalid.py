import json
import os
import sys
import time
import yaml

from datetime import datetime
from pycti import OpenCTIConnectorHelper, get_config_variable


class Citalid:
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
        self.citalid_files_path = get_config_variable(
            "CITALID_FILES_PATH", ["citalid", "files_path"], config
        )
        self.citalid_interval = get_config_variable(
            "CITALID_INTERVAL", ["citalid", "interval"], config, True
        )
        self.citalid_start_date = get_config_variable(
            "CITALID_START_DATE", ["citalid", "start_date"], config, True
        )
        self.update_existing_data = get_config_variable(
            "CONNECTOR_UPDATE_EXISTING_DATA",
            ["connector", "update_existing_data"],
            config,
        )

    def get_interval(self):
        return int(self.citalid_interval) * 60

    # Add confidence to every object in a bundle
    def add_confidence_to_bundle_objects(self, serialized_bundle: str) -> str:
        # the list of object types for which the confidence has to be added
        # (skip marking-definition, identity, external-reference-as-report)
        object_types_with_confidence = [
            "attack-pattern",
            "course-of-action",
            "intrusion-set",
            "campaign",
            "malware",
            "tool",
            "report",
            "relationship",
        ]
        stix_bundle = json.loads(serialized_bundle)
        for obj in stix_bundle["objects"]:
            object_type = obj["type"]
            if object_type in object_types_with_confidence:
                # self.helper.log_info(f"Adding confidence to {object_type} object")
                obj["confidence"] = int(self.helper.connect_confidence_level)
        return json.dumps(stix_bundle)

    def process_data(self):
        try:
            # Get the current timestamp and check
            current_state = self.helper.get_state()
            if current_state is None or "last_timestamp" not in current_state:
                self.helper.set_state({"last_timestamp": self.citalid_start_date})
                timestamp = self.citalid_start_date
            else:
                timestamp = current_state["last_timestamp"]

            now = datetime.utcfromtimestamp(timestamp)
            friendly_name = "Citalid run @ " + now.strftime("%Y-%m-%d %H:%M:%S")
            work_id = self.helper.api.work.initiate_work(
                self.helper.connect_id, friendly_name
            )
            last_timestamp = timestamp
            for f in sorted(os.listdir(self.citalid_files_path)):
                file_timestamp = int(f.split("_")[0])
                file_date = datetime.utcfromtimestamp(file_timestamp).strftime(
                    "%Y-%m-%d %H:%M:%S"
                )
                if file_timestamp > last_timestamp:
                    self.helper.log_info('Processing file "' + file_date + '"')
                    bundle_file = open(self.citalid_files_path + "/" + f)
                    bundle = bundle_file.read()
                    bundle_file.close()
                    bundle_with_confidence = self.add_confidence_to_bundle_objects(
                        bundle
                    )
                    self.send_bundle(work_id, bundle_with_confidence)
                    last_timestamp = file_timestamp
            # Store the current timestamp as a last run
            message = "Connector successfully run, storing last_timestamp as " + str(
                last_timestamp
            )
            self.helper.log_info(message)
            self.helper.set_state({"last_timestamp": last_timestamp})
            self.helper.api.work.to_processed(work_id, message)
        except (KeyboardInterrupt, SystemExit):
            self.helper.log_info("Connector stop")
            sys.exit(0)
        except Exception as e:
            self.helper.log_error(str(e))

    def send_bundle(self, work_id: str, serialized_bundle: str) -> None:
        try:
            self.helper.send_stix2_bundle(
                serialized_bundle,
                entities_types=self.helper.connect_scope,
                update=self.update_existing_data,
                work_id=work_id,
            )
        except Exception as e:
            self.helper.log_error(f"Error while sending bundle: {e}")

    def run(self):
        self.helper.log_info("Fetching Citalid datasets...")
        get_run_and_terminate = getattr(self.helper, "get_run_and_terminate", None)
        if callable(get_run_and_terminate) and self.helper.get_run_and_terminate():
            self.process_data()
            self.helper.force_ping()
        else:
            while True:
                self.process_data()
                time.sleep(self.get_interval())


if __name__ == "__main__":
    try:
        citalidConnector = Citalid()
        citalidConnector.run()
    except Exception as e:
        print(e)
        time.sleep(10)
        sys.exit(0)

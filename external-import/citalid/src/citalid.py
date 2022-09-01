import json
import os
import sys
import time
from datetime import datetime
from dateutil.parser import parse

import yaml
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

        # Create the Citalid identity
        self.identity = self.helper.api.identity.create(
            type="Organization",
            name="Citalid",
            description="Citalid is a french software vendor specilized in cyber risk management.",
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

    # Citalid special processing for object
    def process_bundle(self, serialized_bundle: str) -> str:
        stix_bundle = json.loads(serialized_bundle)
        new_objects = []
        for obj in stix_bundle["objects"]:
            new_obj = {k: v for k, v in obj.items() if v is not None}
            if "created_by_ref" not in new_obj:
                new_obj["created_by_ref"] = self.identity["standard_id"]
            elif (
                new_obj["created_by_ref"]
                == "identity--0a8152ea-b13f-6fca-3742-6752c12f0858"
            ):
                new_obj["created_by_ref"] = self.identity["standard_id"]
            if "created" in new_obj:
                new_obj["created"] = parse(new_obj["created"]).strftime(
                    "%Y-%m-%dT%H:%M:%SZ"
                )
            if "modified" in new_obj:
                new_obj["modified"] = parse(new_obj["modified"]).strftime(
                    "%Y-%m-%dT%H:%M:%SZ"
                )
            if "published" in new_obj:
                new_obj["published"] = parse(new_obj["published"]).strftime(
                    "%Y-%m-%dT%H:%M:%SZ"
                )
            if "start_time" in new_obj:
                new_obj["start_time"] = parse(new_obj["start_time"]).strftime(
                    "%Y-%m-%dT%H:%M:%SZ"
                )
            if "stop_time" in new_obj:
                new_obj["stop_time"] = parse(new_obj["stop_time"]).strftime(
                    "%Y-%m-%dT%H:%M:%SZ"
                )
            if new_obj["type"] == "report":
                if "title" in new_obj and "name" not in new_obj:
                    new_obj["name"] = new_obj["title"]
                if "report--" not in new_obj["id"]:
                    new_obj["id"] = "report--" + new_obj["id"]
            if new_obj["type"] == "location":
                if (
                    "x_citalid_location_type" in new_obj
                    and new_obj["x_citalid_location_type"] == "country"
                ):
                    new_obj["x_opencti_location_type"] = "Country"
            if "objects_refs" in new_obj:
                new_obj["object_refs"] = new_obj["objects_refs"]
            new_objects.append(new_obj)
        stix_bundle["objects"] = new_objects
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
                    bundle_processed = self.process_bundle(bundle)
                    bundle_with_confidence = self.add_confidence_to_bundle_objects(
                        bundle_processed
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

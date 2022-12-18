import datetime
import json
import os
import sys
import time

import cabby
import pytz
import yaml
from dateutil.parser import parse
from pycti import OpenCTIConnectorHelper, get_config_variable


class Eset:
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
        self.eset_api_url = get_config_variable(
            "ESET_API_URL", ["eset", "api_url"], config
        )
        self.eset_username = get_config_variable(
            "ESET_USERNAME", ["eset", "username"], config
        )
        self.eset_password = get_config_variable(
            "ESET_PASSWORD", ["eset", "password"], config
        )
        self.eset_collections = get_config_variable(
            "ESET_COLLECTIONS", ["eset", "collections"], config
        ).split(",")
        self.eset_import_start_date = get_config_variable(
            "ESET_IMPORT_START_DATE",
            ["eset", "import_start_date"],
            config,
        )
        self.eset_create_observables = get_config_variable(
            "ESET_CREATE_OBSERVABLES",
            ["eset", "create_observables"],
            config,
        )
        self.eset_interval = get_config_variable(
            "ESET_INTERVAL", ["eset", "interval"], config, True
        )
        self.update_existing_data = get_config_variable(
            "CONNECTOR_UPDATE_EXISTING_DATA",
            ["connector", "update_existing_data"],
            config,
        )
        self.identity = self.helper.api.identity.create(
            type="Organization",
            name="ESET",
            description="ESET, s.r.o., is a software company specializing in cybersecurity.",
        )
        self.added_after = int(parse(self.eset_import_start_date).timestamp())
        # Init variables
        self.cache = {}

    def get_interval(self):
        return int(self.eset_interval) * 60

    def _import_collection(self, collection, work_id, start_epoch):
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
            "indicator",
        ]
        client = cabby.create_client(
            self.eset_api_url, discovery_path="/taxiiservice/discovery", use_https=True
        )
        client.set_auth(username=self.eset_username, password=self.eset_password)
        no_more_result = False
        end_epoch = start_epoch + 3600
        while no_more_result is False:
            self.helper.log_info(
                "Iterating with collection="
                + str(collection)
                + ", start_epoch="
                + str(start_epoch)
                + ", end_epoch="
                + str(end_epoch)
            )
            begin_date = datetime.datetime.utcfromtimestamp(start_epoch).astimezone(
                pytz.utc
            )
            end_date = datetime.datetime.utcfromtimestamp(end_epoch).astimezone(
                pytz.utc
            )
            for item in client.poll(
                collection + " (stix2)", begin_date=begin_date, end_date=end_date
            ):
                if not item.content:  # Skip empty packages.
                    continue
                parsed_content = json.loads(item.content)
                objects = []
                for object in parsed_content["objects"]:
                    if "confidence" in object_types_with_confidence:
                        if "confidence" not in object:
                            object["confidence"] = int(
                                self.helper.connect_confidence_level
                            )
                    if object["type"] == "indicator":
                        object["name"] = object["pattern"]
                        object["pattern_type"] = "stix"
                        object["pattern"] = (
                            object["pattern"]
                            .replace("SHA1", "'SHA-1'")
                            .replace("SHA256", "'SHA-256'")
                        )
                        if self.eset_create_observables:
                            object[
                                "x_opencti_create_observables"
                            ] = self.eset_create_observables
                    objects.append(object)
                parsed_content["objects"] = objects
                self.helper.send_stix2_bundle(
                    json.dumps(parsed_content),
                    update=self.update_existing_data,
                    work_id=work_id,
                )
            if end_epoch > int(time.time()):
                no_more_result = True
            else:
                start_epoch = end_epoch
                end_epoch = start_epoch + 3600

    def run(self):
        while True:
            try:
                self.helper.log_info("Synchronizing with ESET API...")
                timestamp = int(time.time())
                now = datetime.datetime.utcfromtimestamp(timestamp)
                friendly_name = "ESET run @ " + now.strftime("%Y-%m-%d %H:%M:%S")
                work_id = self.helper.api.work.initiate_work(
                    self.helper.connect_id, friendly_name
                )
                current_state = self.helper.get_state()
                if current_state is None:
                    self.helper.set_state({"last_run": self.added_after})
                # Get collections
                current_state = self.helper.get_state()
                for collection in self.eset_collections:
                    self._import_collection(
                        collection, work_id, current_state["last_run"]
                    )
                self.helper.set_state({"last_run": timestamp})
                message = "End of synchronization"
                self.helper.api.work.to_processed(work_id, message)
                self.helper.log_info(message)

                if self.helper.connect_run_and_terminate:
                    self.helper.log_info("Connector stop")
                    sys.exit(0)

                time.sleep(self.get_interval())
            except (KeyboardInterrupt, SystemExit):
                self.helper.log_info("Connector stop")
                sys.exit(0)

            except Exception as e:
                self.helper.log_error(str(e))

                if self.helper.connect_run_and_terminate:
                    self.helper.log_info("Connector stop")
                    sys.exit(0)

                time.sleep(60)


if __name__ == "__main__":
    try:
        esetConnector = Eset()
        esetConnector.run()
    except Exception as e:
        print(e)
        time.sleep(10)
        sys.exit(0)

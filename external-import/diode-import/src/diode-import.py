import glob
import json
import os
import sys
import time
from collections import defaultdict

import yaml
from pycti import OpenCTIConnector, OpenCTIConnectorHelper, get_config_variable


class DiodeImport:
    def __init__(self):
        # Instantiate the connector helper from config
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        # Build applicant mappings
        opencti_applicant_mappings = get_config_variable(
            "DIODE_IMPORT_APPLICANT_MAPPINGS",
            ["diode_import", "applicant_mappings"],
            config,
            False,
        )
        mappings_dict = defaultdict()  # uses set to avoid duplicates
        for mapping in opencti_applicant_mappings.split(","):
            mapping_def = mapping.split(":")
            mappings_dict[mapping_def[0]] = mapping_def[1]
        self.applicant_mappings = mappings_dict
        # Other configurations
        self.get_from_directory_path = get_config_variable(
            "DIODE_IMPORT_GET_FROM_DIRECTORY_PATH",
            ["diode_import", "get_from_directory_path"],
            config,
            False,
        )
        self.get_from_directory_retention = get_config_variable(
            "DIODE_IMPORT_GET_FROM_DIRECTORY_RETENTION",
            ["diode_import", "get_from_directory_retention"],
            config,
            True,
            7,
        )
        self.connectors_cache = {}
        self.helper = OpenCTIConnectorHelper(config)

    def process(self):
        current_state = self.helper.get_state()
        # This is my path
        path = os.path.join(self.get_from_directory_path, "*.json")
        # Prints all types of txt files present in a Path
        file_paths = glob.glob(path, recursive=True)
        file_paths.sort(key=os.path.getctime)
        for file_path in file_paths:

            # Fetch file content
            file = open(file_path, mode="r")
            file_content = file.read()
            file.close()
            ti_m = os.path.getctime(file_path)
            # Check current state to prevent duplication
            if current_state and current_state.get("last_run", 0) >= ti_m:
                continue
            # region Parse and handle
            json_content = json.loads(file_content)

            connector = json_content.get("connector")
            applicant_id = json_content.get("applicant_id")

            if connector is None or applicant_id is None:
                self.helper.connector_logger.error(
                    "An error occurred because JSON keys are incorrect or missing.",
                    {"connector": connector, "applicant_id": applicant_id},
                )
                continue

            connector_id = connector.get("id")

            # endregion
            # region Register the connector in OpenCTI to simulate the real activity if not in cache
            if self.connectors_cache.get(connector_id) is None:
                connector_registration = OpenCTIConnector(
                    connector.get("id"),
                    connector.get("name"),
                    connector.get("type"),
                    connector.get("scope"),
                    connector.get("auto"),
                    False,
                    False,
                )
                self.helper.api.connector.register(connector_registration)
                self.connectors_cache[connector_id] = connector_id
            # endregion
            # region Setup the helper
            self.helper.connect_id = connector_id
            self.helper.connect_validate_before_import = connector.get(
                "validate_before_import", False
            )
            self.helper.applicant_id = self.applicant_mappings.get(applicant_id)
            # endregion
            # region Send data to the correct queue with the correct options
            friendly_name = f"{connector.get('name')} run @ {time.ctime(ti_m)}"
            work_id = self.helper.api.work.initiate_work(
                self.helper.connect_id, friendly_name
            )
            self.helper.send_stix2_bundle(
                json.dumps(json_content.get("bundle")),
                entities_types=self.helper.connect_scope,
                update=json_content.get("update", False),
                work_id=work_id,
            )
            self.helper.api.work.to_processed(work_id, "Connector successfully run")
            self.helper.set_state({"last_run": ti_m})
            # endregion
        # Remove files
        if self.get_from_directory_retention > 0:  # If 0, disable the auto remove
            current_time = time.time()
            for delete_file in file_paths:
                file_time = os.stat(delete_file).st_mtime
                is_expired_file = (
                    file_time < current_time - 86400 * self.get_from_directory_retention
                )  # 86400 = 1 day
                if is_expired_file:
                    os.remove(delete_file)

    def run(self):
        get_run_and_terminate = getattr(self.helper, "get_run_and_terminate", False)
        if callable(get_run_and_terminate) and self.helper.get_run_and_terminate():
            self.process()
            self.helper.force_ping()
        else:
            while True:
                self.process()
                time.sleep(60)


if __name__ == "__main__":
    try:
        diodeImport = DiodeImport()
        diodeImport.run()
    except Exception as e:
        print(e)
        time.sleep(10)
        sys.exit(0)

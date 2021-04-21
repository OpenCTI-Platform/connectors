################################
# Tanium Connector for OpenCTI #
################################

import os
import yaml
import json
import time

from datetime import datetime
from pycti import OpenCTIConnectorHelper, get_config_variable
from intel_cache import IntelCache
from import_manager import IntelManager
from tanium_api_handler import TaniumApiHandler


class TaniumConnector:
    def __init__(self):
        # Initialize parameters and OpenCTI helper
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config)
        self.helper.set_state(
            {"connectorLastEventId": int(round(time.time() * 1000)) - 1000}
        )

        # Initialize the Tanium API Handler
        tanium_url = get_config_variable("TANIUM_URL", ["tanium", "url"], config)
        tanium_ssl_verify = get_config_variable(
            "TANIUM_SSL_VERIFY", ["tanium", "ssl_verify"], config, False, True
        )
        tanium_login = get_config_variable("TANIUM_LOGIN", ["tanium", "login"], config)
        tanium_password = get_config_variable(
            "TANIUM_PASSWORD", ["tanium", "password"], config
        )
        # Launch quickscan automatically (true/false)
        self.tanium_auto_quickscan = get_config_variable(
            "TANIUM_AUTO_QUICKSCAN", ["tanium", "auto_quickscan"], config, False, False
        )
        # Target computer groups of the automatic quickscan (if enable)
        self.tanium_computer_groups = get_config_variable(
            "TANIUM_COMPUTER_GROUPS", ["tanium", "computer_groups"], config, False, ""
        ).split(",")
        self.tanium_api_handler = TaniumApiHandler(
            self.helper,
            tanium_url,
            tanium_login,
            tanium_password,
            tanium_ssl_verify,
            self.tanium_auto_quickscan,
            self.tanium_computer_groups,
        )

        # Initialize managers
        self.intel_cache = IntelCache(self.helper)
        self.import_manager = IntelManager(
            self.helper, self.tanium_api_handler, self.intel_cache
        )

        # Filters & conditions

        # Types of indicators to synchronize
        self.tanium_indicator_types = get_config_variable(
            "TANIUM_INDICATOR_TYPES", ["tanium", "indicator_types"], config
        ).split(",")
        # Types of observables to synchronize
        self.tanium_observable_types = get_config_variable(
            "TANIUM_OBSERVABLE_TYPES", ["tanium", "observable_types"], config
        ).split(",")
        # Synchronize only the given labels (or everything using "*")
        self.tanium_import_label = get_config_variable(
            "TANIUM_IMPORT_LABEL", ["tanium", "import_label"], config, False, ""
        )
        # Synchronize hashes to Reputation using the given label (or everything using "*")
        self.tanium_reputation_blacklist_label = get_config_variable(
            "TANIUM_REPUTATION_BLACKLIST_LABEL",
            ["tanium", "reputation_blacklist_label"],
            config,
            False,
            "",
        )

    def handle_create_indicator(self, data):
        self.helper.log_info("[CREATE] Processing indicator {" + data["id"] + "}")
        # If import everything as intel
        if self.tanium_import_label == "*":
            self.import_manager.import_intel_from_indicator(data)
            return
        # If no label in this creation and import if filtered
        if "labels" not in data:
            self.helper.log_info(
                "[CREATE] No label corresponding to import filter, doing nothing"
            )
            return
        # If label corresponds
        if self.tanium_import_label in data["labels"]:
            self.import_manager.import_intel_from_indicator(data)
            return
        else:
            self.helper.log_info(
                "[CREATE] No label corresponding to import filter, doing nothing"
            )
        return

    def handle_create_observable(self, data):
        self.helper.log_info("[CREATE] Processing observable {" + data["id"] + "}")
        # if import everything as intel
        if self.tanium_import_label == "*":
            self.import_manager.import_intel_from_observable(data)
        # If file and import everything
        if self.tanium_reputation_blacklist_label == "*":
            self.import_manager.import_reputation(data)
            return
        # If no label in this creation and import if filtered
        if "labels" not in data:
            self.helper.log_info(
                "[CREATE] No label corresponding to import filter, doing nothing"
            )
            return
        # If label corresponds
        if self.tanium_import_label in data["labels"]:
            self.import_manager.import_intel_from_observable(data)
        if self.tanium_reputation_blacklist_label in data["labels"]:
            self.import_manager.import_reputation(data)
        return

    def handle_update_indicator(self, data):
        self.helper.log_info("[UPDATE] Processing indicator {" + data["id"] + "}")
        # New labels have been added and correspond to filter
        if (
            "x_data_update" in data
            and "add" in data["x_data_update"]
            and "labels" in data["x_data_update"]["add"]
            and self.tanium_import_label in data["x_data_update"]["add"]["labels"]
        ):
            # Get the indicator to have the pattern_type
            entity = self.helper.api.indicator.read(id=data["x_opencti_id"])
            data["name"] = entity["name"]
            data["pattern"] = entity["pattern"]
            data["pattern_type"] = entity["pattern_type"]
            if "x_mitre_platforms" in entity:
                data["x_mitre_platforms"] = entity["x_mitre_platforms"]
            self.import_manager.import_intel_from_indicator(data)
            return
        # Labels have been removed and correspond to filter
        if (
            "x_data_update" in data
            and "remove" in data["x_data_update"]
            and "labels" in data["x_data_update"]["remove"]
            and self.tanium_import_label in data["x_data_update"]["remove"]["labels"]
        ):
            self.import_manager.delete_intel(data)
            return
        if (
            "x_data_update" in data
            and "replace" in data["x_data_update"]
            and "pattern" in data["x_data_update"]["replace"]
        ):
            self.import_manager.import_intel_from_indicator(data, True)
            return

    def handle_update_observable(self, data):
        self.helper.log_info("[UPDATE] Processing observable {" + data["id"] + "}")
        # Label has been added and corresponds to filter
        if (
            "x_data_update" in data
            and "add" in data["x_data_update"]
            and "labels" in data["x_data_update"]["add"]
        ):
            # For intels
            if self.tanium_import_label in data["x_data_update"]["add"]["labels"]:
                # Get the indicator to have the pattern_type
                entity = self.helper.api.stix_cyber_observable.read(
                    id=data["x_opencti_id"]
                )
                if "value" in entity:
                    data["value"] = entity["value"]
                if "hashes" in entity:
                    data["hashes"] = entity["hashes"]
                self.import_manager.import_intel_from_observable(data)
            # For reputation
            if (
                self.tanium_reputation_blacklist_label
                in data["x_data_update"]["add"]["labels"]
            ):
                entity = self.helper.api.stix_cyber_observable.read(
                    id=data["x_opencti_id"]
                )
                if "value" in entity:
                    data["value"] = entity["value"]
                if "hashes" in entity:
                    data["hashes"] = entity["hashes"]
                self.import_manager.import_reputation(data)
            return
        if (
            "x_data_update" in data
            and "remove" in data["x_data_update"]
            and "labels" in data["x_data_update"]["remove"]
            and self.tanium_import_label in data["x_data_update"]["remove"]["labels"]
        ):
            self.import_manager.delete_intel(data)
            return

    def handle_delete_indicator(self, data):
        self.import_manager.delete_intel(data)
        return

    def handle_delete_observable(self, data):
        self.import_manager.delete_intel(data)
        self.import_manager.delete_reputation(data)
        return

    def _process_message(self, msg):
        try:
            event_id = msg.id
            date = datetime.fromtimestamp(round(int(event_id.split("-")[0]) / 1000))
            data = json.loads(msg.data)["data"]
        except:
            raise ValueError("Cannot process the message: " + msg)
        # Ignore types which will not be processed
        self.helper.log_info(
            "[PROCESS] Message (id: " + event_id + ", date: " + str(date) + ")"
        )
        if ("revoked" in data and data["revoked"] is True) or (
            data["type"] != "indicator"
            and data["type"] not in self.tanium_observable_types
        ):
            self.helper.log_info(
                "[PROCESS] Doing nothing, entity type not in import filter or entity revoked"
            )
            return
        # Handle creation
        if msg.event == "create":
            if (
                data["type"] == "indicator"
                and data["pattern_type"] in self.tanium_indicator_types
            ):
                return self.handle_create_indicator(data)
            if data["type"] in self.tanium_observable_types:
                return self.handle_create_observable(data)
            return None
        # Handle update
        if msg.event == "update":
            if data["type"] == "indicator":
                return self.handle_update_indicator(data)
            if data["type"] in self.tanium_observable_types:
                return self.handle_update_observable(data)
            return None
        # Handle delete
        elif msg.event == "delete":
            if data["type"] == "indicator":
                return self.handle_delete_indicator(data)
            if data["type"] in self.tanium_observable_types:
                return self.handle_delete_observable(data)
            return None
        return None

    def start(self):
        self.helper.listen_stream(self._process_message)


if __name__ == "__main__":
    TaniumInstance = TaniumConnector()
    TaniumInstance.start()

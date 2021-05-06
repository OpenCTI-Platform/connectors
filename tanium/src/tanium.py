################################################
# Tanium Connector for OpenCTI                 #
################################################

import os
import time

import yaml
import json

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

        # Check Live Stream ID
        if (
            self.helper.connect_live_stream_id is None
            or self.helper.connect_live_stream_id == "ChangeMe"
        ):
            raise ValueError("Missing Live Stream ID")

        # Initialize Tanium API
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

    def _process_message(self, msg):
        try:
            data = json.loads(msg.data)["data"]
        except:
            raise ValueError("Cannot process the message: " + msg)
        # Handle creation
        if msg.event == "create":
            if data["type"] == "indicator":
                self.helper.log_info(
                    "[CREATE] Processing indicator {" + data["id"] + "}"
                )
                return self.import_manager.import_intel_from_indicator(data)
            if data["type"] in [
                "ipv4-addr",
                "ipv6-addr",
                "domain-name",
                "x-opencti-hostname",
                "file",
                "artifact",
                "process",
            ]:
                self.helper.log_info(
                    "[CREATE] Processing observable {" + data["id"] + "}"
                )
                return self.import_manager.import_intel_from_observable(data)
            return None
        # Handle update
        if msg.event == "update":
            if data["type"] == "indicator":
                self.helper.log_info(
                    "[UPDATE] Processing indicator {" + data["id"] + "}"
                )
                return self.import_manager.import_intel_from_indicator(data, True)
            if data["type"] in [
                "ipv4-addr",
                "ipv6-addr",
                "domain-name",
                "x-opencti-hostname",
                "file",
                "artifact",
                "process",
            ]:
                self.helper.log_info(
                    "[UPDATE] Processing observable {" + data["id"] + "}"
                )
                return self.import_manager.import_intel_from_observable(data, True)
            return None
        # Handle delete
        elif msg.event == "delete":
            if data["type"] == "indicator":
                return self.import_manager.delete_intel(data)
            if data["type"] in [
                "ipv4-addr",
                "ipv6-addr",
                "domain-name",
                "x-opencti-hostname",
                "file",
                "artifact",
                "process",
            ]:
                return self.import_manager.delete_intel(data)
            return None
        return None

    def start(self):
        self.helper.listen_stream(self._process_message)


if __name__ == "__main__":
    TaniumInstance = TaniumConnector()
    TaniumInstance.start()

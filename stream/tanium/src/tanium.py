################################################
# Tanium Connector for OpenCTI                 #
################################################

import json
import os

import yaml
from import_manager import IntelManager
from intel_cache import IntelCache
from pycti import OpenCTIConnectorHelper, get_config_variable
from sightings import Sightings
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
        self.tanium_url = get_config_variable("TANIUM_URL", ["tanium", "url"], config)
        self.tanium_ssl_verify = get_config_variable(
            "TANIUM_SSL_VERIFY", ["tanium", "ssl_verify"], config, False, True
        )
        self.tanium_login = get_config_variable(
            "TANIUM_LOGIN", ["tanium", "login"], config
        )
        self.tanium_password = get_config_variable(
            "TANIUM_PASSWORD", ["tanium", "password"], config
        )
        self.tanium_hashes_in_reputation = get_config_variable(
            "TANIUM_HASHES_IN_REPUTATION",
            ["tanium", "hashes_in_reputation"],
            config,
            False,
            True,
        )
        self.tanium_no_hashes_in_intels = get_config_variable(
            "TANIUM_NO_HASHES_IN_INTELS",
            ["tanium", "no_hashes_in_intels"],
            config,
            False,
            True,
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
            self.tanium_url,
            self.tanium_login,
            self.tanium_password,
            self.tanium_ssl_verify,
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
            raise ValueError("Cannot process the message")
        # Handle creation
        if msg.event == "create":
            if data["type"] == "indicator":
                self.helper.log_info(
                    "[CREATE] Processing indicator {"
                    + OpenCTIConnectorHelper.get_attribute_in_extension("id", data)
                    + "}"
                )
                self.import_manager.import_intel_from_indicator(data)
            elif data["type"] in [
                "ipv4-addr",
                "ipv6-addr",
                "domain-name",
                "hostname",
                "process",
            ]:
                self.helper.log_info(
                    "[CREATE] Processing observable {"
                    + OpenCTIConnectorHelper.get_attribute_in_extension("id", data)
                    + "}"
                )
                self.import_manager.import_intel_from_observable(data)
            elif data["type"] in ["file", "artifact"]:
                if self.tanium_hashes_in_reputation:
                    self.import_manager.import_reputation(data)
                if not self.tanium_no_hashes_in_intels:
                    self.import_manager.import_intel_from_observable(data)
            return
        # Handle update
        if msg.event == "update":
            if data["type"] == "indicator":
                self.helper.log_info(
                    "[UPDATE] Processing indicator {"
                    + OpenCTIConnectorHelper.get_attribute_in_extension("id", data)
                    + "}"
                )
                self.import_manager.import_intel_from_indicator(data, True)
            elif data["type"] in [
                "ipv4-addr",
                "ipv6-addr",
                "domain-name",
                "hostname",
                "file",
                "artifact",
                "process",
            ]:
                self.helper.log_info(
                    "[UPDATE] Processing observable {"
                    + OpenCTIConnectorHelper.get_attribute_in_extension("id", data)
                    + "}"
                )
                self.import_manager.import_intel_from_observable(data, True)
            return
        # Handle delete
        elif msg.event == "delete":
            if data["type"] == "indicator":
                self.import_manager.delete_intel(data)
            elif data["type"] in [
                "ipv4-addr",
                "ipv6-addr",
                "domain-name",
                "hostname",
            ]:
                self.import_manager.delete_intel(data)
            elif data["type"] in ["file", "artifact"]:
                self.import_manager.delete_intel(data)
                self.import_manager.delete_reputation(data)
            return
        return

    def start(self):
        self.sightings = Sightings(self.helper, self.tanium_api_handler)
        self.sightings.start()
        self.helper.listen_stream(self._process_message)


if __name__ == "__main__":
    TaniumInstance = TaniumConnector()
    TaniumInstance.start()

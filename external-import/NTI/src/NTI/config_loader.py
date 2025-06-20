import os
import traceback
from pathlib import Path

import yaml
from pycti import get_config_variable


class ConfigConnector:
    def __init__(self):
        """
        Initialize the connector with necessary configurations
        """
        self.duration_period = "P1D"
        self.nti_base_url = "https://nti.nsfocusglobal.com/api/v2/"
        self.package_type = "updated"
        self.create_tasks = {
            "IOC": False,
            "IP": False,
            "Domain": False,
            "URL": False,
            "File": False,
        }
        self.ns_nti_key = None
        self.tlp_level = "white"

        # Load configuration file
        self.load = self._load_config()

    @staticmethod
    def _load_config() -> dict:
        """
        Load the configuration from the YAML file
        :return: Configuration dictionary
        """
        config_file_path = Path(__file__).parents[1].joinpath("config.yml")
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        return config

    def initialize_configurations(self, helper) -> None:
        """
        Connector configuration variables
        :return: None
        """
        try:
            # OpenCTI configurations
            self.duration_period = get_config_variable(
                "CONNECTOR_DURATION_PERIOD",
                ["connector", "duration_period"],
                self.load,
            )
            self.nti_base_url = get_config_variable(
                "NTI_BASE_URL", ["NSFOCUS", "nti_base_url"], self.load
            )
            self.package_type = get_config_variable(
                "NTI_PACKAGE_TYPE", ["NSFOCUS", "nti_package_type"], self.load
            )

            self.create_tasks["IOC"] = get_config_variable(
                "NTI_CREATE_IOC", ["NSFOCUS", "nti_create_ioc"], self.load
            )
            self.create_tasks["IP"] = get_config_variable(
                "NTI_CREATE_IP", ["NSFOCUS", "nti_create_ip"], self.load
            )
            self.create_tasks["Domain"] = get_config_variable(
                "NTI_CREATE_DOMAIN", ["NSFOCUS", "nti_create_domain"], self.load
            )
            self.create_tasks["URL"] = get_config_variable(
                "NTI_CREATE_URL", ["NSFOCUS", "nti_create_url"], self.load
            )
            self.create_tasks["File"] = get_config_variable(
                "NTI_CREATE_FILE", ["NSFOCUS", "nti_create_file"], self.load
            )

            self.ns_nti_key = get_config_variable(
                "NTI_API_KEY", ["NSFOCUS", "nti_api_key"], self.load
            )
            self.tlp_level = get_config_variable(
                "NTI_TLP", ["NSFOCUS", "nti_tlp"], self.load
            ).lower()
        except:
            helper.connector_logger.error(
                f"[init config] init config error: {traceback.format_exc()}"
            )

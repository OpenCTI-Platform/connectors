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
        self.create_tasks = []
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
                default="P1D"
            )
            self.nti_base_url = get_config_variable(
                "NTI_BASE_URL", ["nti", "base_url"], self.load, default="https://nti.nsfocusglobal.com/api/v2/"
            )
            self.package_type = get_config_variable(
                "NTI_PACKAGE_TYPE", ["nti", "package_type"], self.load, default="updated"
            )
            if self.package_type == 'updated':
                match_filename = '-updated'
            else:
                match_filename = ''
            if get_config_variable("NTI_CREATE_IOC", ["nti", "create_ioc"], self.load):
                self.create_tasks.append(f"data.NTI.API.V2.0.ioc{match_filename}")
            if get_config_variable("NTI_CREATE_IP", ["nti", "create_ip"], self.load):
                self.create_tasks.append(f"data.NTI.API.V2.0.ip-basic{match_filename}")
            if get_config_variable(
                "NTI_CREATE_DOMAIN", ["nti", "create_domain"], self.load
            ):
                self.create_tasks.append(f"data.NTI.API.V2.0.domain-basic{match_filename}")
            if get_config_variable("NTI_CREATE_URL", ["nti", "create_url"], self.load):
                self.create_tasks.append(f"data.NTI.API.V2.0.url-basic{match_filename}")
            if get_config_variable(
                "NTI_CREATE_FILE", ["nti", "create_file"], self.load
            ):
                self.create_tasks.append(f"data.NTI.API.V2.0.sample{match_filename}")

            self.ns_nti_key = get_config_variable(
                "NTI_API_KEY", ["nti", "api_key"], self.load, default='', required=True
            )
            self.tlp_level = get_config_variable(
                "NTI_TLP", ["nti", "tlp"], self.load, default="white"
            ).lower()
        except:
            helper.connector_logger.error(
                f"[init config] init config error: {traceback.format_exc()}"
            )
            raise

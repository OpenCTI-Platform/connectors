import os
from pathlib import Path

import yaml
from pycti import get_config_variable


class ConfigConnector:
    def __init__(self):
        """
        Initialize the connector with necessary configurations
        """
        # Load configuration file
        self.load = self._load_config()
        self._initialize_configurations()

        # Ensure connector type is in the load dictionary
        if "connector" not in self.load:
            self.load["connector"] = {}
        self.load["connector"]["type"] = "STREAM"

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

    def _initialize_configurations(self) -> None:
        """
        Connector configuration variables
        :return: None
        """
        # Set default connector type
        self.connector_type = get_config_variable(
            "CONNECTOR_TYPE",
            ["connector", "type"],
            self.load,
            default="STREAM",
        )

        # Elastic Security configurations
        self.elastic_url = get_config_variable(
            "ELASTIC_SECURITY_URL",
            ["elastic_security", "url"],
            self.load,
        )
        self.elastic_api_key = get_config_variable(
            "ELASTIC_SECURITY_API_KEY",
            ["elastic_security", "api_key"],
            self.load,
        )
        self.elastic_client_cert = get_config_variable(
            "ELASTIC_SECURITY_CLIENT_CERT",
            ["elastic_security", "client_cert"],
            self.load,
            default=None,
        )
        self.elastic_client_key = get_config_variable(
            "ELASTIC_SECURITY_CLIENT_KEY",
            ["elastic_security", "client_key"],
            self.load,
            default=None,
        )
        self.elastic_ca_cert = get_config_variable(
            "ELASTIC_SECURITY_CA_CERT",
            ["elastic_security", "ca_cert"],
            self.load,
            default=None,
        )
        self.elastic_verify_ssl = get_config_variable(
            "ELASTIC_SECURITY_VERIFY_SSL",
            ["elastic_security", "verify_ssl"],
            self.load,
            default=True,
        )
        self.elastic_index_name = get_config_variable(
            "ELASTIC_SECURITY_INDEX_NAME",
            ["elastic_security", "index_name"],
            self.load,
            default="logs-ti_custom_opencti.indicator",  # Custom index with proper mappings
        )
        # Optional: Separate Kibana URL for SIEM rules (defaults to auto-convert from ES URL)
        self.elastic_kibana_url = get_config_variable(
            "ELASTIC_SECURITY_KIBANA_URL",
            ["elastic_security", "kibana_url"],
            self.load,
            default=None,  # Auto-detect from elastic_url if not specified
        )
        # Optional: External OpenCTI URL for reference links (defaults to opencti:url)
        self.elastic_opencti_external_url = get_config_variable(
            "ELASTIC_SECURITY_OPENCTI_EXTERNAL_URL",
            ["elastic_security", "opencti_external_url"],
            self.load,
            default=None,  # Use opencti:url if not specified
        )
        self.indicator_expire_time = get_config_variable(
            "ELASTIC_SECURITY_INDICATOR_EXPIRE_TIME",
            ["elastic_security", "indicator_expire_time"],
            self.load,
            isNumber=True,
            default=90,  # Days
        )
        self.batch_size = get_config_variable(
            "ELASTIC_SECURITY_BATCH_SIZE",
            ["elastic_security", "batch_size"],
            self.load,
            isNumber=True,
            default=100,
        )

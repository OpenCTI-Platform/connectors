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
        self.load["connector"]["type"] = "EXTERNAL_IMPORT"

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
            default="EXTERNAL_IMPORT",
        )

        # Elastic Security configurations
        self.elastic_url = get_config_variable(
            "ELASTIC_SECURITY_URL",
            ["elastic_security", "url"],
            self.load,
        )
        self.elastic_kibana_url = get_config_variable(
            "ELASTIC_SECURITY_KIBANA_URL",
            ["elastic_security", "kibana_url"],
            self.load,
            default=None,  # Optional - will use elastic_url conversion if not provided
        )
        self.elastic_api_key = get_config_variable(
            "ELASTIC_SECURITY_API_KEY",
            ["elastic_security", "api_key"],
            self.load,
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

        # Import settings
        self.import_start_date = get_config_variable(
            "ELASTIC_SECURITY_IMPORT_START_DATE",
            ["elastic_security", "import_start_date"],
            self.load,
            default=None,
        )
        self.import_alerts = get_config_variable(
            "ELASTIC_SECURITY_IMPORT_ALERTS",
            ["elastic_security", "import_alerts"],
            self.load,
            default=True,
        )
        self.import_cases = get_config_variable(
            "ELASTIC_SECURITY_IMPORT_CASES",
            ["elastic_security", "import_cases"],
            self.load,
            default=True,
        )
        self.alert_statuses = get_config_variable(
            "ELASTIC_SECURITY_ALERT_STATUSES",
            ["elastic_security", "alert_statuses"],
            self.load,
            default=["open", "acknowledged", "closed"],
        )
        self.case_statuses = get_config_variable(
            "ELASTIC_SECURITY_CASE_STATUSES",
            ["elastic_security", "case_statuses"],
            self.load,
            default=["open", "in-progress", "closed"],
        )

        # Connector run settings
        self.duration_period = get_config_variable(
            "CONNECTOR_DURATION_PERIOD",
            ["connector", "duration_period"],
            self.load,
            default="PT30M",  # 30 minutes
        )

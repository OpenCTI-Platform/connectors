import os
from pathlib import Path

import yaml
from pycti import get_config_variable
from vclib.models.data_source import DataSource


class ConfigConnector:
    def __init__(self):
        """
        Initialize the connector with necessary configurations
        """

        # Load configuration file
        self.load_yml = self._load_config()
        self._initialize_configurations()
        self.load = self.to_dict()

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
        # OpenCTI configurations
        # Required
        self.opencti_url = get_config_variable(
            "OPENCTI_URL",
            ["opencti", "url"],
            self.load_yml,
            required=True,
        )

        self.opencti_token = get_config_variable(
            "OPENCTI_TOKEN",
            ["opencti", "token"],
            self.load_yml,
            required=True,
        )

        self.api_key = get_config_variable(
            "CONNECTOR_VULNCHECK_API_KEY",
            ["connector_vulncheck", "api_key"],
            self.load_yml,
            required=True,
        )

        self.id = get_config_variable(
            "CONNECTOR_ID",
            ["connector", "id"],
            self.load_yml,
            required=True,
        )

        # Defaulted or Optional
        self.type = get_config_variable(
            "CONNECTOR_TYPE",
            ["connector", "type"],
            self.load_yml,
            required=False,
            default="EXTERNAL_IMPORT",
        )

        self.name = get_config_variable(
            "CONNECTOR_NAME",
            ["connector", "name"],
            self.load_yml,
            required=False,
            default="VulnCheck Connector",
        )

        self.scope = get_config_variable(
            "CONNECTOR_SCOPE",
            ["connector", "scope"],
            self.load_yml,
            required=False,
            # Includes ``report`` so the STIX Reports produced for
            # advisory sources (threat actors, ransomware, botnets)
            # are generated out of the box on a fresh deployment
            # with no ``CONNECTOR_SCOPE`` override. Operators who
            # set ``CONNECTOR_SCOPE`` explicitly are unaffected
            # because env-var precedence applies in
            # ``get_config_variable``. Matches the documented
            # default in the connector README.
            default="vulnerability,malware,threat-actor,infrastructure,location,ip-addr,indicator,external-reference,software,report",
        )

        self.log_level = get_config_variable(
            "CONNECTOR_LOG_LEVEL",
            ["connector", "log_level"],
            self.load_yml,
            required=False,
            default="info",
        )

        self.duration_period = get_config_variable(
            "CONNECTOR_DURATION_PERIOD",
            ["connector", "duration_period"],
            self.load_yml,
            required=False,
            default="PT1H",
        )

        # Connector extra parameters
        self.api_base_url = get_config_variable(
            "CONNECTOR_VULNCHECK_API_BASE_URL",
            ["connector_vulncheck", "api_base_url"],
            self.load_yml,
            required=False,
            default="https://api.vulncheck.com/v3",
        )

        self.data_sources = get_config_variable(
            "CONNECTOR_VULNCHECK_DATA_SOURCES",
            ["connector_vulncheck", "data_sources"],
            self.load_yml,
            required=False,
            default=f"{DataSource.VulnCheckKEV},{DataSource.NistNVD2}",
        )

        # NVD2 incremental-ingestion controls (nist-nvd2 / vulncheck-nvd2).
        # Normal runs are incremental via connector state; these only shape
        # the first run and allow manual backfills. See build_nvd2_query_params.
        self.nvd2_pull_history = get_config_variable(
            "CONNECTOR_VULNCHECK_NVD2_PULL_HISTORY",
            ["connector_vulncheck", "nvd2_pull_history"],
            self.load_yml,
            required=False,
            default=False,
        )

        self.nvd2_max_date_range = get_config_variable(
            "CONNECTOR_VULNCHECK_NVD2_MAX_DATE_RANGE",
            ["connector_vulncheck", "nvd2_max_date_range"],
            self.load_yml,
            required=False,
            default=120,
        )

        self.nvd2_last_mod_start_date = get_config_variable(
            "CONNECTOR_VULNCHECK_NVD2_LAST_MOD_START_DATE",
            ["connector_vulncheck", "nvd2_last_mod_start_date"],
            self.load_yml,
            required=False,
            default=None,
        )

        self.nvd2_last_mod_end_date = get_config_variable(
            "CONNECTOR_VULNCHECK_NVD2_LAST_MOD_END_DATE",
            ["connector_vulncheck", "nvd2_last_mod_end_date"],
            self.load_yml,
            required=False,
            default=None,
        )

    def to_dict(self) -> dict:
        """Gather configuration settings and return them as a dictionary."""
        if (
            self.opencti_url is None
            or self.opencti_token is None
            or self.api_key is None
            or self.id is None
        ):
            raise ValueError(
                f"Missing required configuration variables: {'OPENCTI_URL' if self.opencti_url is None else ''} {'OPENCTI_TOKEN' if self.opencti_token is None else ''} {'CONNECTOR_VULNCHECK_API_KEY' if self.api_key is None else ''} {'CONNECTOR_ID' if self.id is None else ''}"
            )
        dct = {
            "opencti": {
                "url": self.opencti_url,
                "token": self.opencti_token,
            },
            "connector": {
                "id": self.id,
                "type": self.type,
                "name": self.name,
                "scope": self.scope,
                "log_level": self.log_level,
                "duration": self.duration_period,
            },
            "connector_vulncheck": {
                "api_key": self.api_key,
                "api_base_url": self.api_base_url,
                "data_sources": self.data_sources,
                "nvd2_pull_history": self.nvd2_pull_history,
                "nvd2_max_date_range": self.nvd2_max_date_range,
                "nvd2_last_mod_start_date": self.nvd2_last_mod_start_date,
                "nvd2_last_mod_end_date": self.nvd2_last_mod_end_date,
            },
        }
        return dct

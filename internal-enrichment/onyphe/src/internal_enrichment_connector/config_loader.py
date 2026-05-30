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

        self.auto = get_config_variable(
            "CONNECTOR_AUTO",
            ["connector", "auto"],
            self.load,
            default=False,
        )

        # Connector extra parameters
        self.base_url = get_config_variable(
            "ONYPHE_BASE_URL",
            ["onyphe", "base_url"],
            self.load,
            default="https://www.onyphe.io/api/v2/",
        )

        self.api_key = get_config_variable(
            "ONYPHE_API_KEY",
            ["onyphe", "api_key"],
            self.load,
        )

        self.max_tlp = get_config_variable(
            "ONYPHE_MAX_TLP",
            ["onyphe", "max_tlp"],
            self.load,
            default="TLP:AMBER",
        )

        self.time_since = get_config_variable(
            "ONYPHE_TIME_SINCE",
            ["onyphe", "time_since"],
            self.load,
            default="1w",
        )

        self.default_score = get_config_variable(
            "ONYPHE_DEFAULT_SCORE",
            ["onyphe", "default_score"],
            self.load,
            default=50,
            isNumber=True,
        )

        self.import_search_results = get_config_variable(
            "ONYPHE_IMPORT_SEARCH_RESULTS",
            ["onyphe", "import_search_results"],
            self.load,
            default=True,
        )

        self.create_note = get_config_variable(
            "ONYPHE_CREATE_NOTE",
            ["onyphe", "create_note"],
            self.load,
            default=False,
        )

        self.pattern_type = get_config_variable(
            "ONYPHE_PATTERN_TYPE",
            ["onyphe", "pattern_type"],
            self.load,
            default="onyphe",
        )

        self.import_full_data = get_config_variable(
            "ONYPHE_IMPORT_FULL_DATA",
            ["onyphe", "import_full_data"],
            self.load,
            default=False,
        )

        self.pivot_threshold = get_config_variable(
            "ONYPHE_PIVOT_THRESHOLD",
            ["onyphe", "pivot_threshold"],
            self.load,
            default=10,
            isNumber=True,
        )

        self.category = get_config_variable(
            "ONYPHE_CATEGORY",
            ["onyphe", "category"],
            self.load,
            default="ctiscan",
        )

        self.indicator_max_results = get_config_variable(
            "ONYPHE_INDICATOR_MAX_RESULTS",
            ["onyphe", "indicator_max_results"],
            self.load,
            default=1000,
            isNumber=True,
        )

        # CSV list of analytical pivot labels controlling which ONYPHE fingerprint
        # fields are turned into Text observables during enrichment.
        # An empty value means "use the default set" (sha256-preferred per family
        # — see DEFAULT_PIVOT_LABELS in onyphe_references.py).
        # Valid labels are the short names in ANALYTICAL_PIVOTS, e.g.:
        #   hhhash-sha256, favicon-sha256, ssh-fingerprint-sha256, app-data-sha256 …
        text_fingerprints_raw = get_config_variable(
            "ONYPHE_TEXT_FINGERPRINTS",
            ["onyphe", "text_fingerprints"],
            self.load,
            default="",
        )
        if text_fingerprints_raw:
            self.text_fingerprints = [
                t.strip() for t in text_fingerprints_raw.split(",") if t.strip()
            ]
        else:
            self.text_fingerprints = []

        # CSV list of OpenCTI observable types (and "Vulnerability") to create
        # during enrichment.  An empty value means "all types" (default behaviour).
        # Valid values: Domain-Name, Hostname, IPv4-Address, IPv6-Address,
        #               Autonomous-System, X509-Certificate, Text, Vulnerability
        enrichment_types_raw = get_config_variable(
            "ONYPHE_ENRICHMENT_TYPES",
            ["onyphe", "enrichment_types"],
            self.load,
            default="",
        )
        if enrichment_types_raw:
            self.enrichment_types = [
                t.strip() for t in enrichment_types_raw.split(",") if t.strip()
            ]
        else:
            self.enrichment_types = []

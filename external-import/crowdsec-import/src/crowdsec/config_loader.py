import os
from pathlib import Path

import yaml
from pycti import get_config_variable

from .utils import (
    clean_config,
)


class CrowdSecConfig:
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
        self.duration_period = get_config_variable(
            "CONNECTOR_DURATION_PERIOD",
            ["connector", "duration_period"],
            self.load,
            default="PT24H",
        )

        # Connector extra parameters
        self.crowdsec_key = clean_config(
            get_config_variable("CROWDSEC_KEY", ["crowdsec", "key"], self.load)
        )
        self.enrichment_threshold_per_import = get_config_variable(
            "CROWDSEC_ENRICHMENT_THRESHOLD_PER_IMPORT",
            ["crowdsec", "enrichment_threshold_per_import"],
            self.load,
            default=2000,
            isNumber=True,
        )
        self.max_tlp = clean_config(
            get_config_variable(
                "CROWDSEC_MAX_TLP",
                ["crowdsec", "max_tlp"],
                self.load,
                default="TLP:AMBER",
            )
        )
        self.create_note = get_config_variable(
            "CROWDSEC_CREATE_NOTE",
            ["crowdsec", "create_note"],
            self.load,
            default=True,
        )
        self.create_sighting = get_config_variable(
            "CROWDSEC_CREATE_SIGHTING",
            ["crowdsec", "create_sighting"],
            self.load,
            default=True,
        )
        self.vulnerability_create_from_cve = get_config_variable(
            "CROWDSEC_VULNERABILITY_CREATE_FROM_CVE",
            ["crowdsec", "vulnerability_create_from_cve"],
            self.load,
            default=True,
        )
        self.tlp_level = clean_config(
            get_config_variable(
                "CROWDSEC_TLP_LEVEL",
                ["crowdsec", "tlp_level"],
                self.load,
                default="amber",
            )
        )
        self.min_delay_between_enrichments = get_config_variable(
            "CROWDSEC_MIN_DELAY_BETWEEN_ENRICHMENTS",
            ["crowdsec", "min_delay_between_enrichments"],
            self.load,
            default=86400,
            isNumber=True,
        )
        self.last_enrichment_date_in_description = get_config_variable(
            "CROWDSEC_LAST_ENRICHMENT_DATE_IN_DESCRIPTION",
            ["crowdsec", "last_enrichment_date_in_description"],
            self.load,
            default=True,
        )
        self.create_targeted_countries_sightings = get_config_variable(
            "CROWDSEC_CREATE_TARGETED_COUNTRIES_SIGHTINGS",
            ["crowdsec", "create_targeted_countries_sightings"],
            self.load,
            default=False,
        )
        raw_indicator_create_from = clean_config(
            get_config_variable(
                "CROWDSEC_INDICATOR_CREATE_FROM",
                ["crowdsec", "indicator_create_from"],
                self.load,
                default="malicious,suspicious,known",
            )
        )
        self.indicator_create_from = raw_indicator_create_from.split(",")

        self.attack_pattern_create_from_mitre = get_config_variable(
            "CROWDSEC_ATTACK_PATTERN_CREATE_FROM_MITRE",
            ["crowdsec", "attack_pattern_create_from_mitre"],
            self.load,
            default=True,
        )
        self.query_since = get_config_variable(
            "CROWDSEC_IMPORT_QUERY_SINCE",
            ["crowdsec", "import_query_since"],
            self.load,
            True,
            24,
        )
        self.query = get_config_variable(
            "CROWDSEC_IMPORT_QUERY",
            ["crowdsec", "import_query"],
            self.load,
            False,
            'behaviors.label:"SSH Bruteforce"',
        )

        self.update_existing_data = get_config_variable(
            "CONNECTOR_UPDATE_EXISTING_DATA",
            ["connector", "update_existing_data"],
            self.load,
            False,
        )

        self.labels_scenario_name = get_config_variable(
            "CROWDSEC_LABELS_SCENARIO_NAME",
            ["crowdsec", "labels_scenario_name"],
            self.load,
            default=True,
        )
        self.labels_scenario_label = get_config_variable(
            "CROWDSEC_LABELS_SCENARIO_LABEL",
            ["crowdsec", "labels_scenario_label"],
            self.load,
            default=False,
        )
        self.labels_scenario_color = clean_config(
            get_config_variable(
                "CROWDSEC_LABELS_SCENARIO_COLOR",
                ["crowdsec", "labels_scenario_color"],
                self.load,
                default="#2E2A14",
            )
        )
        self.labels_cve = get_config_variable(
            "CROWDSEC_LABELS_CVE",
            ["crowdsec", "labels_cve"],
            self.load,
            default=True,
        )
        self.labels_cve_color = clean_config(
            get_config_variable(
                "CROWDSEC_LABELS_CVE_COLOR",
                ["crowdsec", "labels_cve_color"],
                self.load,
                default="#800080",
            )
        )
        self.labels_behavior = get_config_variable(
            "CROWDSEC_LABELS_BEHAVIOR",
            ["crowdsec", "labels_behavior"],
            self.load,
            default=False,
        )
        self.labels_behavior_color = clean_config(
            get_config_variable(
                "CROWDSEC_LABELS_BEHAVIOR_COLOR",
                ["crowdsec", "labels_behavior_color"],
                self.load,
                default="#808000",
            )
        )
        self.labels_mitre = get_config_variable(
            "CROWDSEC_LABELS_MITRE",
            ["crowdsec", "labels_mitre"],
            self.load,
            default=True,
        )
        self.labels_mitre_color = clean_config(
            get_config_variable(
                "CROWDSEC_LABELS_MITRE_COLOR",
                ["crowdsec", "labels_mitre_color"],
                self.load,
                default="#000080",
            )
        )
        self.labels_reputation = get_config_variable(
            "CROWDSEC_LABELS_REPUTATION",
            ["crowdsec", "labels_reputation"],
            self.load,
            default=True,
        )
        self.labels_reputation_malicious_color = clean_config(
            get_config_variable(
                "CROWDSEC_LABELS_REPUTATION_MALICIOUS_COLOR",
                ["crowdsec", "labels_reputation_malicious_color"],
                self.load,
                default="#FF0000",
            )
        )
        self.labels_reputation_suspicious_color = clean_config(
            get_config_variable(
                "CROWDSEC_LABELS_REPUTATION_SUSPICIOUS_COLOR",
                ["crowdsec", "labels_reputation_suspicious_color"],
                self.load,
                default="#FFA500",
            )
        )
        self.labels_reputation_safe_color = clean_config(
            get_config_variable(
                "CROWDSEC_LABELS_REPUTATION_SAFE_COLOR",
                ["crowdsec", "labels_reputation_safe_color"],
                self.load,
                default="#00BFFF",
            )
        )
        self.labels_reputation_known_color = clean_config(
            get_config_variable(
                "CROWDSEC_LABELS_REPUTATION_KNOWN_COLOR",
                ["crowdsec", "labels_reputation_known_color"],
                self.load,
                default="#808080",
            )
        )

import os
from pathlib import Path

import yaml
import json
import ast
from pycti import get_config_variable


def normalize_list_param(param):
    if not param:
        return []

    if isinstance(param, str):
        # Check for JSON
        try:
            loaded = json.loads(param)
            if isinstance(loaded, list):
                return [str(s).lower() for s in loaded]
        except json.JSONDecodeError:
            pass

        # Fallback
        try:
            loaded = ast.literal_eval(param)
            if isinstance(loaded, list):
                return [str(s).lower() for s in loaded]
        except Exception:
            pass

    elif isinstance(param, list):
        return [str(s).lower() for s in param]

    return [param]


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
        self.opencti_url = get_config_variable(
            "OPENCTI_URL",
            ["opencti", "url"],
            self.load,
        )

        self.opencti_token = get_config_variable(
            "OPENCTI_TOKEN",
            ["opencti", "token"],
            self.load,
        )

        # Connector extra parameters
        self.high_priority_labels = get_config_variable(
            "CONNECTOR_SCORING_HIGH_PRIORITY_LABELS",
            ["connector_scoring", "high_priority_labels"],
            self.load,
            default=[],
        )
        self.high_priority_labels = normalize_list_param(self.high_priority_labels)

        self.medium_priority_labels = get_config_variable(
            "CONNECTOR_SCORING_MEDIUM_PRIORITY_LABELS",
            ["connector_scoring", "medium_priority_labels"],
            self.load,
            default=[],
        )
        self.medium_priority_labels = normalize_list_param(self.medium_priority_labels)

        self.low_priority_labels = get_config_variable(
            "CONNECTOR_SCORING_LOW_PRIORITY_LABELS",
            ["connector_scoring", "low_priority_labels"],
            self.load,
            default=[],
        )
        self.low_priority_labels = normalize_list_param(self.low_priority_labels)

        self.indicator_type_enrichable = get_config_variable(
            "CONNECTOR_SCORING_INDICATOR_TYPE_ENRICHABLE",
            ["connector_scoring", "indicator_type_enrichable"],
            self.load,
            default="IPv4-Addr,IPv6-Addr,Domain-Name,StixFile",
        )
        self.indicator_type_enrichable = self.indicator_type_enrichable.split(",")

        self.browse_report = get_config_variable(
            "CONNECTOR_SCORING_BROWSE_REPORT",
            ["connector_scoring", "browse_report"],
            self.load,
            default=False,
        )

        # Threat impact config
        self.threat_impact_score = get_config_variable(
            "CONNECTOR_SCORING_THREAT_IMPACT_SCORE",
            ["connector_scoring", "threat_impact_score"],
            self.load,
            default=False,
        )

        self.threat_high_priority = get_config_variable(
            "CONNECTOR_SCORING_THREAT_HIGH_PRIORITY",
            ["connector_scoring", "threat_high_priority"],
            self.load,
            default=0,
            isNumber=True,
        )

        self.threat_medium_priority = get_config_variable(
            "CONNECTOR_SCORING_THREAT_MEDIUM_PRIORITY",
            ["connector_scoring", "threat_medium_priority"],
            self.load,
            default=0,
            isNumber=True,
        )

        self.threat_low_priority = get_config_variable(
            "CONNECTOR_SCORING_THREAT_LOW_PRIORITY",
            ["connector_scoring", "threat_low_priority"],
            self.load,
            default=0,
            isNumber=True,
        )

        # Toolbox impact config
        self.toolbox_impact_score = get_config_variable(
            "CONNECTOR_SCORING_TOOLBOX_IMPACT_SCORE",
            ["connector_scoring", "toolbox_impact_score"],
            self.load,
            default=False,
        )

        self.toolbox_high_priority = get_config_variable(
            "CONNECTOR_SCORING_TOOLBOX_HIGH_PRIORITY",
            ["connector_scoring", "toolbox_high_priority"],
            self.load,
            default=0,
            isNumber=True,
        )

        self.toolbox_medium_priority = get_config_variable(
            "CONNECTOR_SCORING_TOOLBOX_MEDIUM_PRIORITY",
            ["connector_scoring", "toolbox_medium_priority"],
            self.load,
            default=0,
            isNumber=True,
        )

        self.toolbox_low_priority = get_config_variable(
            "CONNECTOR_SCORING_TOOLBOX_LOW_PRIORITY",
            ["connector_scoring", "toolbox_low_priority"],
            self.load,
            default=0,
            isNumber=True,
        )

        # Location impact config
        self.location_impact_score = get_config_variable(
            "CONNECTOR_SCORING_LOCATION_IMPACT_SCORE",
            ["connector_scoring", "location_impact_score"],
            self.load,
            default=False,
        )

        self.location_high_priority = get_config_variable(
            "CONNECTOR_SCORING_LOCATION_HIGH_PRIORITY",
            ["connector_scoring", "location_high_priority"],
            self.load,
            default=0,
            isNumber=True,
        )

        self.location_medium_priority = get_config_variable(
            "CONNECTOR_SCORING_LOCATION_MEDIUM_PRIORITY",
            ["connector_scoring", "location_medium_priority"],
            self.load,
            default=0,
            isNumber=True,
        )

        self.location_low_priority = get_config_variable(
            "CONNECTOR_SCORING_LOCATION_LOW_PRIORITY",
            ["connector_scoring", "location_low_priority"],
            self.load,
            default=0,
            isNumber=True,
        )

        # Sector impact config
        self.sector_impact_score = get_config_variable(
            "CONNECTOR_SCORING_SECTOR_IMPACT_SCORE",
            ["connector_scoring", "sector_impact_score"],
            self.load,
            default=False,
        )

        self.sector_high_priority = get_config_variable(
            "CONNECTOR_SCORING_SECTOR_HIGH_PRIORITY",
            ["connector_scoring", "sector_high_priority"],
            self.load,
            default=0,
            isNumber=True,
        )

        self.sector_medium_priority = get_config_variable(
            "CONNECTOR_SCORING_SECTOR_MEDIUM_PRIORITY",
            ["connector_scoring", "sector_medium_priority"],
            self.load,
            default=0,
            isNumber=True,
        )

        self.sector_low_priority = get_config_variable(
            "CONNECTOR_SCORING_SECTOR_LOW_PRIORITY",
            ["connector_scoring", "sector_low_priority"],
            self.load,
            default=0,
            isNumber=True,
        )

        # TTP impact config
        self.ttp_impact_score = get_config_variable(
            "CONNECTOR_SCORING_TTP_IMPACT_SCORE",
            ["connector_scoring", "ttp_impact_score"],
            self.load,
            default=False,
        )

        self.ttp_high_priority = get_config_variable(
            "CONNECTOR_SCORING_TTP_HIGH_PRIORITY",
            ["connector_scoring", "ttp_high_priority"],
            self.load,
            default=0,
            isNumber=True,
        )

        self.ttp_medium_priority = get_config_variable(
            "CONNECTOR_SCORING_TTP_MEDIUM_PRIORITY",
            ["connector_scoring", "ttp_medium_priority"],
            self.load,
            default=0,
            isNumber=True,
        )

        self.ttp_low_priority = get_config_variable(
            "CONNECTOR_SCORING_TTP_LOW_PRIORITY",
            ["connector_scoring", "ttp_low_priority"],
            self.load,
            default=0,
            isNumber=True,
        )

        # Creator impact config
        self.author_impact_score = get_config_variable(
            "CONNECTOR_SCORING_AUTHOR_IMPACT_SCORE",
            ["connector_scoring", "author_impact_score"],
            self.load,
            default=False,
        )

        self.author_high_priority = get_config_variable(
            "CONNECTOR_SCORING_AUTHOR_HIGH_PRIORITY",
            ["connector_scoring", "author_high_confidence"],
            self.load,
            default=0,
            isNumber=True,
        )

        self.author_medium_priority = get_config_variable(
            "CONNECTOR_SCORING_AUTHOR_MEDIUM_PRIORITY",
            ["connector_scoring", "author_medium_confidence"],
            self.load,
            default=0,
            isNumber=True,
        )

        self.author_low_priority = get_config_variable(
            "CONNECTOR_SCORING_AUTHOR_LOW_PRIORITY",
            ["connector_scoring", "author_low_confidence"],
            self.load,
            default=0,
            isNumber=True,
        )

        # Impact mapping
        self.impact_map = {
            "Threat": {
                "high": self.threat_high_priority,
                "medium": self.threat_medium_priority,
                "low": self.threat_low_priority,
            },
            "Toolbox": {
                "high": self.toolbox_high_priority,
                "medium": self.toolbox_medium_priority,
                "low": self.toolbox_low_priority,
            },
            "Location": {
                "high": self.location_high_priority,
                "medium": self.location_medium_priority,
                "low": self.location_low_priority,
            },
            "Sector": {
                "high": self.sector_high_priority,
                "medium": self.sector_medium_priority,
                "low": self.sector_low_priority,
            },
            "TTP": {
                "high": self.ttp_high_priority,
                "medium": self.ttp_medium_priority,
                "low": self.ttp_low_priority,
            },
            "Author": {
                "high": self.author_high_priority,
                "medium": self.author_medium_priority,
                "low": self.author_low_priority,
            },
        }

        # Enable flags
        self.impact_enabled = {
            "Threat": self.threat_impact_score,
            "Toolbox": self.toolbox_impact_score,
            "Location": self.location_impact_score,
            "Sector": self.sector_impact_score,
            "TTP": self.ttp_impact_score,
            "Author": self.author_impact_score,
        }

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
        config_file_path = Path(__file__).parents[2].joinpath("config.yml")
        config = {}
        if os.path.isfile(config_file_path):
            try:
                with open(config_file_path, "r", encoding="utf-8") as config_file:
                    config = yaml.safe_load(config_file) or {}
            except (yaml.YAMLError, IOError, OSError) as e:
                # Log warning but continue - env vars may provide config
                import sys

                print(f"Warning: Could not load config.yml: {e}", file=sys.stderr)
        return config

    def _initialize_configurations(self) -> None:
        """
        Connector configuration variables
        :return: None
        """
        # PolySwarm API Key (required)
        self.polyswarm_api_key = get_config_variable(
            "POLYSWARM_API_KEY",
            ["polyswarm", "api_key"],
            self.load,
        )

        # Validate API key is provided
        if not self.polyswarm_api_key:
            raise ValueError(
                "POLYSWARM_API_KEY is required. "
                "Please set the environment variable or add it to config.yml"
            )

        # PolySwarm Community
        self.polyswarm_community = get_config_variable(
            "POLYSWARM_COMMUNITY",
            ["polyswarm", "community"],
            self.load,
            default="default",
        )

        # PolyKG API URL for live malware family profiles and TTP data.
        # TODO: Flip default to production URL before GA release.
        self.polykg_api_url = get_config_variable(
            "POLYKG_API_URL",
            ["polykg", "api_url"],
            self.load,
            default="https://grti.stage-v3.polyswarm.network",
        )

        # Max TLP: refuse enrichment for observables above this level.
        # Valid values: TLP:WHITE, TLP:CLEAR, TLP:GREEN, TLP:AMBER,
        #               TLP:AMBER+STRICT, TLP:RED (or None to disable).
        self.max_tlp = get_config_variable(
            "POLYSWARM_MAX_TLP",
            ["polyswarm", "max_tlp"],
            self.load,
            default=None,
        )

        # replace_with_lower_score: when False, skip score update if existing
        # score is higher than the new PolySwarm score.
        rls_raw = get_config_variable(
            "POLYSWARM_REPLACE_WITH_LOWER_SCORE",
            ["polyswarm", "replace_with_lower_score"],
            self.load,
            default=True,
        )
        # get_config_variable may return a string from env vars
        if isinstance(rls_raw, str):
            self.replace_with_lower_score = rls_raw.lower() in ("true", "1", "yes")
        else:
            self.replace_with_lower_score = bool(rls_raw)

        # --- Network IOC extraction (#43) ---

        # Enable/disable network IOC extraction from PolySwarm IOC API
        ioc_enabled_raw = get_config_variable(
            "POLYSWARM_IOC_ENABLED",
            ["polyswarm", "ioc_enabled"],
            self.load,
            default=True,
        )
        if isinstance(ioc_enabled_raw, str):
            self.ioc_enabled = ioc_enabled_raw.lower() in ("true", "1", "yes")
        else:
            self.ioc_enabled = bool(ioc_enabled_raw)

        # Max network IOC observables per enrichment (global cap)
        ioc_max_raw = get_config_variable(
            "POLYSWARM_IOC_MAX_COUNT",
            ["polyswarm", "ioc_max_count"],
            self.load,
            default=20,
        )
        try:
            self.ioc_max_count = int(ioc_max_raw)
        except (ValueError, TypeError):
            self.ioc_max_count = 20

        # x_opencti_score for network IOC observables (low = observed, not confirmed)
        ioc_score_raw = get_config_variable(
            "POLYSWARM_IOC_SCORE",
            ["polyswarm", "ioc_score"],
            self.load,
            default=20,
        )
        try:
            self.ioc_score = int(ioc_score_raw)
        except (ValueError, TypeError):
            self.ioc_score = 20

        # Which IOC types to create: ip, domain, url (comma-separated)
        ioc_types_raw = get_config_variable(
            "POLYSWARM_IOC_TYPES",
            ["polyswarm", "ioc_types"],
            self.load,
            default="ip,domain,url",
        )
        self.ioc_types = [
            t.strip().lower() for t in str(ioc_types_raw).split(",") if t.strip()
        ]

        # Max Polling Time (with safe conversion)
        max_polling_raw = get_config_variable(
            "POLYSWARM_MAX_POLLING_TIME",
            ["polyswarm", "max_polling_time"],
            self.load,
            default=120,
        )
        try:
            self.max_polling_time = int(max_polling_raw)
        except (ValueError, TypeError):
            self.max_polling_time = 120  # Default fallback

import os
from pathlib import Path

import yaml
from pycti import get_config_variable

from .mitre_resolver import ENTERPRISE_ATTACK_URL

TLP_MARKING_IDS = {
    "TLP:CLEAR": "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
    "TLP:WHITE": "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
    "TLP:GREEN": "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da",
    "TLP:AMBER": "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",
    "TLP:AMBER+STRICT": "marking-definition--826578e1-40a3-4b46-a8d8-b9931824d066",
    "TLP:RED": "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed",
}


class ConfigConnector:
    def __init__(self):
        self.load = self._load_config()
        self._initialize_configurations()
        self._validate_required()

    @staticmethod
    def _load_config() -> dict:
        config_file_path = Path(__file__).parents[1].joinpath("config.yml")
        if os.path.isfile(config_file_path):
            with open(config_file_path, encoding="utf-8") as config_file:
                return yaml.load(config_file, Loader=yaml.FullLoader) or {}
        return {}

    @staticmethod
    def _as_bool(value) -> bool:
        if isinstance(value, bool):
            return value
        return str(value).strip().lower() in {"true", "1", "yes", "y", "on"}

    @staticmethod
    def _resolve_tlp(value: str) -> str:
        tlp_label = (value or "TLP:AMBER").strip().upper()
        if tlp_label not in TLP_MARKING_IDS:
            raise ValueError(f"Unsupported TLP value: {value}")
        return TLP_MARKING_IDS[tlp_label]

    def _initialize_configurations(self) -> None:
        self.splunk_host = get_config_variable(
            "SPLUNK_HOST", ["splunk-search", "host"], self.load
        )
        self.splunk_port = int(
            get_config_variable(
                "SPLUNK_PORT", ["splunk-search", "port"], self.load, default="8089"
            )
        )
        self.splunk_token = get_config_variable(
            "SPLUNK_TOKEN", ["splunk-search", "token"], self.load
        )
        self.splunk_app = get_config_variable(
            "SPLUNK_APP", ["splunk-search", "app"], self.load, default="search"
        )
        self.splunk_scheme = get_config_variable(
            "SPLUNK_SCHEME", ["splunk-search", "scheme"], self.load, default="https"
        )
        self.splunk_verify_ssl = self._as_bool(
            get_config_variable(
                "SPLUNK_VERIFY_SSL",
                ["splunk-search", "verify_ssl"],
                self.load,
                default="true",
            )
        )
        self.splunk_search_earliest = get_config_variable(
            "SPLUNK_SEARCH_EARLIEST",
            ["splunk-search", "earliest_time"],
            self.load,
            default="-30d@d",
        )
        self.splunk_search_latest = get_config_variable(
            "SPLUNK_SEARCH_LATEST",
            ["splunk-search", "latest_time"],
            self.load,
            default="now",
        )
        self.splunk_timeout = int(
            get_config_variable(
                "SPLUNK_SEARCH_TIMEOUT",
                ["splunk-search", "timeout"],
                self.load,
                default="60",
            )
        )
        self.splunk_wait_seconds = int(
            get_config_variable(
                "SPLUNK_WAIT_SECONDS",
                ["splunk-search", "wait_seconds"],
                self.load,
                default="2",
            )
        )
        self.splunk_max_results = int(
            get_config_variable(
                "SPLUNK_MAX_RESULTS",
                ["splunk-search", "max_results"],
                self.load,
                default="1000",
            )
        )
        self.sighting_tlp_label = get_config_variable(
            "SPLUNK_SIGHTING_TLP",
            ["splunk-search", "sighting_tlp"],
            self.load,
            default="TLP:AMBER",
        )
        self.observable_tlp_label = get_config_variable(
            "SPLUNK_OBSERVABLE_TLP",
            ["splunk-search", "observable_tlp"],
            self.load,
            default="TLP:AMBER",
        )
        self.sighting_tlp = self._resolve_tlp(self.sighting_tlp_label)
        self.observable_tlp = self._resolve_tlp(self.observable_tlp_label)
        self.mitre_data_sources_enabled = self._as_bool(
            get_config_variable(
                "MITRE_DATA_SOURCES_ENABLED",
                ["splunk-search", "mitre_data_sources_enabled"],
                self.load,
                default="true",
            )
        )
        self.mitre_attack_bundle_url = get_config_variable(
            "MITRE_ATTACK_BUNDLE_URL",
            ["splunk-search", "mitre_attack_bundle_url"],
            self.load,
            default=ENTERPRISE_ATTACK_URL,
        )

    def _validate_required(self) -> None:
        missing = []
        if not self.splunk_host:
            missing.append("SPLUNK_HOST")
        if not self.splunk_token:
            missing.append("SPLUNK_TOKEN")
        if missing:
            raise ValueError(
                f"Missing required configuration variables: {', '.join(missing)}"
            )

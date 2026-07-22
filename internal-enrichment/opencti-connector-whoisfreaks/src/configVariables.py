import sys
from pathlib import Path
import yaml
from pycti import get_config_variable


class ConfigVariables:
    """
    Configuration loader for WhoisFreaks OpenCTI Connector.
    Reads settings from config.yml or environment variables.
    """

    def __init__(self):

        config_file_path = Path(__file__).parents[1] / "config.yml"
        config = {}

        if config_file_path.is_file():
            with open(config_file_path, "r", encoding="utf-8") as file:
                config = yaml.safe_load(file) or {}

        self.opencti_url = get_config_variable(
            "OPENCTI_URL", ["opencti", "url"], config
        )

        self.opencti_token = get_config_variable(
            "OPENCTI_TOKEN", ["opencti", "token"], config
        )

        self.connector_id = get_config_variable(
            "CONNECTOR_ID", ["connector", "id"], config
        )
        self.connector_type = get_config_variable(
            "CONNECTOR_TYPE", ["connector", "type"], config
        )
        self.connector_name = get_config_variable(
            "CONNECTOR_NAME", ["connector", "name"], config
        )
        self.connector_scope = get_config_variable(
            "CONNECTOR_SCOPE", ["connector", "scope"], config
        )
        self.connector_confidence_level = get_config_variable(
            "CONNECTOR_CONFIDENCE", ["connector", "confidence_level"], config
        )
        self.connector_auto = get_config_variable(
            "CONNECTOR_AUTO", ["connector", "auto"], config
        )
        # Force log level to uppercase string (e.g. 'INFO')
        raw_log_level = get_config_variable(
            "CONNECTOR_LOG_LEVEL", ["connector", "log_level"], config, default="INFO"
        )
        self.connector_log_level = (
            str(raw_log_level).upper() if raw_log_level else "INFO"
        )
        self.whoisfreaks_api_key = get_config_variable(
            "WHOISFREAKS_API_KEY", ["whoisfreaks", "api_key"], config
        )

        self._validate()

    def _validate(self) -> None:
        """Validates that all required configuration values are present."""
        missing = []
        if not self.opencti_url or self.opencti_url == "ChangeMe":
            missing.append("OPENCTI_URL / opencti.url")
        if not self.opencti_token or self.opencti_token == "ChangeMe":
            missing.append("OPENCTI_TOKEN / opencti.token")
        if not self.connector_id or self.connector_id == "ChangeMe":
            missing.append("CONNECTOR_ID / connector.id")
        if not self.whoisfreaks_api_key or self.whoisfreaks_api_key == "ChangeMe":
            missing.append("WHOISFREAKS_API_KEY / whoisfreaks.api_key")

        if missing:
            print(
                f"[ERROR] Missing or default configuration values for: {', '.join(missing)}"
            )
            print("[ERROR] Please update config.yml or pass environment variables.")
            sys.exit(1)

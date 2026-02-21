import os

import yaml
from pycti import get_config_variable


class ConfigLoader:
    def __init__(self):
        config_path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "..", "config.yml"
        )
        config = (
            yaml.load(open(config_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_path)
            else {}
        )
        self._config = config

        # OpenCTI
        self.opencti_url = get_config_variable(
            "OPENCTI_URL", ["opencti", "url"], config
        )
        self.opencti_token = get_config_variable(
            "OPENCTI_TOKEN", ["opencti", "token"], config
        )

        # Connector
        self.connector_id = get_config_variable(
            "CONNECTOR_ID", ["connector", "id"], config
        )
        self.connector_name = get_config_variable(
            "CONNECTOR_NAME", ["connector", "name"], config, default="SikkerAPI"
        )
        self.connector_scope = get_config_variable(
            "CONNECTOR_SCOPE", ["connector", "scope"], config, default="sikkerapi"
        )
        self.connector_log_level = get_config_variable(
            "CONNECTOR_LOG_LEVEL",
            ["connector", "log_level"],
            config,
            default="info",
        )
        self.connector_duration_period = get_config_variable(
            "CONNECTOR_DURATION_PERIOD",
            ["connector", "duration_period"],
            config,
            default="PT6H",
        )

        # SikkerAPI
        self.api_key = get_config_variable(
            "SIKKERAPI_API_KEY", ["sikkerapi", "api_key"], config
        )
        self.base_url = get_config_variable(
            "SIKKERAPI_BASE_URL",
            ["sikkerapi", "base_url"],
            config,
            default="https://api.sikkerapi.com",
        )
        self.collection_id = get_config_variable(
            "SIKKERAPI_COLLECTION_ID",
            ["sikkerapi", "collection_id"],
            config,
            default="sikker-threat-intel",
        )
        self.page_size = get_config_variable(
            "SIKKERAPI_PAGE_SIZE",
            ["sikkerapi", "page_size"],
            config,
            isNumber=True,
            default=500,
        )
        self.confidence_min = get_config_variable(
            "SIKKERAPI_CONFIDENCE_MIN",
            ["sikkerapi", "confidence_min"],
            config,
            isNumber=True,
            default=0,
        )
        self.import_start_date = get_config_variable(
            "SIKKERAPI_IMPORT_START_DATE",
            ["sikkerapi", "import_start_date"],
            config,
        )

    def to_pycti_config(self) -> dict:
        return {
            "opencti": {
                "url": self.opencti_url,
                "token": self.opencti_token,
            },
            "connector": {
                "type": "EXTERNAL_IMPORT",
                "id": self.connector_id,
                "name": self.connector_name,
                "scope": self.connector_scope,
                "log_level": self.connector_log_level,
                "duration_period": self.connector_duration_period,
            },
        }

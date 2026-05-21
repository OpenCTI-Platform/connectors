import os

import yaml
from pycti import get_config_variable


class ConnectorSettings:  # pylint: disable=too-few-public-methods
    def __init__(self, config_file_path: str = "config.yml") -> None:
        config_file_path = config_file_path.replace("\\", "/")
        if os.path.isfile(config_file_path):
            with open(config_file_path, encoding="utf-8") as f:
                config = yaml.load(f, Loader=yaml.FullLoader)
        else:
            config = {}

        self.opencti_url: str = get_config_variable(
            "OPENCTI_URL",
            ["opencti", "url"],
            config,
            default="http://opencti:8080",
        )
        opencti_token = get_config_variable(
            "OPENCTI_TOKEN",
            ["opencti", "token"],
            config,
        )
        if opencti_token is None:
            raise ValueError("Missing OpenCTI Token")
        self.opencti_token: str = opencti_token

        connector_id = get_config_variable(
            "CONNECTOR_ID",
            ["connector", "id"],
            config,
        )
        if connector_id is None:
            raise ValueError("Missing Connector ID")
        self.connector_id: str = connector_id

        self.connector_name: str = get_config_variable(
            "CONNECTOR_NAME",
            ["connector", "name"],
            config,
            default="Flare",
        )
        self.connector_scope: str = get_config_variable(
            "CONNECTOR_SCOPE",
            ["connector", "scope"],
            config,
            default="Incident,Observable,Indicator",
        )
        self.connector_log_level: str = get_config_variable(
            "CONNECTOR_LOG_LEVEL",
            ["connector", "log_level"],
            config,
            default="info",
        )
        self.connector_duration_period: str = get_config_variable(
            "CONNECTOR_DURATION_PERIOD",
            ["connector", "duration_period"],
            config,
            default="PT1H",
        )

        flare_api_key = get_config_variable(
            "FLARE_API_KEY",
            ["flare", "api_key"],
            config,
        )
        if flare_api_key is None:
            raise ValueError("Missing Flare API Key")
        self.flare_api_key: str = flare_api_key

        self.flare_api_domain: str = get_config_variable(
            "FLARE_API_DOMAIN",
            ["flare", "api_domain"],
            config,
            default="api.flare.io",
        )
        self.flare_tenant_id: int | None = get_config_variable(
            "FLARE_TENANT_ID",
            ["flare", "tenant_id"],
            config,
            isNumber=True,
        )

        flare_event_types = get_config_variable(
            "FLARE_EVENT_TYPES",
            ["flare", "event_types"],
            config,
        )
        self.flare_event_types: list[str] = (
            str(flare_event_types).split(",")
            if flare_event_types
            else ["stealer_log", "domain", "ransomleak", "leak"]
        )

        flare_event_actions = get_config_variable(
            "FLARE_EVENT_ACTIONS",
            ["flare", "event_actions"],
            config,
        )
        self.flare_event_actions: list[str] | None = (
            str(flare_event_actions).split(",") if flare_event_actions else None
        )

        self.flare_lookback_days: int = get_config_variable(
            "FLARE_LOOKBACK_DAYS",
            ["flare", "lookback_days"],
            config,
            isNumber=True,
            default=30,
        )
        self.flare_tlp_level: str = get_config_variable(
            "FLARE_TLP_LEVEL",
            ["flare", "tlp_level"],
            config,
            default="white",
        )

    def to_helper_config(self) -> dict[str, object]:
        return {
            "opencti": {
                "url": self.opencti_url,
                "token": self.opencti_token,
            },
            "connector": {
                "id": self.connector_id,
                "type": "EXTERNAL_IMPORT",
                "name": self.connector_name,
                "scope": self.connector_scope,
                "log_level": self.connector_log_level,
                "duration_period": self.connector_duration_period,
            },
        }

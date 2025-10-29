import warnings

from connectors_sdk import BaseConnectorSettings, BaseExternalImportConnectorConfig
from external_import_connector.constants import ConfigKeys
from pycti import get_config_variable
from pydantic import Field, model_validator
from pydantic_settings import BaseSettings


class APIConfig(BaseSettings):
    api_base_url: str = Field(description="API base URL", default_factory=str)
    api_key: str = Field(description="API key", default_factory=str)

    @model_validator(mode="before")
    @classmethod
    def migrate_deprecated_configs(cls, data: dict) -> dict:
        deprecated_configs = [
            {
                "key": ConfigKeys.API_BASE_URL,
                "yaml_path": ["connector_hunt_io", "api_base_url"],
                "field_name": "api_base_url",
                "old_name": ConfigKeys.API_BASE_URL,
                "new_name": "CONNECTOR_HUNT_IO_API_BASE_URL",
            },
            {
                "key": ConfigKeys.API_KEY,
                "yaml_path": ["connector_hunt_io", "api_key"],
                "field_name": "api_key",
                "old_name": ConfigKeys.API_BASE_URL,
                "new_name": "CONNECTOR_HUNT_IO_API_KEY",
            },
        ]

        for config in deprecated_configs:
            value = get_config_variable(config["key"], config["yaml_path"])
            if value:
                warnings.warn(
                    message=f"Env var '{config['old_name']}' is deprecated. "
                    f"Use '{config['new_name']}' instead.",
                    category=DeprecationWarning,
                )
                data[config["field_name"]] = (
                    data.get(config["field_name"], None) or value
                )

        return data


class ConfigConnector(BaseConnectorSettings):
    """Handles connector configuration loading and validation."""

    connector: BaseExternalImportConnectorConfig = Field(
        default_factory=BaseExternalImportConnectorConfig
    )
    connector_hunt_io: APIConfig = Field(default_factory=APIConfig)

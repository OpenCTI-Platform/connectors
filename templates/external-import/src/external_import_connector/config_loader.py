from datetime import timedelta
from typing import Literal

from connectors_sdk.models.base import BaseConnectorSettings
from connectors_sdk.models.base.connector_config import ExternalImportConnectorConfig
from pydantic import BaseModel, Field
from pydantic_settings import SettingsConfigDict


class _ConnectorConfig(ExternalImportConnectorConfig):
    id: str = Field(
        default="template-12345678-1234-1234-12ab-12ab1234abcd",
        description="A UUID v4 to identify the connector in OpenCTI.",
    )
    name: str = Field(
        default="Connector Template",
        description="The name of the connector.",
    )
    scope: list[str] = Field(
        default=["template"],
        description="The scope of the connector",
    )
    duration_period: timedelta = Field(
        default=timedelta(days=1),
        description="The period of time to await between two runs of the connector.",
    )
    log_level: Literal["debug", "info", "warn", "warning", "error"] = Field(
        default="error",
        description="The minimum level of logs to display.",
    )


class _ConnectorTemplateConfig(BaseModel):
    api_base_url: str = Field(
        default="https://api.example.com/v1/",
        description="API base URL",
    )
    api_key: str = Field(
        description="API key for authentication",
    )
    tlp_level: Literal["clear", "white", "green", "amber", "amber+strict", "red"] = (
        Field(
            default="clear",
            description="TLP level for imported data",
        )
    )


class ConfigConnector(BaseConnectorSettings):
    model_config = SettingsConfigDict(yaml_file="config.yml")

    connector: _ConnectorConfig = Field(default_factory=_ConnectorConfig)
    connector_template: _ConnectorTemplateConfig = Field(
        default_factory=_ConnectorTemplateConfig
    )

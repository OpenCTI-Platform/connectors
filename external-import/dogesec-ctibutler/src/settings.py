"""OpenCTI CTI Butler connector settings module."""

from datetime import timedelta

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
    DeprecatedField,
    ListFromString,
)
from pydantic import Field, HttpUrl, SecretStr


class CTIButlerConnectorConfig(BaseExternalImportConnectorConfig):
    """Defaults of the `connector` section for the CTI Butler connector."""

    id: str = Field(
        description="A UUID v4 to identify the connector in OpenCTI.",
        default="15bf64d8-ff5f-4a6c-95cb-19edfefea75c",
    )
    name: str = Field(
        description="The name of the connector.",
        default="CTIButler",
    )
    scope: ListFromString = Field(
        description="The scope of the connector.",
        default=["ctibutler"],
    )
    duration_period: timedelta = Field(
        description="The period of time to await between two runs of the connector.",
        default=timedelta(days=7),
    )


class CTIButlerConfig(BaseConfigModel):
    """Settings specific to the CTI Butler connector."""

    base_url: HttpUrl = Field(
        description="The URL of the CTI Butler API.",
        default=HttpUrl("https://api.ctibutler.com/"),
    )
    api_key: SecretStr = Field(
        description="The API key used to authenticate against the CTI Butler API.",
    )
    knowledgebases: str = Field(
        description=(
            "Comma-separated list of the knowledge bases to import, without spaces "
            "(e.g. 'attack-enterprise,capec'). Supported values: 'cwe', 'capec', "
            "'location', 'attack-mobile', 'attack-ics', 'attack-enterprise', "
            "'disarm', 'atlas'."
        ),
    )
    interval_days: int | None = DeprecatedField(
        description="Polling interval in days.",
        default=None,
        deprecated="Use 'CONNECTOR_DURATION_PERIOD' in the 'connector' section instead.",
        new_namespace="connector",
        new_namespaced_var="duration_period",
        new_value_factory=lambda days: timedelta(days=int(days)),
    )


class ConnectorSettings(BaseConnectorSettings):
    """Settings of the CTI Butler connector."""

    connector: CTIButlerConnectorConfig = Field(
        default_factory=CTIButlerConnectorConfig
    )
    ctibutler: CTIButlerConfig = Field(default_factory=CTIButlerConfig)

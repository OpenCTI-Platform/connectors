from datetime import timedelta

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
    ListFromString,
)
from pydantic import Field, HttpUrl, SecretStr


class ExternalImportConnectorConfig(BaseExternalImportConnectorConfig):
    """
    Override the `BaseExternalImportConnectorConfig` to add parameters and/or defaults
    to the configuration for connectors of type `EXTERNAL_IMPORT`.
    """

    id: str = Field(
        description="A UUID v4 to identify the connector in OpenCTI.",
        default="770a8220-4e7c-46d1-bb5e-bbce47480912",
    )
    name: str = Field(
        description="The name of the connector.",
        default="Phishunt",
    )
    scope: ListFromString = Field(
        description="The scope of the connector.",
        default=[],
    )
    duration_period: timedelta = Field(
        description="The period of time to await between two runs of the connector.",
        default=timedelta(hours=1),
    )


class PhishuntConfig(BaseConfigModel):
    """
    Define parameters and/or defaults for the configuration specific to the `PhishuntConnector`.
    """

    api_key: SecretStr | None = Field(
        description="The API key for Phishunt.",
        default=None,
    )
    create_indicators: bool = Field(
        description="If true then indicators will be created from Pulse indicators and added to the report.",
        default=True,
    )
    default_x_opencti_score: int = Field(
        description="The default x_opencti_score to use for indicators. If a per indicator type score is not set, this is used.",
        default=40,
    )
    x_opencti_score_domain: int = Field(
        description="The x_opencti_score to use for Domain indicators. If not set, the default value is default_x_opencti_score.",
        default=40,
    )
    x_opencti_score_ip: int = Field(
        description="The x_opencti_score to use for IP indicators. If not set, the default value is default_x_opencti_score.",
        default=40,
    )
    x_opencti_score_url: int = Field(
        description="The x_opencti_score to use for URL indicators. If not set, the default value is default_x_opencti_score.",
        default=40,
    )


class ConnectorSettings(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include `ExternalImportConnectorConfig` and `PhishuntConfig`.
    """

    connector: ExternalImportConnectorConfig = Field(
        default_factory=ExternalImportConnectorConfig
    )
    phishunt: PhishuntConfig = Field(default_factory=PhishuntConfig)

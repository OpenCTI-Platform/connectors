import warnings
from datetime import timedelta

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
    ListFromString,
)
from pydantic import Field, SecretStr, model_validator


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
        default=["phishunt"],
    )
    duration_period: timedelta = Field(
        description="The period of time to await between two runs of the connector.",
        default=timedelta(days=3),
    )


class PhishuntConfig(BaseConfigModel):
    """
    Define parameters and/or defaults for the configuration specific to the `PhishuntConnector`.
    """

    api_key: SecretStr | None = Field(
        description="The API key for Phishunt. If not set, the connector will use the public feed.",
        default=None,
    )
    create_indicators: bool = Field(
        description="If true then indicators will be created from Pulse indicators and added to the report.",
        default=True,
    )
    default_x_opencti_score: int = Field(
        description="The default `x_opencti_score` to use for indicators. "
        "If no per indicator type score is set, this is the fallback default score.",
        default=40,
    )
    x_opencti_score_domain: int | None = Field(
        description="The `x_opencti_score` to use for Domain indicators. "
        "If not set, the default value is `default_x_opencti_score`.",
        default=None,
    )
    x_opencti_score_ip: int | None = Field(
        description="The `x_opencti_score` to use for IP indicators. "
        "If not set, the default value is `default_x_opencti_score`.",
        default=None,
    )
    x_opencti_score_url: int | None = Field(
        description="The `x_opencti_score` to use for URL indicators. "
        "If not set, the default value is `default_x_opencti_score`.",
        default=None,
    )


class ConnectorSettings(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include `ExternalImportConnectorConfig` and `PhishuntConfig`.
    """

    connector: ExternalImportConnectorConfig = Field(
        default_factory=ExternalImportConnectorConfig
    )
    phishunt: PhishuntConfig = Field(default_factory=PhishuntConfig)

    @model_validator(mode="before")
    @classmethod
    def migrate_deprecated_interval(cls, data: dict) -> dict:
        """
        Env var `PHISHUNT_INTERVAL` is deprecated.
        This is a workaround to keep the old config working while we migrate to `CONNECTOR_DURATION_PERIOD`.
        """
        connector_data: dict = data.get("connector", {})
        phishunt_data: dict = data.get("phishunt", {})
        if interval := phishunt_data.pop("interval", None):
            if connector_data.get("duration_period") is not None:
                warnings.warn(
                    "Both 'PHISHUNT_INTERVAL' and 'CONNECTOR_DURATION_PERIOD' are set. "
                    "'CONNECTOR_DURATION_PERIOD' will take precedence."
                )
            else:
                warnings.warn(
                    "Env var 'PHISHUNT_INTERVAL' is deprecated. Use 'CONNECTOR_DURATION_PERIOD' instead."
                )
                connector_data["duration_period"] = timedelta(days=int(interval))

        return data

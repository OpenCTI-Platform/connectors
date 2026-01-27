from datetime import timedelta

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
    ListFromString,
)
from pydantic import Field, SecretStr


class ExternalImportConnectorConfig(BaseExternalImportConnectorConfig):
    """
    Override the `BaseExternalImportConnectorConfig` to add parameters and/or defaults
    to the configuration for connectors of type `EXTERNAL_IMPORT`.
    """

    id: str = Field(
        description="A UUID v4 to identify the connector in OpenCTI.",
        default="6528cf33-6059-4927-bc08-db52f4cfbb5a",
    )
    name: str = Field(
        description="The name of the connector.",
        default="Valhalla",
    )
    scope: ListFromString = Field(
        description="The scope of the connector.",
        default=[],
    )
    duration_period: timedelta = Field(
        description="The period of time to await between two runs of the connector.",
        default=timedelta(hours=1),
    )


class ValhallaConfig(BaseConfigModel):
    """
    Define parameters and/or defaults for the configuration specific to the `ValhallaConnector`.
    """

    api_key: SecretStr | None = Field(
        description="Valhalla API key. Empty key fetches only public/demo rules.",
        default=None,
    )
    interval_sec: int = Field(
        description="Interval in seconds between runs (default: 86400 = 1 day).",
        default=86400,
    )


class ConnectorSettings(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include `ExternalImportConnectorConfig` and `ValhallaConfig`.
    """

    connector: ExternalImportConnectorConfig = Field(
        default_factory=ExternalImportConnectorConfig
    )
    valhalla: ValhallaConfig = Field(default_factory=ValhallaConfig)

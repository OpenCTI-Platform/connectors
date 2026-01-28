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
        default="6528cf33-6059-4927-bc08-db52f4cfbb5a",
    )
    name: str = Field(
        description="The name of the connector.",
        default="Valhalla",
    )
    scope: ListFromString = Field(
        description="The scope of the connector.",
        default=["valhalla"],
    )
    duration_period: timedelta = Field(
        description="The period of time to await between two runs of the connector.",
        default=timedelta(days=1),
    )


class ValhallaConfig(BaseConfigModel):
    """
    Define parameters and/or defaults for the configuration specific to the `ValhallaConnector`.
    """

    api_key: SecretStr | None = Field(
        description="Valhalla API key. Empty key fetches only public/demo rules.",
        default=None,
    )


class ConnectorSettings(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include `ExternalImportConnectorConfig` and `ValhallaConfig`.
    """

    connector: ExternalImportConnectorConfig = Field(
        default_factory=ExternalImportConnectorConfig
    )
    valhalla: ValhallaConfig = Field(default_factory=ValhallaConfig)

    @model_validator(mode="before")
    @classmethod
    def migrate_deprecated_interval(cls, data: dict) -> dict:
        """
        Env var `VALHALLA_INTERVAL_SEC` is deprecated.
        This is a workaround to keep the old config working while we migrate to `CONNECTOR_DURATION_PERIOD`.
        """
        connector_data: dict = data.get("connector", {})
        valhalla_data: dict = data.get("valhalla", {})
        if interval := valhalla_data.pop("interval_sec", None):
            if connector_data.get("duration_period") is not None:
                warnings.warn(
                    "Both 'VALHALLA_INTERVAL_SEC' and 'CONNECTOR_DURATION_PERIOD' are set. "
                    "'CONNECTOR_DURATION_PERIOD' will take precedence."
                )
            else:
                warnings.warn(
                    "Env var 'VALHALLA_INTERVAL_SEC' is deprecated. Use 'CONNECTOR_DURATION_PERIOD' instead."
                )
                connector_data["duration_period"] = timedelta(seconds=int(interval))

        return data

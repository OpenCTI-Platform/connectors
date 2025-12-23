import warnings
from datetime import datetime, timedelta, timezone

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
    DatetimeFromIsoString,
    ListFromString,
)
from pydantic import Field, HttpUrl, SecretStr, model_validator


class ExternalImportConnectorConfig(BaseExternalImportConnectorConfig):
    """
    Override the `BaseExternalImportConnectorConfig` to add parameters and/or defaults
    to the configuration for connectors of type `EXTERNAL_IMPORT`.
    """

    id: str = Field(
        description="The ID of the connector.",
        default="e84df642-f33b-4c73-877f-dd4b0093fd09",
    )
    name: str = Field(
        description="The name of the connector.",
        default="Silobreaker",
    )
    scope: ListFromString = Field(
        description="The scope of the connector.",
        default=["silobreaker"],
    )
    duration_period: timedelta = Field(
        description="The period of time to await between two runs of the connector.",
        default=timedelta(hours=1),
    )


class SilobreakerConfig(BaseConfigModel):
    """
    Define parameters and/or defaults for the configuration specific to the `SilobreakerConnector`.
    """

    api_url: HttpUrl = Field(
        description="The URL of the Silobreaker API.",
        default=HttpUrl("https://api.silobreaker.com"),
    )
    api_key: SecretStr = Field(
        description="The API key for the Silobreaker API.",
    )
    api_shared: SecretStr = Field(
        description="The shared secret for the Silobreaker API.",
    )
    lists: ListFromString = Field(
        description="The lists of Silobreaker to import.",
        default=["138809", "96910", "36592", "55112", "50774"],
    )
    import_start_date: DatetimeFromIsoString = Field(
        description="The start date for importing Silobreaker data.",
        default=datetime(2024, 9, 1, tzinfo=timezone.utc),
    )


class ConnectorSettings(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include `ExternalImportConnectorConfig` and `SilobreakerConfig`.
    """

    connector: ExternalImportConnectorConfig = Field(
        default_factory=ExternalImportConnectorConfig
    )
    silobreaker: SilobreakerConfig = Field(default_factory=SilobreakerConfig)

    @model_validator(mode="before")
    @classmethod
    def migrate_deprecated_interval(cls, data: dict) -> dict:
        """
        Env var `SILOBREAKER_INTERVAL` is deprecated.
        This is a workaround to keep the old config working while we migrate to `CONNECTOR_DURATION_PERIOD`.
        """
        connector_data: dict = data.get("connector", {})
        silobreaker_data: dict = data.get("silobreaker", {})

        if interval := silobreaker_data.pop("interval", None):
            warnings.warn(
                "Env var 'SILOBREAKER_INTERVAL' is deprecated. Use 'CONNECTOR_DURATION_PERIOD' instead."
            )

            connector_data["duration_period"] = timedelta(minutes=int(interval))

        return data

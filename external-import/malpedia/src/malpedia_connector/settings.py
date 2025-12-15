import warnings
from datetime import timedelta
from typing import Any, Literal

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
    ListFromString,
)
from pydantic import Field, SecretStr, field_validator, model_validator


class ExternalImportConnectorConfig(BaseExternalImportConnectorConfig):
    """
    Override the `BaseExternalImportConnectorConfig` to add parameters and/or defaults
    to the configuration for connectors of type `EXTERNAL_IMPORT`.
    """

    id: str = Field(
        description="The ID of the connector.",
        default="8a277536-ca52-4d87-9f8e-4f77e3e6512c",
    )
    name: str = Field(
        description="The name of the connector.",
        default="Malpedia",
    )
    scope: ListFromString = Field(
        description="The scope of the connector.",
        default="malpedia",
    )
    duration_period: timedelta = Field(
        description="The period of time to await between two runs of the connector.",
        default=timedelta(hours=24),
    )


class MalpediaConfig(BaseConfigModel):
    """
    Define parameters and/or defaults for the configuration specific to the `MalpediaConnector`.
    """

    auth_key: SecretStr | None = Field(
        description="API authentication key",
        default=None,
    )
    import_intrusion_sets: bool = Field(
        description="Choose if you want to import Intrusion-Sets from Malpedia",
        default=True,
    )
    import_yara: bool = Field(
        description="Choose if you want to import Yara rules from Malpedia",
        default=True,
    )
    create_indicators: bool = Field(
        description="Choose if you want to create Indicators Sample (File) from Malpedia",
        default=True,
    )
    create_observables: bool = Field(
        description="Choose if you want to create Observables Sample (File) from Malpedia",
        default=True,
    )
    default_marking: (
        Literal["TLP:CLEAR", "TLP:WHITE", "TLP:GREEN", "TLP:AMBER", "TLP:RED"] | None
    ) = Field(
        description="The default TLP marking to apply to entities created by the connector. "
        "If not defined, the default when an API key is provided is `TLP:AMBER`, otherwise `TLP:WHITE`.",
        default=None,
    )

    @field_validator("default_marking", mode="before")
    @classmethod
    def validate_default_marking(cls, value: Any) -> Any:
        """Normalize TLP Marking case before validation."""
        if isinstance(value, str):
            return value.strip().upper()
        return value


class ConnectorSettings(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include `ExternalImportConnectorConfig` and `MalpediaConfig`.
    """

    connector: ExternalImportConnectorConfig = Field(
        default_factory=ExternalImportConnectorConfig
    )
    malpedia: MalpediaConfig = Field(default_factory=MalpediaConfig)

    @model_validator(mode="before")
    @classmethod
    def migrate_deprecated_interval(cls, data: dict) -> dict:
        """
        Env var `MALPEDIA_INTERVAL_SEC` is deprecated.
        This is a workaround to keep the old config working while we migrate to `CONNECTOR_DURATION_PERIOD`.
        """
        connector_data: dict = data.get("connector", {})
        malpedia_data: dict = data.get("malpedia", {})

        if interval := malpedia_data.pop("interval_sec", None):
            warnings.warn(
                "Env var 'MALPEDIA_INTERVAL_SEC' is deprecated. Use 'CONNECTOR_DURATION_PERIOD' instead."
            )

            connector_data["duration_period"] = timedelta(seconds=int(interval))

        return data

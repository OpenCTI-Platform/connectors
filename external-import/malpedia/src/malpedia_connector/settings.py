from datetime import timedelta

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
)
from pydantic import Field, SecretStr


class ExternalImportConnectorConfig(BaseExternalImportConnectorConfig):
    """
    Override the `BaseExternalImportConnectorConfig` to add parameters and/or defaults
    to the configuration for connectors of type `EXTERNAL_IMPORT`.
    """

    name: str = Field(
        description="The name of the connector.",
        default="Malpedia",
    )
    duration_period: timedelta = Field(
        description="The period of time to await between two runs of the connector.",
        default=timedelta(hours=1),
    )


class MalpediaConfig(BaseConfigModel):
    """
    Define parameters and/or defaults for the configuration specific to the `MalpediaConnector`.
    """

    auth_key: SecretStr = Field(
        description="API authentication key",
        default=SecretStr(""),
    )
    interval_sec: int = Field(
        description="Interval in seconds before a new import is considered",
        default=86400,
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
    default_marking: str = Field(
        description="If not defined in config, an authenticated user will have TLP:AMBER, otherwise TLP:CLEAR",
        default="TLP:CLEAR",
    )


class ConnectorSettings(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include `ExternalImportConnectorConfig` and `MalpediaConfig`.
    """

    connector: ExternalImportConnectorConfig = Field(
        default_factory=ExternalImportConnectorConfig
    )
    malpedia: MalpediaConfig = Field(default_factory=MalpediaConfig)

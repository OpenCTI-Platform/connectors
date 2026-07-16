from datetime import timedelta

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
    ListFromString,
)
from pydantic import Field, SecretStr


class ZeroFoxConnectorConfig(BaseExternalImportConnectorConfig):
    """Connector section configuration.

    Mirrors the existing ``CONNECTOR_*`` variables consumed by the ZeroFox connector.
    """

    name: str = Field(
        description="The name of the connector.",
        default="ZeroFox",
    )
    scope: ListFromString = Field(
        description="The scope of the connector.",
        default=["zerofox"],
    )
    duration_period: timedelta = Field(
        description="The period of time to await between two runs of the connector.",
        default=timedelta(days=1),
    )
    run_every: str = Field(
        description=(
            "Interval between two runs of the connector, e.g. '7d', '12h', '10m', "
            "'30s' where the final letter is one of 'd', 'h', 'm', 's'."
        ),
        default="1d",
    )
    first_run: str = Field(
        description=(
            "Interval to look back on the connector's very first run, e.g. '7d', "
            "'12h', '10m', '30s'."
        ),
        default="1d",
    )
    update_existing_data: bool = Field(
        description="Whether to update data already ingested into the platform.",
        default=False,
    )


class ZeroFoxConfig(BaseConfigModel):
    """Configuration specific to the ZeroFox connector.

    Mirrors the existing ``ZEROFOX_*`` variables.
    """

    username: str = Field(
        description="The username used to authenticate against the ZeroFox API.",
    )
    password: SecretStr = Field(
        description="The password used to authenticate against the ZeroFox API.",
    )
    collectors: str | None = Field(
        description=(
            "Comma-separated list of ZeroFox CTI feeds to collect. "
            "When unset, all available feeds are collected."
        ),
        default=None,
    )


class ConnectorSettings(BaseConnectorSettings):
    """Global settings for the ZeroFox connector."""

    connector: ZeroFoxConnectorConfig = Field(
        default_factory=ZeroFoxConnectorConfig,
    )
    zerofox: ZeroFoxConfig = Field(default_factory=ZeroFoxConfig)

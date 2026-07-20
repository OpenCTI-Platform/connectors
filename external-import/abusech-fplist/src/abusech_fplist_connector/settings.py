from datetime import timedelta

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
    ListFromString,
)
from pydantic import Field, SecretStr


class ExternalImportConnectorConfig(BaseExternalImportConnectorConfig):
    name: str = Field(
        description="The name of the connector.",
        default="AbusechFplist",
    )
    scope: ListFromString = Field(
        description="The scope of the connector.",
        default=["indicator"],
    )
    duration_period: timedelta = Field(
        description="How often to run (ISO-8601 duration).",
        default=timedelta(days=1),
    )


class AbusechFplistConfig(BaseConfigModel):
    api_base_url: str = Field(
        description="Hunting API endpoint.",
        default="https://hunting-api.abuse.ch/api/v1/",
    )
    api_key: SecretStr = Field(
        description="Your abuse.ch Auth-Key from the Authentication Portal.",
    )
    dry_run: bool = Field(
        description="If true, log which Indicators would be deleted without actually deleting them.",
        default=False,
    )


class ConnectorSettings(BaseConnectorSettings):
    connector: ExternalImportConnectorConfig = Field(
        default_factory=ExternalImportConnectorConfig
    )
    abusech_fplist: AbusechFplistConfig = Field(default_factory=AbusechFplistConfig)

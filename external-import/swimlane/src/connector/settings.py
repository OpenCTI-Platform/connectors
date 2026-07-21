from datetime import timedelta
from typing import Literal

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
    ListFromString,
)
from pydantic import AliasChoices, Field, HttpUrl, SecretStr


class ExternalImportConnectorConfig(BaseExternalImportConnectorConfig):
    """
    Override the `BaseExternalImportConnectorConfig` to add parameters and/or defaults
    to the configuration for connectors of type `EXTERNAL_IMPORT`.
    """

    name: str = Field(
        description="The name of the connector.",
        default="Swimlane",
    )
    duration_period: timedelta = Field(
        description="The period of time to await between two runs of the connector.",
        default=timedelta(minutes=15),
    )
    scope: ListFromString = Field(
        description="The scope of the connector",
        default=[],
    )


class SwimlaneConfig(BaseConfigModel):
    """
    Define parameters and/or defaults for the configuration specific to the Swimlane connector.
    """

    api_base_url: HttpUrl = Field(
        description="Base URL of the Swimlane instance (e.g. https://swimlane.example.com).",
        validation_alias=AliasChoices("api_base_url", "url"),
        serialization_alias="api_base_url",
    )
    api_token: SecretStr = Field(
        description="Swimlane API token (Personal Access Token) used for authentication.",
        validation_alias=AliasChoices("api_token", "token"),
        serialization_alias="api_token",
    )
    application_id: str = Field(
        description="ID of the Swimlane application whose records are imported.",
    )
    max_records: int = Field(
        description="Maximum number of records to fetch per run.",
        default=100,
        ge=1,
    )
    tlp_level: Literal["clear", "white", "green", "amber", "amber+strict", "red"] = (
        Field(
            description="TLP marking applied to the imported case-incidents.",
            default="amber",
        )
    )
    ssl_verify: bool = Field(
        description="Whether to verify the SSL certificate of the Swimlane instance.",
        default=True,
    )


class ConnectorSettings(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include `ExternalImportConnectorConfig` and `SwimlaneConfig`.
    """

    connector: ExternalImportConnectorConfig = Field(
        default_factory=ExternalImportConnectorConfig
    )
    swimlane: SwimlaneConfig = Field(default_factory=SwimlaneConfig)

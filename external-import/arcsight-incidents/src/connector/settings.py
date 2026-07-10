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
        default="ArcSight Incidents",
    )
    duration_period: timedelta = Field(
        description="The period of time to await between two runs of the connector.",
        default=timedelta(minutes=15),
    )
    scope: ListFromString = Field(
        description="The scope of the connector",
        default=[],
    )


class ArcSightIncidentsConfig(BaseConfigModel):
    """
    Define parameters and/or defaults for the configuration specific to the ArcSight Incidents connector.
    """

    api_base_url: HttpUrl = Field(
        description="Base URL of the ArcSight ESM Manager (e.g. https://arcsight.example.com:8443).",
        validation_alias=AliasChoices("api_base_url", "url"),
        serialization_alias="api_base_url",
    )
    username: str = Field(
        description="ArcSight ESM user name.",
    )
    password: SecretStr = Field(
        description="ArcSight ESM user password.",
    )
    max_cases: int = Field(
        description="Maximum number of ESM cases to fetch per run.",
        default=200,
        ge=1,
    )
    tlp_level: Literal["clear", "white", "green", "amber", "amber+strict", "red"] = (
        Field(
            description="TLP marking applied to the imported incidents.",
            default="amber",
        )
    )
    ssl_verify: bool = Field(
        description="Whether to verify the SSL certificate of the ArcSight ESM Manager.",
        default=True,
    )


class ConnectorSettings(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include `ExternalImportConnectorConfig` and `ArcSightIncidentsConfig`.
    """

    connector: ExternalImportConnectorConfig = Field(
        default_factory=ExternalImportConnectorConfig
    )
    arcsight_incidents: ArcSightIncidentsConfig = Field(
        default_factory=ArcSightIncidentsConfig
    )

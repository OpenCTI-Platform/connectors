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
        default="LogRhythm Incidents",
    )
    scope: ListFromString = Field(
        description="The scope of the connector.",
        default=["logrhythm"],
    )
    duration_period: timedelta = Field(
        description="The period of time to await between two runs of the connector.",
        default=timedelta(minutes=15),
    )


class LogRhythmIncidentsConfig(BaseConfigModel):
    """
    Define parameters and/or defaults for the configuration specific to the LogRhythm Incidents connector.
    """

    api_base_url: HttpUrl = Field(
        description="Base URL of the LogRhythm API gateway (e.g. https://logrhythm.example.com:8501).",
        validation_alias=AliasChoices("api_base_url", "url"),
        serialization_alias="api_base_url",
    )
    api_token: SecretStr = Field(
        description="LogRhythm API token (Bearer) used for authentication.",
        validation_alias=AliasChoices("api_token", "token"),
        serialization_alias="api_token",
    )
    max_cases: int = Field(
        description="Maximum number of LogRhythm cases to fetch per run.",
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
        description="Whether to verify the SSL certificate of the LogRhythm API gateway.",
        default=True,
    )


class ConnectorSettings(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include `ExternalImportConnectorConfig` and `LogRhythmIncidentsConfig`.
    """

    connector: ExternalImportConnectorConfig = Field(
        default_factory=ExternalImportConnectorConfig
    )
    logrhythm_incidents: LogRhythmIncidentsConfig = Field(
        default_factory=LogRhythmIncidentsConfig
    )

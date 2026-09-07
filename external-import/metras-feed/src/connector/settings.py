"""Pydantic settings for the Metras Feed connector (EXTERNAL_IMPORT)."""

from datetime import timedelta

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
    ListFromString,
)
from connectors_sdk.models.enums import TLPLevel
from pydantic import Field, HttpUrl, SecretStr


class ExternalImportConnectorConfig(BaseExternalImportConnectorConfig):
    id: str = Field(
        default="df7d629d-20a6-4a94-aa2b-86c5baacdda6",
        description="The unique identifier of the connector.",
        examples=["df7d629d-20a6-4a94-aa2b-86c5baacdda6"],
    )
    name: str = Field(
        default="Metras-Feed",
        description="The name of the connector.",
        examples=["Metras-Feed"],
    )
    scope: ListFromString = Field(
        default=["Metras"],
        description="The scope of the connector.",
        examples=["Metras"],
    )
    duration_period: timedelta = Field(
        default=timedelta(hours=1),
        description="ISO-8601 duration (e.g. 'PT1H') representing the period between two runs.",
        examples=["PT1H"],
    )


class MetrasConfig(BaseConfigModel):
    api_base_url: HttpUrl = Field(
        default=HttpUrl("https://api.metras.sa/api"),
        description="Base URL of the Metras API.",
        examples=["https://api.metras.sa/api"],
    )
    api_key: SecretStr = Field(
        description="Metras API key (X-API-KEY header).",
        examples=["ChangeMe"],
    )
    verify_ssl: bool = Field(
        default=True, description="Verify TLS certificates.", examples=[True]
    )

    import_alerts: bool = Field(
        default=True, description="Import EDR alerts.", examples=[True]
    )
    import_binaries: bool = Field(
        default=True, description="Import binaries as StixFile.", examples=[True]
    )
    import_endpoints: bool = Field(
        default=True,
        description="Import endpoints as System identities.",
        examples=[True],
    )
    binary_malicious_only: bool = Field(
        default=True,
        description="Only import banned/unsigned binaries (reduces noise).",
        examples=[True],
    )
    page_size: int = Field(
        default=50, ge=1, le=500, description="Records per page.", examples=[50]
    )
    tlp_level: TLPLevel = Field(
        default=TLPLevel.AMBER,
        description="TLP marking applied to imported objects.",
        examples=[TLPLevel.AMBER],
    )


class ConnectorSettings(BaseConnectorSettings):
    connector: ExternalImportConnectorConfig = Field(
        default_factory=ExternalImportConnectorConfig
    )
    metras: MetrasConfig = Field(default_factory=MetrasConfig)

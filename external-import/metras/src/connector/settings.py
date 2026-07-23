"""Pydantic settings for the Metras Feed connector (EXTERNAL_IMPORT)."""

from datetime import timedelta
from typing import Literal

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
)
from pydantic import Field, HttpUrl, SecretStr


class ExternalImportConnectorConfig(BaseExternalImportConnectorConfig):
    name: str = Field(default="Metras-Feed", examples=["Metras-Feed"])
    # Poll cadence. ISO-8601 duration (e.g. PT1H). Mandatory for the SDK.
    duration_period: timedelta = Field(default=timedelta(hours=1), examples=["PT1H"])


class MetrasConfig(BaseConfigModel):
    api_base_url: HttpUrl = Field(
        default="https://api.metras.sa/api",
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
    tlp_level: Literal["clear", "white", "green", "amber", "red"] = Field(
        default="amber",
        description="TLP marking applied to imported objects.",
        examples=["amber"],
    )


class ConnectorSettings(BaseConnectorSettings):
    connector: ExternalImportConnectorConfig = Field(
        default_factory=ExternalImportConnectorConfig
    )
    metras: MetrasConfig = Field(default_factory=MetrasConfig)

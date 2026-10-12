"""Configuration of the Microsoft Defender XDR hunt connector."""

from typing import Literal

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseInternalHuntConnectorConfig,
    ListFromString,
)
from pydantic import Field, HttpUrl, SecretStr, field_validator


class MicrosoftDefenderHuntConnectorConfig(BaseInternalHuntConnectorConfig):
    """Connector-level configuration of the Microsoft Defender XDR hunt connector."""

    id: str = Field(
        description="A UUID v4 to identify the connector in OpenCTI.",
        default="ca088a24-7e69-4b55-b4e6-dd241f9a9fe4",
    )
    name: str = Field(
        description="The name of the connector.",
        default="Microsoft Defender Hunt",
    )
    scope: ListFromString = Field(
        description="The hunt platform the connector executes against.",
        default=["microsoft-defender"],
    )
    security_platform_name: str | None = Field(
        description="Name of the OpenCTI Security Platform the hunts are executed against.",
        default="Microsoft Defender XDR",
    )
    security_platform_type: Literal["SIEM", "EDR", "XDR", "SOAR", "NDR", "ISPM"] = (
        Field(
            description="Type of the OpenCTI Security Platform the hunts are executed against.",
            default="XDR",
        )
    )


class MicrosoftDefenderHuntConfig(BaseConfigModel):
    """Microsoft Entra ID and Microsoft Graph settings of the hunt connector."""

    tenant_id: str = Field(
        description="Microsoft Entra tenant ID of the app registration.",
    )
    client_id: str = Field(
        description="Client (application) ID of the app registration.",
    )
    client_secret: SecretStr = Field(
        description="Client secret of the app registration.",
    )
    login_url: HttpUrl = Field(
        description="Microsoft Entra ID login URL: 'https://login.microsoftonline.com' (global and US Government "
        "L4) or 'https://login.microsoftonline.us' (US Government L5, DoD).",
        default=HttpUrl("https://login.microsoftonline.com"),
    )
    graph_url: HttpUrl = Field(
        description="Microsoft Graph URL: 'https://graph.microsoft.com' (global), 'https://graph.microsoft.us' "
        "(US Government L4) or 'https://dod-graph.microsoft.us' (US Government L5, DoD).",
        default=HttpUrl("https://graph.microsoft.com"),
    )
    sigma_pipeline: str = Field(
        description="pySigma pipeline translating Sigma rules: 'microsoft_xdr' (Defender XDR advanced hunting "
        "tables) or 'none'.",
        default="microsoft_xdr",
    )

    @field_validator("tenant_id", "client_id")
    @classmethod
    def _not_blank(cls, value: str) -> str:
        """Reject a blank tenant or client ID."""
        if not value.strip():
            raise ValueError("must not be blank.")
        return value.strip()

    @field_validator("client_secret")
    @classmethod
    def _secret_not_blank(cls, value: SecretStr) -> SecretStr:
        """Reject a blank client secret."""
        if not value.get_secret_value().strip():
            raise ValueError("must not be blank.")
        return value


class ConnectorSettings(BaseConnectorSettings):
    """Settings of the Microsoft Defender XDR hunt connector."""

    connector: MicrosoftDefenderHuntConnectorConfig = Field(
        default_factory=MicrosoftDefenderHuntConnectorConfig
    )
    microsoft_defender_hunt: MicrosoftDefenderHuntConfig = Field(
        default_factory=MicrosoftDefenderHuntConfig
    )

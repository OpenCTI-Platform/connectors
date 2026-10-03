"""Configuration of the Microsoft Sentinel hunt connector."""

from typing import Literal, Self

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseInternalHuntConnectorConfig,
    ListFromString,
)
from pydantic import Field, HttpUrl, SecretStr, model_validator


class MicrosoftSentinelHuntConnectorConfig(BaseInternalHuntConnectorConfig):
    """Connector-level configuration of the Microsoft Sentinel hunt connector."""

    id: str = Field(
        description="A UUID v4 to identify the connector in OpenCTI.",
        default="1c9f4a3b-0c1e-4b7a-9e57-6a1d2f8b3c45",
    )
    name: str = Field(
        description="The name of the connector.",
        default="Microsoft Sentinel Hunt",
    )
    scope: ListFromString = Field(
        description="The hunt platform the connector executes against.",
        default=["microsoft-sentinel"],
    )
    security_platform_name: str | None = Field(
        description="Name of the OpenCTI Security Platform the hunts are executed against.",
        default="Microsoft Sentinel",
    )


class MicrosoftSentinelHuntConfig(BaseConfigModel):
    """Azure and Log Analytics settings of the hunt connector."""

    auth_type: Literal["app_registration", "azure_credential"] = Field(
        description="Authentication method: 'app_registration' (default) requires tenant_id, client_id and "
        "client_secret; 'azure_credential' uses DefaultAzureCredential (managed identity, workload identity, "
        "or a local `az login` session) and ignores them.",
        default="app_registration",
    )
    tenant_id: str | None = Field(
        description="Microsoft Entra tenant ID of the app registration.",
        default=None,
    )
    client_id: str | None = Field(
        description="Client (application) ID of the app registration.",
        default=None,
    )
    client_secret: SecretStr | None = Field(
        description="Client secret of the app registration.",
        default=None,
    )
    workspace_id: str = Field(
        description="Workspace ID (GUID) of the Log Analytics workspace of Microsoft Sentinel.",
    )
    additional_workspaces: ListFromString = Field(
        description="Other Log Analytics workspaces (IDs or resource IDs) queried with the main workspace.",
        default=[],
    )
    api_url: HttpUrl = Field(
        description="URL of the Log Analytics query API: 'https://api.loganalytics.io' (Azure public cloud), "
        "'https://api.loganalytics.us' (Azure Government) or 'https://api.loganalytics.azure.cn' (Azure China).",
        default=HttpUrl("https://api.loganalytics.io"),
    )
    authority_host: str = Field(
        description="Microsoft Entra authority host: 'login.microsoftonline.com' (Azure public cloud), "
        "'login.microsoftonline.us' (Azure Government) or 'login.chinacloudapi.cn' (Azure China).",
        default="login.microsoftonline.com",
    )
    sigma_pipeline: str = Field(
        description="pySigma pipeline(s) translating Sigma rules, chained with '+': 'sentinel_asim' "
        "(ASIM parsers), 'azure_monitor' (SecurityEvent and Azure Monitor tables), 'microsoft_xdr' "
        "(Defender XDR tables streamed to Sentinel) or 'none'.",
        default="sentinel_asim",
    )

    @model_validator(mode="after")
    def _check_credentials(self) -> Self:
        """Require the app registration credentials for the 'app_registration' method."""
        if self.auth_type != "app_registration":
            return self
        values = {
            "tenant_id": self.tenant_id,
            "client_id": self.client_id,
            "client_secret": (
                self.client_secret.get_secret_value() if self.client_secret else None
            ),
        }
        missing = [name for name, value in values.items() if not (value or "").strip()]
        if missing:
            raise ValueError(
                f"auth_type is 'app_registration' but {', '.join(missing)} is not set. Provide "
                "tenant_id, client_id and client_secret, or set auth_type to 'azure_credential'."
            )
        return self


class ConnectorSettings(BaseConnectorSettings):
    """Settings of the Microsoft Sentinel hunt connector."""

    connector: MicrosoftSentinelHuntConnectorConfig = Field(
        default_factory=MicrosoftSentinelHuntConnectorConfig
    )
    microsoft_sentinel_hunt: MicrosoftSentinelHuntConfig = Field(
        default_factory=MicrosoftSentinelHuntConfig
    )

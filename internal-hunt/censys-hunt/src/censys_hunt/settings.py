"""Configuration of the Censys Platform hunt connector."""

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseInternalHuntConnectorConfig,
    ListFromString,
)
from pydantic import Field, HttpUrl, SecretStr, field_validator


class CensysHuntConnectorConfig(BaseInternalHuntConnectorConfig):
    """Connector-level configuration of the Censys Platform hunt connector."""

    id: str = Field(
        description="A UUID v4 to identify the connector in OpenCTI.",
        default="13f4e73a-72d0-4104-b355-eacacf10cdc8",
    )
    name: str = Field(
        description="The name of the connector.",
        default="Censys Platform Hunt",
    )
    scope: ListFromString = Field(
        description="The hunt platform the connector executes against.",
        default=["censys"],
    )
    max_concurrent_runs: int | None = Field(
        description="Maximum number of hunt runs OpenCTI may dispatch to this connector at the same time "
        "(a run sends one search at a time). The platform budget is the minimum of its own setting and "
        "this value. Defaults to 1: Censys allows 1 concurrent request per organization on the Starter "
        "plan and 25 on the Search and Core plans.",
        default=1,
        ge=1,
    )


class CensysHuntConfig(BaseConfigModel):
    """Censys Platform settings of the hunt connector."""

    token: SecretStr = Field(
        description="Censys Platform personal access token of a user with the API Access role.",
    )
    organization_id: str | None = Field(
        description="ID of the Censys organization whose credits the searches use (required by the "
        "paid plans).",
        default=None,
    )
    api_url: HttpUrl = Field(
        description="URL of the Censys Platform API.",
        default=HttpUrl("https://api.platform.censys.io"),
    )
    create_certificates: bool = Field(
        description="Whether to create the X.509 certificates found (with their indicators).",
        default=True,
    )

    @field_validator("token")
    @classmethod
    def _token_not_blank(cls, value: SecretStr) -> SecretStr:
        """Reject a blank token."""
        if not value.get_secret_value().strip():
            raise ValueError("must not be blank.")
        return value


class ConnectorSettings(BaseConnectorSettings):
    """Settings of the Censys Platform hunt connector."""

    connector: CensysHuntConnectorConfig = Field(
        default_factory=CensysHuntConnectorConfig
    )
    censys_hunt: CensysHuntConfig = Field(default_factory=CensysHuntConfig)

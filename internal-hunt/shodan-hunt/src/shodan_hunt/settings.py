"""Configuration of the Shodan hunt connector."""

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseInternalHuntConnectorConfig,
    ListFromString,
)
from pydantic import Field, HttpUrl, SecretStr, field_validator


class ShodanHuntConnectorConfig(BaseInternalHuntConnectorConfig):
    """Connector-level configuration of the Shodan hunt connector."""

    id: str = Field(
        description="A UUID v4 to identify the connector in OpenCTI.",
        default="11d3f48e-c01a-41f5-bae7-468ca49af164",
    )
    name: str = Field(
        description="The name of the connector.",
        default="Shodan Hunt",
    )
    scope: ListFromString = Field(
        description="The hunt platform the connector executes against.",
        default=["shodan"],
    )
    max_concurrent_runs: int | None = Field(
        description="Maximum number of hunt runs OpenCTI may dispatch to this connector at the same time "
        "(a run sends one search at a time). The platform budget is the minimum of its own setting and "
        "this value. Defaults to 1: the Shodan API answers 1 request per second on every plan.",
        default=1,
        ge=1,
    )


class ShodanHuntConfig(BaseConfigModel):
    """Shodan settings of the hunt connector."""

    api_key: SecretStr = Field(
        description="Shodan API key of a plan with query credits.",
    )
    api_url: HttpUrl = Field(
        description="URL of the Shodan API.",
        default=HttpUrl("https://api.shodan.io"),
    )
    create_certificates: bool = Field(
        description="Whether to create the X.509 certificates found (with their indicators).",
        default=True,
    )

    @field_validator("api_key")
    @classmethod
    def _key_not_blank(cls, value: SecretStr) -> SecretStr:
        """Reject a blank API key."""
        if not value.get_secret_value().strip():
            raise ValueError("must not be blank.")
        return value


class ConnectorSettings(BaseConnectorSettings):
    """Settings of the Shodan hunt connector."""

    connector: ShodanHuntConnectorConfig = Field(
        default_factory=ShodanHuntConnectorConfig
    )
    shodan_hunt: ShodanHuntConfig = Field(default_factory=ShodanHuntConfig)

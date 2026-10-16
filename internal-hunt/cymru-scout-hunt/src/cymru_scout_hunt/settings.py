"""Configuration of the Team Cymru Scout hunt connector."""

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseInternalHuntConnectorConfig,
    ListFromString,
)
from pydantic import Field, HttpUrl, SecretStr, field_validator


class CymruScoutHuntConnectorConfig(BaseInternalHuntConnectorConfig):
    """Connector-level configuration of the Team Cymru Scout hunt connector."""

    id: str = Field(
        description="A UUID v4 to identify the connector in OpenCTI.",
        default="8e41a23c-b3e9-4bed-ab99-02b201d72f8c",
    )
    name: str = Field(
        description="The name of the connector.",
        default="Team Cymru Scout Hunt",
    )
    scope: ListFromString = Field(
        description="The hunt platform the connector executes against.",
        default=["cymru-scout"],
    )
    max_concurrent_runs: int | None = Field(
        description="Maximum number of hunt runs OpenCTI may dispatch to this connector at the same time "
        "(a run sends one search at a time). The platform budget is the minimum of its own setting and "
        "this value. Defaults to 1: Team Cymru Scout answers 1 request per second and caps the "
        "concurrent requests of an account.",
        default=1,
        ge=1,
    )


class CymruScoutHuntConfig(BaseConfigModel):
    """Team Cymru Scout settings of the hunt connector."""

    api_key: SecretStr = Field(
        description="Team Cymru Scout API key of an account with search queries.",
    )
    api_url: HttpUrl = Field(
        description="URL of the Team Cymru Scout API.",
        default=HttpUrl("https://scout.cymru.com/api/scout"),
    )

    @field_validator("api_key")
    @classmethod
    def _key_not_blank(cls, value: SecretStr) -> SecretStr:
        """Reject a blank API key."""
        if not value.get_secret_value().strip():
            raise ValueError("must not be blank.")
        return value


class ConnectorSettings(BaseConnectorSettings):
    """Settings of the Team Cymru Scout hunt connector."""

    connector: CymruScoutHuntConnectorConfig = Field(
        default_factory=CymruScoutHuntConnectorConfig
    )
    cymru_scout_hunt: CymruScoutHuntConfig = Field(default_factory=CymruScoutHuntConfig)

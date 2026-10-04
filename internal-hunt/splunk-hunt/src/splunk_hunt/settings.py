"""Configuration of the Splunk hunt connector."""

from typing import Literal, Self

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseInternalHuntConnectorConfig,
    ListFromString,
)
from pydantic import Field, HttpUrl, SecretStr, model_validator


class SplunkHuntConnectorConfig(BaseInternalHuntConnectorConfig):
    """Connector-level configuration of the Splunk hunt connector."""

    id: str = Field(
        description="A UUID v4 to identify the connector in OpenCTI.",
        default="315a82d6-6d55-43ca-a2cc-240b0bbd5b79",
    )
    name: str = Field(
        description="The name of the connector.",
        default="Splunk Hunt",
    )
    scope: ListFromString = Field(
        description="The hunt platform the connector executes against.",
        default=["splunk"],
    )
    security_platform_name: str | None = Field(
        description="Name of the OpenCTI Security Platform the hunts are executed against.",
        default="Splunk",
    )


class SplunkHuntConfig(BaseConfigModel):
    """Splunk REST API settings of the hunt connector."""

    url: HttpUrl = Field(
        description="URL of the Splunk REST API (management port), e.g. 'https://splunk.example.com:8089'.",
    )
    token: SecretStr | None = Field(
        description="Splunk authentication token (preferred). Leave empty to use username and password.",
        default=None,
    )
    username: str | None = Field(
        description="Splunk user name, used when no token is set.",
        default=None,
    )
    password: SecretStr | None = Field(
        description="Splunk user password, used when no token is set.",
        default=None,
    )
    verify_ssl: bool = Field(
        description="Whether to verify the TLS certificate of the Splunk REST API.",
        default=True,
    )
    app: str = Field(
        description="Splunk app namespace the search jobs run in.",
        default="search",
    )
    owner: str = Field(
        description="Splunk user namespace the search jobs run in.",
        default="nobody",
    )
    search_prefix: str = Field(
        description="SPL constraint added to every search, e.g. 'index=wineventlog OR index=sysmon', "
        "or the '`opencti_hunt_scope`' macro of the OpenCTI for Splunk Enterprise add-on.",
        default="",
    )
    sigma_pipeline: str = Field(
        description="pySigma pipeline(s) translating Sigma rules, chained with '+': "
        "'splunk_windows', 'splunk_sysmon_acceleration', 'splunk_cim' or 'none'.",
        default="splunk_windows",
    )
    output_format: Literal["default", "data_model"] = Field(
        description="pySigma Splunk output format: plain searches ('default') or CIM data model "
        "searches ('data_model', requires the 'splunk_cim' pipeline).",
        default="default",
    )
    poll_interval: float = Field(
        description="Seconds between two status checks of a search job.",
        default=2.0,
        gt=0,
    )

    @model_validator(mode="after")
    def _check_credentials(self) -> Self:
        """Require a token, or a user name and a password."""
        has_token = bool(self.token and self.token.get_secret_value().strip())
        has_basic = bool(
            self.username and self.password and self.password.get_secret_value().strip()
        )
        if not has_token and not has_basic:
            raise ValueError("Set token, or username and password.")
        return self


class ConnectorSettings(BaseConnectorSettings):
    """Settings of the Splunk hunt connector."""

    connector: SplunkHuntConnectorConfig = Field(
        default_factory=SplunkHuntConnectorConfig
    )
    splunk_hunt: SplunkHuntConfig = Field(default_factory=SplunkHuntConfig)

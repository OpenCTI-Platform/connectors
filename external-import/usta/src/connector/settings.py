"""
USTA connector settings.

Configuration management using Pydantic models following
the OpenCTI connector SDK patterns.
"""

# pylint: disable=too-few-public-methods

from abc import ABC
from datetime import timedelta
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, HttpUrl, SecretStr, field_serializer
from pydantic_settings import BaseSettings, SettingsConfigDict


class BaseConfigModel(BaseModel, ABC):
    """Base class for config models — frozen and accepts extra fields."""

    model_config = ConfigDict(extra="allow", frozen=True, validate_default=True)


class _OpenCTIConfig(BaseConfigModel):
    url: HttpUrl = Field(description="The base URL of the OpenCTI instance.")
    token: SecretStr = Field(description="The API token to connect to OpenCTI.")

    @field_serializer("token")
    def _serialize_token(self, v: SecretStr) -> str:
        return v.get_secret_value()


class _BaseConnectorConfig(BaseConfigModel, ABC):
    id: str = Field(description="A UUID v4 to identify the connector in OpenCTI.")
    name: str = Field(description="The name of the connector.")
    scope: str = Field(description="The scope of the connector.")
    log_level: Literal["debug", "info", "warn", "warning", "error"] = Field(
        description="The minimum level of logs to display.",
        default="error",
    )


class BaseExternalImportConnectorConfig(_BaseConnectorConfig):
    """Base config for external import connectors."""

    type: Literal["EXTERNAL_IMPORT"] = "EXTERNAL_IMPORT"
    duration_period: timedelta = Field(
        description="The period of time to await between two runs of the connector."
    )


class BaseConnectorSettings(BaseSettings):
    """Base settings class — loads configuration from environment variables."""

    model_config = SettingsConfigDict(
        env_nested_delimiter="_",
        env_nested_max_split=1,
        extra="allow",
        frozen=True,
    )

    opencti: _OpenCTIConfig = Field(
        default_factory=_OpenCTIConfig,  # type: ignore[arg-type]
        description="OpenCTI configurations.",
    )
    connector: _BaseConnectorConfig = Field(
        default_factory=_BaseConnectorConfig,  # type: ignore[arg-type]
        description="Connector configurations.",
    )

    def to_helper_config(self) -> dict[str, Any]:
        """Convert settings to a dict suitable for OpenCTIConnectorHelper."""
        return self.model_dump(mode="json", exclude_none=True)


class ExternalImportConnectorConfig(BaseExternalImportConnectorConfig):
    """
    Override the BaseExternalImportConnectorConfig to add parameters
    and/or defaults specific to the USTA connector.
    """

    name: str = Field(
        description="The name of the connector.",
        default="USTA",
    )
    scope: str = Field(
        description="The scope of the connector.",
        default="indicator,observable,malware,identity,incident,user-account,report,threat-actor",
    )
    duration_period: timedelta = Field(
        description="The period of time to await between two runs.",
        default=timedelta(minutes=30),
    )


class UstaConfig(BaseConfigModel):
    """
    Define parameters specific to the USTA connector.
    """

    api_base_url: HttpUrl = Field(
        description="USTA API base URL.",
        default="https://usta.prodaft.com",
    )
    api_key: SecretStr = Field(
        description="USTA API bearer token for authentication.",
    )

    @field_serializer("api_key")
    def _serialize_api_key(self, v: SecretStr) -> str:
        return v.get_secret_value()

    import_start_date: timedelta = Field(
        description=(
            "ISO 8601 duration string specifying how far back to import data "
            "(e.g., P90D for 90 days, P30D for 30 days). "
            "Only used on the very first run when no state exists."
        ),
        default=timedelta(days=90),
    )
    page_size: int = Field(
        description="Number of records to fetch per API page.",
        default=100,
        ge=1,
        le=500,
    )
    import_malicious_urls: bool = Field(
        description="Enable import of malicious URL indicators.",
        default=True,
    )
    import_phishing_sites: bool = Field(
        description="Enable import of phishing site indicators.",
        default=True,
    )
    import_malware_hashes: bool = Field(
        description="Enable import of malware hash indicators.",
        default=True,
    )
    import_compromised_credentials: bool = Field(
        description=(
            "Enable import of compromised credentials tickets "
            "(Account Takeover Prevention)."
        ),
        default=True,
    )
    import_credit_cards: bool = Field(
        description="Enable import of compromised credit card tickets (Fraud Intelligence).",
        default=True,
    )
    import_deep_sight_tickets: bool = Field(
        description=(
            "Enable import of Deep Sight intelligence tickets "
            "(threat reports, leaks, APT activity)."
        ),
        default=True,
    )
    store_credential_password: bool = Field(
        description=(
            "When enabled, the raw password from Account Takeover Prevention "
            "records is stored in the STIX User-Account credential field. "
            "Disabled by default for security reasons."
        ),
        default=False,
    )
    tlp_level: Literal["clear", "white", "green", "amber", "red"] = Field(
        description="TLP marking level to apply to imported data.",
        default="red",
    )
    confidence_level: int = Field(
        description="Confidence level for created STIX objects (0-100).",
        default=99,
        ge=0,
        le=100,
    )


class ConnectorSettings(BaseConnectorSettings):
    """
    Main settings class that combines all configuration sections.
    """

    connector: ExternalImportConnectorConfig = Field(
        default_factory=ExternalImportConnectorConfig
    )
    usta: UstaConfig = Field(default_factory=UstaConfig)

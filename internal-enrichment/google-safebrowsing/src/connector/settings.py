from typing import Any

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseInternalEnrichmentConnectorConfig,
    DeprecatedField,
    ListFromString,
)
from pydantic import Field, HttpUrl, SecretStr, field_validator

DEFAULT_API_URL = "https://safebrowsing.googleapis.com"


class InternalEnrichmentConnectorConfig(BaseInternalEnrichmentConnectorConfig):
    """
    Override the `BaseInternalEnrichmentConnectorConfig` to add parameters and/or defaults
    to the configuration for connectors of type `INTERNAL_ENRICHMENT`.
    """

    id: str = Field(
        description="A UUID v4 to identify the connector in OpenCTI.",
        default="d60e3bf8-5de9-496e-abf4-62123b0ca599",
    )
    name: str = Field(
        description="The name of the connector.",
        default="Google Safe Browsing",
    )
    scope: ListFromString = Field(
        description="The scope of the connector.",
        default=["Url", "Domain-Name", "Hostname"],
    )


class SafeBrowsingConfig(BaseConfigModel):
    """
    Define parameters and/or defaults for the configuration specific to the `SafeBrowsingConnector`.
    """

    api_key: SecretStr = Field(
        description="Safe Browsing API key (Google or Yandex).",
        min_length=1,
    )
    api_url: HttpUrl = Field(
        description=(
            "Safe Browsing API base URL. "
            "Use `https://sba.yandex.net` for Yandex Safe Browsing."
        ),
        default=HttpUrl(DEFAULT_API_URL),
    )

    @field_validator("api_url", mode="before")
    @classmethod
    def _empty_api_url_to_default(cls, value: Any) -> Any:
        """Treat an empty value (e.g. `SAFE_BROWSING_API_URL=`) as unset."""
        if value is None or (isinstance(value, str) and not value.strip()):
            return DEFAULT_API_URL
        return value


class LegacyGoogleSafeBrowsingConfig(BaseConfigModel):
    """
    Legacy `GOOGLE_SAFE_BROWSING_*` variables, migrated to the `safe_browsing` section.
    """

    api_key: SecretStr | None = Field(
        description="Legacy Google Safe Browsing API key.",
        default=None,
    )


class ConnectorSettings(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include `InternalEnrichmentConnectorConfig` and `SafeBrowsingConfig`.
    """

    connector: InternalEnrichmentConnectorConfig = Field(
        default_factory=InternalEnrichmentConnectorConfig
    )
    safe_browsing: SafeBrowsingConfig = Field(default_factory=SafeBrowsingConfig)

    # Legacy env vars prefix (`GOOGLE_SAFE_BROWSING_API_KEY`)
    google_safe_browsing: LegacyGoogleSafeBrowsingConfig = DeprecatedField(
        deprecated="Use 'SAFE_BROWSING_API_KEY' in the 'safe_browsing' section instead.",
        new_namespace="safe_browsing",
    )

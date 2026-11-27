"""Configuration of the Privara Unmask connector.

Values come from environment variables (``PRIVARA_UNMASK_API_KEY``...) or from
``config.yml`` (see ``config.yml.sample``). Pydantic validates them when the
connector starts.
"""

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseInternalEnrichmentConnectorConfig,
    ListFromString,
)
from pydantic import Field, HttpUrl, PositiveInt, SecretStr, field_validator


class InternalEnrichmentConnectorConfig(BaseInternalEnrichmentConnectorConfig):
    """Defaults of the `connector` section for this connector.

    `auto` keeps the SDK default (`false`): every analysis can be charged, so
    enrichment should be started by an analyst or a targeted playbook.
    """

    id: str = Field(
        description="A UUID v4 to identify the connector in OpenCTI.",
        default="3f0c7a52-6a2e-4c43-9a51-8d7a1f0e5b21",
    )
    name: str = Field(
        description="The name of the connector.",
        default="Privara Unmask",
    )
    scope: ListFromString = Field(
        description="The OpenCTI entity types the connector enriches (files carrying an Android package).",
        default=["Artifact", "StixFile"],
    )


class PrivaraUnmaskConfig(BaseConfigModel):
    """Options specific to the Privara Unmask connector."""

    api_base_url: HttpUrl = Field(
        description="Unmask API base URL.",
        default=HttpUrl("https://app.tajapps.com/api/unmask/v1"),
    )
    api_key: SecretStr = Field(
        description="Unmask API key (pvu_...) with the `submit` and `read` scopes. "
        "Create it at https://app.tajapps.com/dashboard/unmask/api (sign up at "
        "https://tajapps.com/unmask/).",
    )
    max_wait: PositiveInt = Field(
        description="Longest time in seconds to wait for one analysis before giving up "
        "(the analysis keeps running; enriching the file again within 24 hours picks up "
        "the same job at no extra cost).",
        default=3600,
    )
    poll_interval: PositiveInt = Field(
        description="First delay in seconds between two status checks when the API gives no "
        "Retry-After (it grows up to 120 s; never below 15 s).",
        default=30,
    )
    max_file_size_mb: PositiveInt | None = Field(
        description="Optional lower size cap in MB. By default the API's own limit is used "
        "(GET /balance, limits.max_file_mb).",
        default=None,
    )
    create_observables: bool = Field(
        description="Also create an observable (URL, IP, domain) for each C2 indicator.",
        default=True,
    )
    notify_email: bool | None = Field(
        description="Send the Privara result e-mail for each analysis "
        "(unset: the account's own setting).",
        default=None,
    )

    @field_validator("api_base_url")
    @classmethod
    def _https_only(cls, value: HttpUrl) -> HttpUrl:
        if value.scheme != "https" and value.host not in ("localhost", "127.0.0.1"):
            raise ValueError("api_base_url must use https")
        return value


class ConnectorSettings(BaseConnectorSettings):
    """All the configuration of the connector."""

    connector: InternalEnrichmentConnectorConfig = Field(
        default_factory=InternalEnrichmentConnectorConfig
    )
    privara_unmask: PrivaraUnmaskConfig = Field(default_factory=PrivaraUnmaskConfig)

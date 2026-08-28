from datetime import timedelta
from typing import Literal

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
    ListFromString,
)
from pydantic import Field, HttpUrl, SecretStr, model_validator


class ExternalImportConnectorConfig(BaseExternalImportConnectorConfig):
    """
    Override the `BaseExternalImportConnectorConfig` to add parameters and/or defaults
    to the configuration for connectors of type `EXTERNAL_IMPORT`.
    """

    name: str = Field(
        description="The name of the connector.",
        default="Doppel Threat Intelligence",
    )
    scope: ListFromString = Field(
        description="The scope of the connector.",
        default=["doppel"],
    )
    duration_period: timedelta = Field(
        description="The period of time to await between two runs of the connector.",
        default=timedelta(hours=1),
    )


class DoppelConfig(BaseConfigModel):
    """
    Define parameters and/or defaults for the configuration specific to the `DoppelConnector`.
    """

    api_base_url: HttpUrl = Field(
        description=(
            "Doppel API base URL. A trailing /v1 or /v2 is accepted and normalized "
            "to the selected api_version."
        ),
        default=HttpUrl("https://api.doppel.com"),
    )

    api_version: Literal["v1", "v2"] = Field(
        description=(
            "Doppel API version. Choose exactly one authentication mode: V1 API "
            "keys or V2 OAuth client credentials."
        ),
        default="v1",
    )

    api_key: SecretStr | None = Field(
        description=(
            "V1 API key sent as the x-api-key header. Required for V1 and must "
            "be unset for V2."
        ),
        default=None,
    )

    user_api_key: SecretStr | None = Field(
        description=(
            "Optional V1 user API key sent as the x-user-api-key header. Must "
            "be unset for V2."
        ),
        default=None,
    )

    organization_code: str | None = Field(
        description=(
            "Optional V1 organization workspace code sent as the "
            "x-organization-code header. Must be unset for V2."
        ),
        default=None,
    )

    client_id: str | None = Field(
        description="OAuth client ID required for V2 and must be unset for V1.",
        default=None,
    )

    client_secret: SecretStr | None = Field(
        description="OAuth client secret required for V2 and must be unset for V1.",
        default=None,
    )

    token_url: HttpUrl | None = Field(
        description=(
            "Optional V2 OAuth token endpoint. Defaults to /oauth/token on the "
            "API base URL and must be unset for V1."
        ),
        default=None,
    )

    token_audience: str = Field(
        description="OAuth audience used only for the V2 client-credentials exchange.",
        default="doppel-external",
        min_length=1,
    )

    tlp_level: Literal[
        "clear",
        "white",
        "green",
        "amber",
        "amber+strict",
        "red",
    ] = Field(
        description="Default TLP level of the imported entities.",
        default="clear",
    )

    alerts_endpoint: str = Field(
        description=(
            "API resource path for alert ingestion. A leading v1/ or v2/ is "
            "accepted and normalized to api_version."
        ),
        default="/alerts",
    )

    historical_polling_days: int = Field(
        description="Determines the time-window for initial data fetching", default=30
    )

    max_retries: int = Field(
        description="Configures automated error recovery from transient failures",
        default=3,
    )

    retry_delay: int = Field(
        description="Controls the frequency of requests during error recovery",
        default=30,
    )

    page_size: int = Field(
        description="Optimizes request volume and memory usage per fetch", default=100
    )

    enable_grouping_case: bool = Field(
        description="Enables creation of grouping cases", default=False
    )

    enable_rft_case: bool = Field(
        description="Enables creation of RFT cases for takedown alerts", default=False
    )

    @model_validator(mode="after")
    def validate_authentication(self) -> "DoppelConfig":
        """Require exactly one credential set for the selected API version."""
        if self.api_version == "v1":
            if any(
                value is not None
                for value in (self.client_id, self.client_secret, self.token_url)
            ):
                raise ValueError(
                    "V2 OAuth settings must be unset when api_version is v1"
                )
            if self.api_key is None or not self.api_key.get_secret_value().strip():
                raise ValueError("api_key is required when api_version is v1")
            return self

        if any(
            value is not None
            for value in (self.api_key, self.user_api_key, self.organization_code)
        ):
            raise ValueError("V1 API key settings must be unset when api_version is v2")
        if self.client_id is None or not self.client_id.strip():
            raise ValueError("client_id is required when api_version is v2")
        if (
            self.client_secret is None
            or not self.client_secret.get_secret_value().strip()
        ):
            raise ValueError("client_secret is required when api_version is v2")
        return self


class ConnectorSettings(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include `ExternalImportConnectorConfig` and `DoppelConfig`.
    """

    connector: ExternalImportConnectorConfig = Field(
        default_factory=ExternalImportConnectorConfig
    )
    doppel: DoppelConfig = Field(default_factory=DoppelConfig)

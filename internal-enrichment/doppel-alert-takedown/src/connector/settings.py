from typing import Literal

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseInternalEnrichmentConnectorConfig,
    ListFromString,
)
from pydantic import Field, HttpUrl, SecretStr, model_validator


class InternalEnrichmentConnectorConfig(BaseInternalEnrichmentConnectorConfig):
    """
    Override the `BaseInternalEnrichmentConnectorConfig` to add parameters and/or defaults
    to the configuration for the `Doppel Alert And Takedown` connector.
    """

    id: str = Field(
        description="The unique identifier of the connector.",
        default="b8821b12-470d-4037-a8c2-4bcf5432a000",
    )
    name: str = Field(
        description="The name of the connector.",
        default="Doppel Alert and Takedown",
    )
    scope: ListFromString = Field(
        description="The scope of the connector (types of observables to enrich).",
        default=["Url", "Domain-Name"],
    )


class DoppelAlertTakedownConfig(BaseConfigModel):
    """
    Define parameters and/or defaults for the configuration specific to the `Doppel Alert And Takedown` connector.
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
            "V1 user API key sent as the x-user-api-key header. Required for V1 "
            "and must be unset for V2."
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

    tags: ListFromString = Field(
        description="List of tags to attach to the alerts created in Doppel.",
        default=[],
    )
    takedown_comment: str = Field(
        description="Comment sent to Doppel when requesting a takedown.",
        default="Confirmed by OpenCTI — requesting takedown.",
    )
    max_tlp: Literal[
        "TLP:CLEAR",
        "TLP:WHITE",
        "TLP:GREEN",
        "TLP:AMBER",
        "TLP:AMBER+STRICT",
        "TLP:RED",
    ] = Field(
        default="TLP:RED",
        description="Max TLP level of entities to enrich.",
    )

    @model_validator(mode="after")
    def validate_authentication(self) -> "DoppelAlertTakedownConfig":
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
            if (
                self.user_api_key is None
                or not self.user_api_key.get_secret_value().strip()
            ):
                raise ValueError("user_api_key is required when api_version is v1")
            return self

        if any(value is not None for value in (self.api_key, self.user_api_key)):
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
    Override `BaseConnectorSettings` to include `InternalEnrichmentConnectorConfig` and `DoppelConfig`.
    """

    connector: InternalEnrichmentConnectorConfig = Field(
        default_factory=InternalEnrichmentConnectorConfig
    )
    doppel_alert_takedown: DoppelAlertTakedownConfig = Field(
        default_factory=DoppelAlertTakedownConfig
    )

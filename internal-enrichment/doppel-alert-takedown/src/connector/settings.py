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
        description=(
            "The OpenCTI entity types supported by the connector. Add Incident to "
            "request takedown for existing Doppel alerts."
        ),
        default=["Url", "Domain-Name"],
    )
    auto: bool = Field(
        description=(
            "Whether the connector should run automatically when an entity is "
            "created or updated. Must be false when CONNECTOR_SCOPE includes Incident."
        ),
        default=False,
    )
    auto_update: bool = Field(
        description=(
            "Whether the connector should run automatically when an entity is "
            "updated. Must be false when CONNECTOR_SCOPE includes Incident."
        ),
        default=False,
    )


class DoppelAlertTakedownConfig(BaseConfigModel):
    """
    Define parameters and/or defaults for the configuration specific to the `Doppel Alert And Takedown` connector.
    """

    api_base_url: HttpUrl = Field(
        description="Doppel API base URL.",
        default=HttpUrl("https://api.doppel.com"),
    )
    api_key: SecretStr = Field(
        description="Doppel API key, sent as the `x-api-key` header.",
    )
    user_api_key: SecretStr = Field(
        description="Doppel user API key, sent as the `x-user-api-key` header.",
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

    @model_validator(mode="after")
    def prevent_automatic_incident_takedowns(self) -> "ConnectorSettings":
        """Incident takedown must always be an explicit manual or playbook action."""
        incident_enabled = any(
            str(scope).lower() == "incident" for scope in self.connector.scope
        )
        if incident_enabled and (self.connector.auto or self.connector.auto_update):
            raise ValueError(
                "CONNECTOR_AUTO and CONNECTOR_AUTO_UPDATE must be false when "
                "CONNECTOR_SCOPE includes Incident"
            )
        return self

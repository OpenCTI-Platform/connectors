from typing import Literal

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseInternalEnrichmentConnectorConfig,
    ListFromString,
)
from pydantic import Field, HttpUrl, SecretStr


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

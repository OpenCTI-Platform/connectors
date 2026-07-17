from typing import Literal

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseInternalEnrichmentConnectorConfig,
)
from pydantic import Field, HttpUrl, field_validator


class InternalEnrichmentConnectorConfig(BaseInternalEnrichmentConnectorConfig):
    """
    Override the `BaseInternalEnrichmentConnectorConfig` to add parameters and/or defaults
    to the configuration for the `Doppel Alert And Takedown` connector.
    """

    name: str = Field(
        description="The name of the connector.",
        default="Doppel Alert And Takedown",
    )
    scope: str = Field(
        description="The scope of the connector (types of observables to enrich).",
        default="Url,Domain-Name",
    )


class DoppelConfig(BaseConfigModel):
    """
    Define parameters and/or defaults for the configuration specific to the `Doppel Alert And Takedown` connector.
    """

    api_base_url: HttpUrl = Field(
        description="Doppel API base URL.",
        default=HttpUrl("https://api.doppel.com"),
    )
    api_key: str = Field(
        description="Doppel API key, sent as the `x-api-key` header.",
    )
    user_api_key: str = Field(
        description="Doppel user API key, sent as the `x-user-api-key` header.",
    )
    tags: list[str] = Field(
        description="List of tags to attach to the alerts created in Doppel.",
        default_factory=list,
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
        "",
    ] = Field(
        default="",
        description="Max TLP level of entities to enrich (empty = no limit).",
    )

    @field_validator("tags", mode="before")
    @classmethod
    def _split_tags(cls, value: object) -> object:
        """Allow tags to be provided as a comma-separated string (env var friendly)."""
        if isinstance(value, str):
            return [tag.strip() for tag in value.split(",") if tag.strip()]
        return value


class ConnectorSettings(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include `InternalEnrichmentConnectorConfig` and `DoppelConfig`.
    """

    connector: InternalEnrichmentConnectorConfig = Field(
        default_factory=InternalEnrichmentConnectorConfig
    )
    doppel: DoppelConfig = Field(default_factory=DoppelConfig)

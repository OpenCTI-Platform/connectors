from typing import Literal

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseInternalEnrichmentConnectorConfig,
)
from connectors_sdk.settings.annotated_types import ListFromString
from pydantic import Field, HttpUrl, SecretStr


class InternalEnrichmentConnectorConfig(BaseInternalEnrichmentConnectorConfig):
    """
    Override the `BaseInternalEnrichmentConnectorConfig` to add parameters and/or defaults
    to the configuration for connectors of type `INTERNAL_ENRICHMENT`.
    """

    id: str = Field(
        description="The UUID of the connector.",
        default="9955194d-d000-4507-bc9d-19f851c20de9",
    )
    name: str = Field(
        description="The name of the connector.",
        default="Silent Push - Enrichment",
    )
    scope: ListFromString = Field(
        description="The scope of the connector",
        default=[
            "Indicator",
            "IPv4-Addr",
            "IPv6-Addr",
            "Domain-Name",
            "Hostname",
            "URL",
        ],
    )


class SilentpushConfig(BaseConfigModel):
    """
    Define parameters and/or defaults for the configuration specific to the `SilentpushConnector`.
    """

    api_base_url: HttpUrl = Field(
        description="External API base URL.",
        default="https://app.silentpush.com/api/v2/",
    )
    api_key: SecretStr = Field(description="API key for authentication.")
    max_tlp: Literal[
        "TLP:WHITE",
        "TLP:CLEAR",
        "TLP:GREEN",
        "TLP:AMBER",
        "TLP:AMBER+STRICT",
        "TLP:RED",
    ] = Field(
        description="Max TLP level of the entities to enrich.",
        default="TLP:AMBER",
    )
    verify_cert: bool = Field(
        description="Whether to verify SSL certificates when connecting to the API.",
        default=True,
    )


class ConnectorSettings(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include `InternalEnrichmentConnectorConfig` and `SilentpushConfig`.
    """

    connector: InternalEnrichmentConnectorConfig = Field(
        default_factory=InternalEnrichmentConnectorConfig
    )
    silentpush: SilentpushConfig = Field(default_factory=SilentpushConfig)

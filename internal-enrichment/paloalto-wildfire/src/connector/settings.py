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
    to the configuration for connectors of type `INTERNAL_ENRICHMENT`.
    """

    name: str = Field(
        description="The name of the connector.",
        default="Palo Alto Networks WildFire",
    )
    scope: ListFromString = Field(
        description="The scope of the connector (observable types to enrich).",
        default=["StixFile", "Artifact"],
    )


class PaloaltoWildfireConfig(BaseConfigModel):
    """
    Define parameters and/or defaults for the configuration specific to the
    `PaloaltoWildfireConnector`.
    """

    api_key: SecretStr = Field(
        description="Palo Alto Networks WildFire API key.",
    )
    api_base_url: HttpUrl = Field(
        description="WildFire API base URL (cloud region or appliance).",
        default="https://wildfire.paloaltonetworks.com/publicapi",
    )
    max_tlp: Literal[
        "TLP:CLEAR",
        "TLP:WHITE",
        "TLP:GREEN",
        "TLP:AMBER",
        "TLP:AMBER+STRICT",
        "TLP:RED",
    ] = Field(
        description="Maximum TLP of the observable the connector is allowed to enrich.",
        default="TLP:AMBER",
    )


class ConnectorSettings(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include `InternalEnrichmentConnectorConfig` and
    `PaloaltoWildfireConfig`.
    """

    connector: InternalEnrichmentConnectorConfig = Field(
        default_factory=InternalEnrichmentConnectorConfig
    )
    paloalto_wildfire: PaloaltoWildfireConfig = Field(
        default_factory=PaloaltoWildfireConfig
    )

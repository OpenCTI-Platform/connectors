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
    submit_unknown: bool = Field(
        description=(
            "Submit unknown files (carried by the observable) to WildFire for analysis "
            "when no verdict exists yet. Disabled by default (opt-in): submission "
            "uploads the sample to WildFire."
        ),
        default=False,
    )
    max_file_size: int = Field(
        description=(
            "Maximum size (in bytes) of a file the connector will download from OpenCTI "
            "and submit to WildFire."
        ),
        default=33554432,
    )
    submission_timeout: int = Field(
        description=(
            "Maximum time (in seconds) to wait for a submitted file's verdict before "
            "giving up."
        ),
        default=600,
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

from typing import Literal

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseInternalEnrichmentConnectorConfig,
    ListFromString,
)
from pydantic import Field, SecretStr


class InternalEnrichmentConnectorConfig(BaseInternalEnrichmentConnectorConfig):
    """
    Override the `BaseInternalEnrichmentConnectorConfig` to add parameters and/or defaults
    to the configuration for connectors of type `INTERNAL_ENRICHMENT`.
    """

    id: str = Field(
        description="A UUID v4 to identify the connector in OpenCTI.",
        default="19168ccc-5b5c-4d87-9611-87578e341a58",
    )
    name: str = Field(
        description="The name of the connector.",
        default="Hatching Triage Sandbox",
    )
    scope: ListFromString = Field(
        description="The scope of the connector.",
        default=["Artifact", "Url"],
    )


class HatchingTriageSandboxConfig(BaseConfigModel):
    """
    Define parameters and/or defaults for the configuration specific to the Hatching Triage Sandbox connector.
    """

    token: SecretStr = Field(
        description="Hatching Triage API token. See https://tria.ge/account",
    )
    base_url: str = Field(
        description="Hatching Triage API base URL. See https://tria.ge/docs/",
        default="https://tria.ge/api",
    )
    use_existing_analysis: bool = Field(
        description="If true, get existing analysis if any.",
        default=True,
    )
    family_color: str = Field(
        description="Label color for malware family.",
        default="#0059f7",
    )
    botnet_color: str = Field(
        description="Label color for botnet.",
        default="#f79e00",
    )
    campaign_color: str = Field(
        description="Label color for campaign.",
        default="#7a01e5",
    )
    tag_color: str = Field(
        description="Label color for all other labels.",
        default="#54483b",
    )
    max_tlp: Literal[
        "TLP:CLEAR",
        "TLP:GREEN",
        "TLP:AMBER",
        "TLP:AMBER+STRICT",
        "TLP:RED",
    ] = Field(
        description="Maximum TLP marking for observable submission.",
        default="TLP:AMBER",
    )


class ConnectorSettings(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include `InternalEnrichmentConnectorConfig`
    and `HatchingTriageSandboxConfig`.
    """

    connector: InternalEnrichmentConnectorConfig = Field(
        default_factory=InternalEnrichmentConnectorConfig
    )
    hatching_triage_sandbox: HatchingTriageSandboxConfig = Field(
        default_factory=HatchingTriageSandboxConfig
    )

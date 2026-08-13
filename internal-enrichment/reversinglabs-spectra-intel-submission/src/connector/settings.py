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
        default="a7f3b2c1-6d4e-4f8a-9b0c-2e1d3f5a7b9c",
    )
    name: str = Field(
        description="The name of the connector.",
        default="ReversingLabs Spectra Intelligence Submission",
    )
    scope: ListFromString = Field(
        description="The scope of the connector.",
        default=["Artifact", "Url", "StixFile", "File"],
    )


class ReversinglabsSpectraIntelSubmissionConfig(BaseConfigModel):
    """
    Config fields specific to the ReversingLabs Spectra Intel Submission connector.
    """

    url: str = Field(
        description="ReversingLabs Spectra Intelligence API base URL.",
        default="data.reversinglabs.com",
    )
    username: str = Field(
        description="ReversingLabs Spectra Intelligence username.",
    )
    password: SecretStr = Field(
        description="ReversingLabs Spectra Intelligence password.",
    )
    max_tlp: Literal[
        "TLP:WHITE",
        "TLP:CLEAR",
        "TLP:GREEN",
        "TLP:AMBER",
        "TLP:AMBER+STRICT",
        "TLP:RED",
    ] = Field(
        description="Maximum TLP level for entities that the connector can enrich.",
        default="TLP:AMBER",
    )
    sandbox_os: Literal["windows7", "windows10", "windows11", "macos11", "linux"] = (
        Field(
            description="The platform to execute the sample on.",
            default="windows10",
        )
    )
    sandbox_internet_sim: bool = Field(
        description="Enable internet simulation during sandbox analysis.",
        default=False,
    )
    create_indicators: bool = Field(
        description="Create STIX indicators from analysis results.",
        default=True,
    )
    poll_interval: int = Field(
        description="Polling interval in seconds to check analysis results.",
        default=250,
        ge=250,
    )


class ConnectorSettings(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include connector-specific configuration.
    """

    connector: InternalEnrichmentConnectorConfig = Field(
        default_factory=InternalEnrichmentConnectorConfig
    )
    reversinglabs_spectra_intel_submission: (
        ReversinglabsSpectraIntelSubmissionConfig
    ) = Field(default_factory=ReversinglabsSpectraIntelSubmissionConfig)

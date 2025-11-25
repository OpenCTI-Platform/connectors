from typing import Literal

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseInternalEnrichmentConnectorConfig,
)
from pydantic import Field


class ReversinglabsSpectraAnalyzeConfig(BaseConfigModel):
    url: str = Field(description="API base URL", validation_alias="spectra_analyze_url")
    token: str = Field(
        description="API token", validation_alias="spectra_analyze_token"
    )
    tlp_level: Literal[
        "TLP:WHITE",
        "TLP:CLEAR",
        "TLP:GREEN",
        "TLP:AMBER",
        "TLP:AMBER+STRICT",
        "TLP:RED",
    ] = Field(description="TLP level", default="TLP:AMBER")
    max_tlp: Literal[
        "TLP:WHITE",
        "TLP:CLEAR",
        "TLP:GREEN",
        "TLP:AMBER",
        "TLP:AMBER+STRICT",
        "TLP:RED",
    ] = Field(
        description="Maximum TLP for entity that connector can enrich",
        default="TLP:AMBER",
    )
    sandbox_os: Literal["windows11", "windows10", "windows7", "macos11", "linux"] = (
        Field(description="The platform to execute the sample on", default="windows10")
    )
    cloud_analysis: bool = Field(description="Enable cloud analysis", default=True)


class ConfigLoader(BaseConnectorSettings):
    """Handles connector configuration loading and validation."""

    connector: BaseInternalEnrichmentConnectorConfig = Field(
        default_factory=BaseInternalEnrichmentConnectorConfig
    )
    reversinglabs_spectra_analyze: ReversinglabsSpectraAnalyzeConfig = Field(
        default_factory=ReversinglabsSpectraAnalyzeConfig,
        validation_alias="reversinglabs",
    )

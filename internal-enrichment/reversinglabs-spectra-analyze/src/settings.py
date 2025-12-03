from typing import Literal

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseInternalEnrichmentConnectorConfig,
)
from connectors_sdk.core.pydantic import ListFromString
from pydantic import Field, model_validator


class ConnectorSettings(BaseInternalEnrichmentConnectorConfig):
    name: str = Field(
        description="Connector name.", default="ReversingLabs Spectra Analyze"
    )
    scope: ListFromString = Field(
        description="Comma-separated list of entity types the connector will enrich.",
        default="Artifact,IPv4-Addr,Domain-Name",
    )


class ReversinglabsSpectraAnalyzeConfig(BaseConfigModel):
    url: str = Field(description="API base URL", validation_alias="spectra_analyze_url")
    token: str = Field(
        description="API token", validation_alias="spectra_analyze_token"
    )
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

    @model_validator(mode="before")
    @classmethod
    def migrate_deprecated_settings(cls, data) -> dict:
        reversinglabs = data.get("reversinglabs", {})
        reversinglabs.update(data.pop("reversinglabs_spectra_analyze", {}))
        data["reversinglabs"] = reversinglabs
        return data

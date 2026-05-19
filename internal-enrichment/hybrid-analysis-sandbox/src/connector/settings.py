from typing import Literal

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseInternalEnrichmentConnectorConfig,
    DeprecatedField,
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
        default="22538379-7caa-41ac-a401-c752db2cd2ac",
    )
    name: str = Field(
        description="The name of the connector.",
        default="Hybrid Analysis (Sandbox Windows 10 64bit)",
    )
    scope: ListFromString = Field(
        description="The scope of the connector.",
        default=["StixFile", "Artifact", "Url", "Domain-Name", "Hostname"],
    )


class HybridAnalysisSandboxConfig(BaseConfigModel):
    """
    Define parameters and/or defaults for the configuration specific to the `HybridAnalysisSandboxConnector`.
    """

    token: SecretStr = Field(
        description="Hybrid Analysis API token.",
    )
    environment_id: Literal[400, 310, 300, 200, 160, 120, 110, 100] = Field(
        description=(
            "Analysis environment ID. Available values: "
            "400=Mac Catalina 64 bit (x86), "
            "310=Linux (Ubuntu 20.04, 64 bit), "
            "300=Linux (Ubuntu 16.04, 64 bit), "
            "200=Android Static Analysis, "
            "160=Windows 10 64 bit, "
            "120=Windows 7 64 bit, "
            "110=Windows 7 32 bit (HWP Support), "
            "100=Windows 7 32 bit."
        ),
        default=110,
    )
    max_tlp: Literal[
        "TLP:CLEAR",
        "TLP:GREEN",
        "TLP:AMBER",
        "TLP:AMBER+STRICT",
        "TLP:RED",
    ] = Field(
        description="Maximum TLP for submission.",
        default="TLP:AMBER",
    )

    api_key: SecretStr = DeprecatedField(
        new_namespaced_var="token",
        removal_date="2026-12-31",
    )


class ConnectorSettings(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include `InternalEnrichmentConnectorConfig` and `HybridAnalysisSandboxConfig`.
    """

    connector: InternalEnrichmentConnectorConfig = Field(
        default_factory=InternalEnrichmentConnectorConfig
    )
    hybrid_analysis_sandbox: HybridAnalysisSandboxConfig = Field(
        default_factory=HybridAnalysisSandboxConfig
    )

    # Legacy env vars prefix
    hybrid_analysis: HybridAnalysisSandboxConfig = DeprecatedField(
        new_namespace="hybrid_analysis_sandbox",
        removal_date="2026-12-31",
    )

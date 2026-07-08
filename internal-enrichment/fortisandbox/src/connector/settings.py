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
        default="FortiSandbox",
    )
    scope: ListFromString = Field(
        description="The scope of the connector (observable types to enrich).",
        default=["StixFile", "Artifact"],
    )


class FortisandboxConfig(BaseConfigModel):
    """
    Define parameters and/or defaults for the configuration specific to the
    `FortisandboxConnector`.
    """

    api_base_url: HttpUrl = Field(
        description="FortiSandbox base URL (appliance, VM or cloud), without the /jsonrpc suffix.",
    )
    username: str = Field(
        description="FortiSandbox API username.",
    )
    password: SecretStr = Field(
        description="FortiSandbox API password.",
    )
    api_version: str = Field(
        description="FortiSandbox JSON-RPC API version sent with every request.",
        default="4.2.4",
    )
    ssl_verify: bool = Field(
        description="Whether to verify the FortiSandbox TLS certificate.",
        default=True,
    )
    submit_unknown: bool = Field(
        description=(
            "Submit unknown files for on-demand analysis when no verdict exists yet "
            "(requires the observable to carry an uploaded file). Enabled by default so "
            "Artifacts uploaded to OpenCTI are detonated in FortiSandbox."
        ),
        default=True,
    )
    max_file_size: int = Field(
        description=(
            "Maximum size (in bytes) of a file the connector will download from OpenCTI "
            "and submit to FortiSandbox."
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
    `FortisandboxConfig`.
    """

    connector: InternalEnrichmentConnectorConfig = Field(
        default_factory=InternalEnrichmentConnectorConfig
    )
    fortisandbox: FortisandboxConfig = Field(default_factory=FortisandboxConfig)

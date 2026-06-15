from datetime import timedelta
from typing import Literal

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
)
from pydantic import Field, HttpUrl, SecretStr


class ExternalImportConnectorConfig(BaseExternalImportConnectorConfig):
    """
    Override the `BaseExternalImportConnectorConfig` to add parameters and/or defaults
    to the configuration for connectors of type `EXTERNAL_IMPORT`.
    """

    name: str = Field(
        description="The name of the connector.",
        default="CTM360 ThreatCover",
    )
    duration_period: timedelta = Field(
        description="The period of time to await between two runs of the connector.",
        default=timedelta(hours=1),
    )


class Ctm360ThreatcoverConfig(BaseConfigModel):
    """
    Define parameters and/or defaults for the configuration specific to the
    `Ctm360ThreatcoverConnector`.
    """

    api_root_url: HttpUrl = Field(
        description="CTM360 ThreatCover TAXII 2.1 API root URL (tenant specific).",
    )
    api_token: SecretStr = Field(
        description="CTM360 ThreatCover API token (sent as the TAXII Authorization header).",
    )
    collection_id: str = Field(
        description="TAXII collection id to poll (the ThreatCover 'Observables' collection).",
    )
    tlp_level: Literal[
        "clear",
        "white",
        "green",
        "amber",
        "amber+strict",
        "red",
    ] = Field(
        description="Default TLP level applied to the imported entities.",
        default="amber",
    )
    verify_ssl: bool = Field(
        description="Whether to verify the TAXII server TLS certificate.",
        default=True,
    )


class ConnectorSettings(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include `ExternalImportConnectorConfig` and
    `Ctm360ThreatcoverConfig`.
    """

    connector: ExternalImportConnectorConfig = Field(
        default_factory=ExternalImportConnectorConfig
    )
    ctm360_threatcover: Ctm360ThreatcoverConfig = Field(
        default_factory=Ctm360ThreatcoverConfig
    )

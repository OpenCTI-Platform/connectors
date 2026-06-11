from datetime import timedelta
from typing import Literal

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
    ListFromString,
)
from pydantic import Field, HttpUrl, SecretStr


class ExternalImportConnectorConfig(BaseExternalImportConnectorConfig):
    """
    Override the `BaseExternalImportConnectorConfig` to add parameters and/or defaults
    to the configuration for connectors of type `EXTERNAL_IMPORT`.
    """

    name: str = Field(
        description="The name of the connector.",
        default="Recorded Future ASI Exposures",
    )
    scope: ListFromString = Field(
        description="The scope of the connector.",
        default=[
            "incident",
            "vulnerability",
            "ipv4-addr",
            "ipv6-addr",
            "domain-name",
        ],
    )
    duration_period: timedelta = Field(
        description="The period of time to await between two runs of the connector.",
        default=timedelta(hours=1),
    )


class RfAsiConfig(BaseConfigModel):
    """
    Define parameters and/or defaults for the configuration specific to the `RfAsiConnector`.
    """

    api_base_url: HttpUrl = Field(
        description="API base URL.",
        default="https://api.securitytrails.com/v2",
    )
    api_key: SecretStr = Field(description="API key for authentication.")
    project_id: str = Field(description="ASI project ID to fetch exposures from.")
    tlp_level: Literal[
        "clear",
        "white",
        "green",
        "amber",
        "amber+strict",
        "red",
    ] = Field(
        description="Default TLP level of the imported entities.",
        default="amber+strict",
    )
    portal_base_url: HttpUrl | None = Field(
        description="Optional portal base URL for external reference deep links.",
        default=None,
    )
    page_limit: int = Field(
        description="Number of exposures to fetch per API page.",
        default=100,
        ge=1,
        le=1000,
    )


class ConnectorSettings(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include `ExternalImportConnectorConfig` and `RfAsiConfig`.
    """

    connector: ExternalImportConnectorConfig = Field(
        default_factory=ExternalImportConnectorConfig
    )
    rf_asi: RfAsiConfig = Field(default_factory=RfAsiConfig)

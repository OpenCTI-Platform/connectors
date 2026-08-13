from datetime import timedelta
from typing import Literal

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
    ListFromString,
)
from pydantic import Field


class ExternalImportConnectorConfig(BaseExternalImportConnectorConfig):
    """
    Override the `BaseExternalImportConnectorConfig` to add parameters and/or defaults
    to the configuration for connectors of type `EXTERNAL_IMPORT`.
    """

    name: str = Field(
        description="The name of the connector.",
        default="CrowdStrike Recon",
    )
    scope: ListFromString = Field(
        description="The scope of the connector.",
        default=["crowdstrike-recon"],
    )
    duration_period: timedelta = Field(
        description="The period of time to await between two runs of the connector.",
        default=timedelta(hours=1),
    )


class CrowdStrikeReconConfig(BaseConfigModel):
    """
    Define parameters and/or defaults for the configuration specific to the `CrowdStrikeReconConnector`.
    """

    api_base_url: str = Field(description="API base URL.")
    client_id: str = Field(description="CrowdStrike Falcon Client ID.")
    client_secret: str = Field(description="CrowdStrike Falcon Client Secret.")
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
    import_start_date: timedelta = Field(
        default=timedelta(days=10),
        description="ISO 8601 duration string specifying how far back to import alerts (e.g., P1D for 1 day, P7D for 7 days)",
    )
    filter_topic: str = Field(
        description="Filter notifications by topic name(s). Comma-separated string (e.g. 'SA_BRAND,SA_THIRD_PARTY_V2'). Empty means no filtering.",
        default="",
    )
    filter_type: str = Field(
        description="Filter notifications by item type(s). Comma-separated string (e.g. 'typosquatting_domain,exposed_data'). Empty means no filtering.",
        default="",
    )
    filter_priority: str = Field(
        description="Filter notifications by priority(ies). Comma-separated string (e.g. 'high,medium,low'). Empty means no filtering.",
        default="",
    )


class ConnectorSettings(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include `ExternalImportConnectorConfig` and `CrowdStrikeReconConfig`.
    """

    connector: ExternalImportConnectorConfig = Field(
        default_factory=ExternalImportConnectorConfig
    )
    crowdstrike_recon: CrowdStrikeReconConfig = Field(
        default_factory=CrowdStrikeReconConfig
    )

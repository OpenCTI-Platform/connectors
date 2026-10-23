"""Configuration settings for the ORKL connector."""

from datetime import timedelta

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
    ListFromString,
)
from connectors_sdk.models.enums import TLPLevel
from pydantic import Field, HttpUrl


class ExternalImportConnectorConfig(BaseExternalImportConnectorConfig):
    """Connector-level configuration for ORKL."""

    id: str = Field(
        description="A UUID v4 to identify the connector in OpenCTI.",
        default="5a1f8b3e-0c2d-4a7f-9e6b-3d8c1a4f7b20",
    )
    name: str = Field(
        description="The name of the connector.",
        default="ORKL",
    )
    scope: ListFromString = Field(
        description="The scope of the connector.",
        default=["orkl"],
    )
    duration_period: timedelta = Field(
        description="The period of time to await between two runs of the connector.",
        default=timedelta(days=1),
    )


class OrklConfig(BaseConfigModel):
    """ORKL API configuration."""

    api_base_url: HttpUrl = Field(
        description="Base URL of the ORKL API.",
        default="https://orkl.eu/api/v1",
    )
    full_resync_period: timedelta = Field(
        description=(
            "How often the whole ORKL library is re-imported to pick up changes on "
            "existing entries (e.g. 'P30D' for 30 days). The first run always imports "
            "the whole library; between two full re-imports, only entries created "
            "since the last run are imported. Set to 'P0D' to disable periodic "
            "re-imports."
        ),
        default=timedelta(days=30),
    )
    tlp_level: TLPLevel = Field(
        description="TLP marking level applied to created STIX objects.",
        default=TLPLevel.CLEAR,
    )
    threat_actor_as_intrusion_set: bool = Field(
        description="Create ORKL threat actors as Intrusion Sets (true) or as Threat Actors (false).",
        default=True,
    )
    ingest_tools: bool = Field(
        description="Create Tool entities from the threat actors' tools. Disabled by default: the ORKL feed does not distinguish malware from tools, so enabling this will create Tool entities for what are in fact malware families.",
        default=False,
    )


class ConnectorSettings(BaseConnectorSettings):
    """Root settings combining OpenCTI, connector, and ORKL configurations."""

    connector: ExternalImportConnectorConfig = Field(
        default_factory=ExternalImportConnectorConfig
    )
    orkl: OrklConfig = Field(default_factory=OrklConfig)

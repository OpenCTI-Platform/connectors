"""Connector configuration, from environment variables (`OFFSEQ_MIRAGE_*`) or `config.yml`."""

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
    id: str = Field(
        description="The unique identifier of the connector.",
        default="29bd5f71-1b78-4252-8fc4-dd0b8cd467dc",
    )
    name: str = Field(
        description="The name of the connector.",
        default="OffSeq Mirage",
    )
    scope: ListFromString = Field(
        description="The scope of the connector, i.e. the entity types it imports.",
        default=[
            "Indicator",
            "IPv4-Addr",
            "Url",
            "StixFile",
            "Attack-Pattern",
            "Vulnerability",
        ],
    )
    duration_period: timedelta = Field(
        description="Time to wait between two runs, as an ISO 8601 duration. "
        "The feed is rebuilt once a day; an unchanged bundle is skipped.",
        default=timedelta(hours=6),
    )


class MirageConfig(BaseConfigModel):
    """Options specific to the OffSeq Mirage connector."""

    feed_url: HttpUrl = Field(
        description="URL of the Mirage Feed STIX 2.1 bundle.",
        default=HttpUrl("https://feeds.offseq.com/mirage-feed/latest/stix/mirage.json"),
    )
    import_relationships: bool = Field(
        description="Import the ATT&CK techniques and CVEs each indicator is linked "
        "to, with `indicates` and `related-to` relationships.",
        default=True,
    )
    create_observables: bool = Field(
        description="Create the observable behind each indicator, with a `based-on` "
        "relationship.",
        default=True,
    )
    tlp_level: TLPLevel = Field(
        description="TLP marking applied to every object this connector creates. "
        "The feed is published as TLP:CLEAR.",
        default=TLPLevel.CLEAR,
    )
    batch_size: int = Field(
        description="Indicators per bundle sent to OpenCTI.",
        default=1000,
        ge=100,
        le=5000,
    )


class ConnectorSettings(BaseConnectorSettings):
    connector: ExternalImportConnectorConfig = Field(
        default_factory=ExternalImportConnectorConfig
    )
    offseq_mirage: MirageConfig = Field(default_factory=MirageConfig)

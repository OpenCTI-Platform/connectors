"""Connector configuration models.

Configuration values are read from environment variables or `config.yml`
(see `config.yml.sample` and the README's "Configuration variables" section).
"""

from datetime import timedelta

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
    ListFromString,
)
from connectors_sdk.models.enums import TLPLevel
from pydantic import Field, HttpUrl


class ConnectorConfig(BaseExternalImportConnectorConfig):
    """Connector-level configuration, common to every `EXTERNAL_IMPORT` connector."""

    id: str = Field(
        description="The unique identifier of the connector.",
        default="cd55d2d1-cdd9-4880-9e76-afa1f4c1d0cb",
    )
    name: str = Field(
        description="The name of the connector.",
        default="ENISA EUVD",
    )
    scope: ListFromString = Field(
        description="The scope of the connector, i.e. the entity types it imports.",
        default=["vulnerability"],
    )
    duration_period: timedelta = Field(
        description="Time to wait between two runs of the connector, "
        "as an ISO 8601 duration (e.g. `PT2H` for two hours).",
        default=timedelta(hours=2),
    )


class EuvdConfig(BaseConfigModel):
    """Configuration specific to the ENISA EUVD API (env prefix: `EUVD_`)."""

    api_base_url: HttpUrl = Field(
        default=HttpUrl("https://euvdservices.enisa.europa.eu/api"),
        description="The base URL of the ENISA EUVD API.",
    )
    import_start_date: timedelta = Field(
        default=timedelta(days=30),
        description="First run only: how far back (last-update) to pull, as an "
        "ISO 8601 duration (e.g. 'P30D' for 30 days). Subsequent runs resume from "
        "the connector's persisted state.",
    )
    tlp_level: TLPLevel = Field(
        default=TLPLevel.CLEAR,
        description="Default TLP (Traffic Light Protocol) marking applied to "
        "every object this connector creates in OpenCTI.",
    )
    ingest_software: bool = Field(
        default=False,
        description="Enable/disable the import of Software observables and their "
        "'has' relationship to each vulnerability. Off by default: a single "
        "vulnerability can reference many affected products, which increases "
        "the volume of objects created per run.",
    )


class ConnectorSettings(BaseConnectorSettings):
    """Aggregates all configuration objects the connector needs."""

    connector: ConnectorConfig = Field(default_factory=ConnectorConfig)
    euvd: EuvdConfig = Field(default_factory=EuvdConfig)

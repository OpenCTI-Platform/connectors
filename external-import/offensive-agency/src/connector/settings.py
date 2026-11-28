"""Connector configuration models.

Two groups of options:

    - `ExternalImportConnectorConfig`: options common to every `EXTERNAL_IMPORT`
      connector (inherited from `connectors-sdk`), with defaults for this feed.
    - `OffensiveAgencyConfig`: options specific to the offensive.agency feed,
      read from `OFFENSIVE_AGENCY_*` environment variables or the
      `offensive_agency` section of `config.yml`.
"""

from datetime import timedelta

from connectors_sdk import (
    BaseConfigModel,
    BaseExternalImportConnectorConfig,
    BaseExternalImportConnectorSettings,
    ListFromString,
)
from connectors_sdk.models.enums import TLPLevel
from pydantic import Field, HttpUrl


class ExternalImportConnectorConfig(BaseExternalImportConnectorConfig):
    """Connector-level configuration, with defaults for the offensive.agency feed."""

    id: str = Field(
        description="The unique identifier of the connector (a UUIDv4).",
        default="9a3a5220-ef54-455f-944c-e3a2a32b8d2d",
    )
    name: str = Field(
        description="The name of the connector.",
        default="Offensive Agency",
    )
    scope: ListFromString = Field(
        description="The scope of the connector, i.e. the entity types it imports.",
        default=["Indicator", "Tool", "IPv4-Addr"],
    )
    duration_period: timedelta = Field(
        description="Time to wait between two runs of the connector, "
        "as an ISO 8601 duration (e.g. `PT6H` for six hours). "
        "The feed is dated by day, so a shorter period does not bring more data.",
        default=timedelta(hours=6),
    )


class OffensiveAgencyConfig(BaseConfigModel):
    """Configuration specific to the offensive.agency feed."""

    api_base_url: HttpUrl = Field(
        description="Base URL of the offensive.agency API. "
        "The connector reads the STIX feed at `<api_base_url>/feeds/stix.json`.",
        default=HttpUrl("https://www.offensive.agency/api/v1"),
    )
    tlp_level: TLPLevel = Field(
        description="TLP marking applied to every object the connector creates. "
        "The feed is public and carries no marking.",
        default=TLPLevel.CLEAR,
    )
    indicator_validity: timedelta = Field(
        description="How long an indicator stays valid after the feed last saw the "
        "agent on its IP, as an ISO 8601 duration (e.g. `P30D` for 30 days). "
        "The feed only keeps the last 7 days: an IP that leaves it expires in "
        "OpenCTI once this period has passed. Minimum `P1D`, since the feed is "
        "dated by day.",
        default=timedelta(days=30),
        ge=timedelta(days=1),
    )
    create_observables: bool = Field(
        description="Create an IPv4 observable for each indicator, linked by a "
        "`based-on` relationship.",
        default=True,
    )


class ConnectorSettings(BaseExternalImportConnectorSettings):
    """All the configuration the connector needs."""

    connector: ExternalImportConnectorConfig = Field(
        default_factory=ExternalImportConnectorConfig
    )
    offensive_agency: OffensiveAgencyConfig = Field(
        default_factory=OffensiveAgencyConfig,
    )

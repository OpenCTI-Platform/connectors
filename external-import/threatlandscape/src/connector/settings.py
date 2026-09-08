from datetime import timedelta
from typing import Literal

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
)
from pydantic import Field, HttpUrl


class ExternalImportConnectorConfig(BaseExternalImportConnectorConfig):
    """
    Override the `BaseExternalImportConnectorConfig` to set defaults specific to
    the Threat Landscape connector.
    """

    name: str = Field(
        description="The name of the connector.",
        default="Threat Landscape",
    )
    duration_period: timedelta = Field(
        description="The period of time to await between two runs of the connector.",
        default=timedelta(hours=1),
    )


class ThreatLandscapeConfig(BaseConfigModel):
    """
    Configuration parameters specific to the Threat Landscape connector.
    """

    api_base_url: HttpUrl = Field(
        description="Base URL of the Threat Landscape REST API.",
        default="https://api.threatlandscape.io/rest/v1",
    )
    api_key: str = Field(
        description="API key sent in the 'apikey' request header.",
    )
    import_since: timedelta = Field(
        description=(
            "Lookback window applied on the first run only. "
            "Expressed as an ISO 8601 duration (e.g. P30D for 30 days, P365D for 1 year). "
            "Subsequent runs use the seq_id cursor and ignore this value."
        ),
        default=timedelta(days=30),
    )
    feed: Literal[
        "intelligence",
        "intelligence-osint",
        "intelligence-darknet",
        "ioc",
    ] = Field(
        description=(
            "Which Threat Landscape API feed to ingest. "
            "'intelligence' ingests full STIX bundles from both OSINT and darknet sources. "
            "'intelligence-osint' restricts to OSINT bundles only. "
            "'intelligence-darknet' restricts to darknet bundles only. "
            "'ioc' ingests lean actionable indicators from the IOC API."
        ),
    )
    page_size: int = Field(
        description="Number of bundles to fetch per API request.",
        default=100,
        ge=1,
        le=1000,
    )


class ConnectorSettings(BaseConnectorSettings):
    """
    Top-level settings combining standard connector config with
    Threat Landscape-specific parameters.
    """

    connector: ExternalImportConnectorConfig = Field(
        default_factory=ExternalImportConnectorConfig
    )
    threatlandscape: ThreatLandscapeConfig = Field(
        default_factory=ThreatLandscapeConfig
    )

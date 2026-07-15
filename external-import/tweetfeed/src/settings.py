from datetime import timedelta
from typing import Optional

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
    ListFromString,
)
from pydantic import Field


class ExternalImportConnectorConfig(BaseExternalImportConnectorConfig):
    """Connector-level configuration for the TweetFeed connector.

    Provides a default for the SDK's structural ``duration_period`` field. The
    connector keeps its own ``tweetfeed.interval`` scheduling loop, so this value
    is only used to satisfy the manager-supported contract.
    """

    name: str = Field(default="TweetFeed", description="The name of the connector.")

    duration_period: timedelta = Field(
        description="The period of time to await between two runs of the connector.",
        default=timedelta(days=1),
    )
    scope: ListFromString = Field(
        description="The scope of the connector",
        default=[],
    )


class TweetFeedConfig(BaseConfigModel):
    """Config fields specific to the TweetFeed connector.

    Mirrors the connector's existing configuration variables one-to-one.
    """

    confidence_level: int = Field(
        description="Score applied to imported data, from 0 (Unknown) to 100 (Fully trusted).",
        default=25,
    )
    create_indicators: bool = Field(
        description="Whether to create indicators from the imported IOCs.",
        default=True,
    )
    create_observables: bool = Field(
        description="Whether to create observables from the imported IOCs.",
        default=True,
    )
    interval: int = Field(
        description="Interval, in days, between two runs of the connector.",
        default=1,
    )
    update_existing_data: bool = Field(
        description="Whether to update data already present in OpenCTI.",
        default=True,
    )
    org_name: Optional[str] = Field(
        description="Name of the author organization created in OpenCTI.",
        default="Tweetfeed",
    )
    org_description: Optional[str] = Field(
        description="Description of the author organization created in OpenCTI.",
        default="Tweetfeed, a connector to import IOC from Twitter.",
    )
    days_back_in_time: int = Field(
        description="Number of days to retrieve data back in time.",
        default=30,
    )


class ConnectorSettings(BaseConnectorSettings):
    """Global settings for the TweetFeed connector."""

    connector: ExternalImportConnectorConfig = Field(
        default_factory=ExternalImportConnectorConfig
    )
    tweetfeed: TweetFeedConfig = Field(default_factory=TweetFeedConfig)

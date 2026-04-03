from datetime import timedelta
from typing import Literal, Optional

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
)
from pydantic import Field, HttpUrl


class ExternalImportConnectorConfig(BaseExternalImportConnectorConfig):
    """
    Override the `BaseExternalImportConnectorConfig` to add parameters and/or defaults
    to the configuration for connectors of type `EXTERNAL_IMPORT`.
    """

    name: str = Field(
        description="The name of the connector.",
        default="Doppel Threat Intelligence",
    )
    duration_period: timedelta = Field(
        description="The period of time to await between two runs of the connector.",
        default=timedelta(hours=1),
    )


class DoppelConfig(BaseConfigModel):
    """
    Define parameters and/or defaults for the configuration specific to the `DoppelConnector`.
    """

    api_base_url: HttpUrl = Field(
        description="API base URL.", default="https://api.doppel.com/v1"
    )

    api_key: str = Field(description="API key for authentication.")

    user_api_key: Optional[str] = Field(description="Used for user-specific identity")

    organization_code: Optional[str] = Field(
        description="Identifies the specific organizational workspace for multi-tenant keys"
    )

    tlp_level: Literal[
        "clear",
        "white",
        "green",
        "amber",
        "amber+strict",
        "red",
    ] = Field(
        description="Default TLP level of the imported entities.",
        default="clear",
    )

    alerts_endpoint: str = Field(
        description="Specifies the API resource path for alert ingestion",
        default="/alerts",
    )

    historical_polling_days: int = Field(
        description="Determines the time-window for initial data fetching", default=30
    )

    max_retries: int = Field(
        description="Configures automated error recovery from transient failures",
        default=3,
    )

    retry_delay: int = Field(
        description="Controls the frequency of requests during error recovery",
        default=30,
    )

    page_size: int = Field(
        description="Optimizes request volume and memory usage per fetch", default=100
    )


class ConnectorSettings(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include `ExternalImportConnectorConfig` and `DoppelConfig`.
    """

    connector: ExternalImportConnectorConfig = Field(
        default_factory=ExternalImportConnectorConfig
    )
    doppel: DoppelConfig = Field(default_factory=DoppelConfig)

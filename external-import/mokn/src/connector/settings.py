"""Settings module following OpenCTI standard structure."""

from datetime import timedelta
from typing import Literal

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
    ListFromString,
)
from pydantic import Field, SecretStr


class ExternalImportConnectorConfig(BaseExternalImportConnectorConfig):
    """Base external import connector configuration."""

    id: str = Field(description="A UUID v4 to identify the connector in OpenCTI.")
    name: str = Field(description="The name of the connector.", default="MokN")
    scope: ListFromString = Field(
        description="The scope of the connector.",
        default=["mokn"],
    )
    duration_period: timedelta = Field(
        description="The period of time to await between two runs of the connector.",
        default=timedelta(hours=1),
    )


class MoknConfig(BaseConfigModel):
    """Configuration specific to the MokN connector."""

    console_url: str = Field(description="MokN console base URL.")
    api_key: SecretStr = Field(description="MokN API key.")
    tlp_level: Literal["clear", "white", "green", "amber", "amber+strict", "red"] = (
        Field(
            description="TLP marking level.",
            default="amber",
        )
    )
    first_run_days_back: int = Field(
        description="Number of days to retrieve on first execution.",
        default=30,
        ge=1,
    )


class ConnectorSettings(BaseConnectorSettings):
    """Connector settings with OpenCTI and MokN configuration sections."""

    connector: ExternalImportConnectorConfig = Field(
        default_factory=ExternalImportConnectorConfig
    )
    mokn: MoknConfig = Field(default_factory=MoknConfig)

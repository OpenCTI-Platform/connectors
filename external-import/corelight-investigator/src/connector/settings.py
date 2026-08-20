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
        default="Corelight Investigator",
    )
    scope: ListFromString = Field(
        description="The scope of the connector.",
        default=["corelight-investigator"],
    )
    duration_period: timedelta = Field(
        description="The period of time to await between two runs of the connector.",
        default=timedelta(hours=1),
    )


class CorelightInvestigatorConfig(BaseConfigModel):
    """
    Define parameters and/or defaults for the configuration specific to the
    `CorelightInvestigatorConnector`.
    """

    api_base_url: HttpUrl = Field(
        description="Corelight Investigator API base URL (region specific, e.g. https://eu.api.investigator.corelight.com).",
    )
    api_key: SecretStr = Field(
        description="Corelight Investigator API key (sent as an Authorization bearer header).",
    )
    alerts_path: str = Field(
        description="Path of the Investigator Detections and Alerts API endpoint.",
        default="/api/v1/alerts",
    )
    import_window_days: int = Field(
        description="Number of days to look back on the first run.",
        default=7,
        gt=0,
    )
    max_alerts: int = Field(
        description="Maximum number of alerts to request per run.",
        default=1000,
        gt=0,
    )
    tlp_level: Literal[
        "clear",
        "white",
        "green",
        "amber",
        "amber+strict",
        "red",
    ] = Field(
        description="Default TLP marking applied to the imported entities.",
        default="amber",
    )
    ssl_verify: bool = Field(
        description="Whether to verify the API server TLS certificate.",
        default=True,
    )


class ConnectorSettings(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include `ExternalImportConnectorConfig` and
    `CorelightInvestigatorConfig`.
    """

    connector: ExternalImportConnectorConfig = Field(
        default_factory=ExternalImportConnectorConfig
    )
    corelight_investigator: CorelightInvestigatorConfig = Field(
        default_factory=CorelightInvestigatorConfig
    )

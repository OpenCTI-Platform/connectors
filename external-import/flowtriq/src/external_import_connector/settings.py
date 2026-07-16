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
    """
    Override the `BaseExternalImportConnectorConfig` to add parameters and/or defaults
    to the configuration for connectors of type `EXTERNAL_IMPORT`.
    """

    id: str = Field(description="A UUID v4 to identify the connector in OpenCTI.")
    name: str = Field(
        description="The name of the connector.",
        default="Flowtriq DDoS Incidents",
    )
    scope: ListFromString = Field(
        description="The scope of the connector.",
        default=["flowtriq"],
    )
    duration_period: timedelta = Field(
        description="The period of time to await between two runs of the connector.",
        default=timedelta(hours=1),
    )


class FlowtriqConfig(BaseConfigModel):
    """
    Define parameters and/or defaults for the configuration specific to the Flowtriq connector.
    """

    api_url: str = Field(
        description="Flowtriq API base URL.",
        default="https://app.flowtriq.com",
    )
    api_key: SecretStr = Field(
        description="Your Flowtriq deploy token (64-character hex string).",
    )
    incident_status: Literal["active", "resolved", "false_positive", ""] = Field(
        description="Filter incidents by status. Leave empty to fetch all statuses.",
        default="resolved",
    )
    incident_severity: ListFromString = Field(
        description="Comma-separated severity levels to import (critical, high, medium, low). Leave empty for all.",
        default=[],
    )
    create_indicator: bool = Field(
        description="Whether to create Indicator objects from observables.",
        default=True,
    )
    tlp_level: Literal["clear", "green", "amber", "amber+strict", "red"] = Field(
        description="TLP marking for imported data (`clear`, `green`, `amber`, `amber+strict`, `red`).",
        default="green",
    )
    import_limit: int = Field(
        description="Maximum number of incidents to fetch per run.",
        default=100,
    )
    min_severity: Literal["low", "medium", "high", "critical", ""] = Field(
        description="Minimum severity threshold. Incidents below this level are skipped.",
        default="",
    )


class ConnectorSettings(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include `ExternalImportConnectorConfig` and `FlowtriqConfig`.
    """

    connector: ExternalImportConnectorConfig = Field(
        default_factory=ExternalImportConnectorConfig
    )
    flowtriq: FlowtriqConfig = Field(default_factory=FlowtriqConfig)

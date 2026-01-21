from datetime import timedelta

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

    id: str = Field(
        description="A UUID v4 to identify the connector in OpenCTI.",
    )
    name: str = Field(
        description="The name of the connector.",
        default="Microsoft Sentinel Incidents",
    )
    scope: ListFromString = Field(
        description="The scope of the connector.",
        default=["sentinel"],
    )
    duration_period: timedelta = Field(
        description="The period of time to await between two runs of the connector.",
        default=timedelta(hours=1),
    )


class MicrosoftSentinelIncidentsConfig(BaseConfigModel):
    """
    Define parameters and/or defaults for the configuration specific to the `MicrosoftSentinelIncidentsConnector`.
    """

    tenant_id: str = Field(
        description="Your Azure App Tenant ID, see the screenshot to help you find this information.",
    )
    client_id: str = Field(
        description="Your Azure App Client ID, see the screenshot to help you find this information.",
    )
    client_secret: SecretStr = Field(
        description="Your Azure App Client secret, See the screenshot to help you find this information.",
    )
    subscription_id: str = Field(
        description="Your Microsoft Sentinel subscription ID.",
    )
    resource_group: str = Field(
        description="Your Microsoft Sentinel resource group.",
    )
    workspace_id: str = Field(
        description="Your Microsoft Sentinel workspace ID.",
    )
    import_start_date: str = Field(
        description="Import starting date (in YYYY-MM-DD format or YYYY-MM-DDTHH:MM:SSZ format) - used only if connector's state is not set.",
        default="2020-01-01T00:00:00Z",
    )
    filter_labels: ListFromString = Field(
        description="Only incidents containing these specified labels will be retrieved and ingested (comma separated values).",
        default=[],
    )


class ConnectorSettings(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include `ExternalImportConnectorConfig` and `MicrosoftSentinelIncidentsConfig`.
    """

    connector: ExternalImportConnectorConfig = Field(
        default_factory=ExternalImportConnectorConfig
    )
    microsoft_sentinel_incidents: MicrosoftSentinelIncidentsConfig = Field(
        default_factory=MicrosoftSentinelIncidentsConfig
    )

from datetime import datetime, timedelta, timezone

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
    DatetimeFromIsoString,
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
        default="Microsoft Defender Incidents",
    )
    scope: ListFromString = Field(
        description="The scope of the connector.",
        default=["defender"],
    )
    duration_period: timedelta = Field(
        description="The period of time to await between two runs of the connector.",
        default=timedelta(hours=1),
    )


class MicrosoftDefenderIncidentsConfig(BaseConfigModel):
    """
    Define parameters and/or defaults for the configuration specific to the `MicrosoftDefenderIncidentsConnector`.
    """

    tenant_id: str = Field(
        description="Your Azure App Tenant ID, see connector's README to help you find this information.",
    )
    client_id: str = Field(
        description="Your Azure App Client ID, see connector's README to help you find this information.",
    )
    client_secret: SecretStr = Field(
        description="Your Azure App Client secret, see connector's README to help you find this information.",
    )
    api_base_url: HttpUrl = Field(
        description="The Microsoft Graph API base URL used to retrieve incidents.",
        default=HttpUrl("https://graph.microsoft.com/v1.0"),
    )
    incident_path: str = Field(
        description="The Microsoft Graph API path used to retrieve incidents.",
        default="/security/incidents",
    )
    import_start_date: DatetimeFromIsoString = Field(
        description="The date from which to start importing incidents, in ISO 8601 format "
        "(e.g. `2025-01-01T00:00:00Z`). Only used when the connector's state is not set yet.",
        default=datetime(2020, 1, 1, tzinfo=timezone.utc),
    )


class ConnectorSettings(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include `ExternalImportConnectorConfig` and `MicrosoftDefenderIncidentsConfig`.
    """

    connector: ExternalImportConnectorConfig = Field(
        default_factory=ExternalImportConnectorConfig
    )
    microsoft_defender_incidents: MicrosoftDefenderIncidentsConfig = Field(
        default_factory=MicrosoftDefenderIncidentsConfig
    )

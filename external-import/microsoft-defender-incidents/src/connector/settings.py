from datetime import timedelta

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
    DatetimeFromIsoString,
    ListFromString,
)
from connectors_sdk.settings.annotated_types import parse_iso_string
from pydantic import Field, SecretStr


class ExternalImportConnectorConfig(BaseExternalImportConnectorConfig):
    """
    Override `BaseExternalImportConnectorConfig` to add defaults for this connector.
    """

    id: str = Field(
        description="A UUID v4 to identify the connector in OpenCTI.",
        default="ChangeMe",
    )
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
    Config fields specific to the Microsoft Defender Incidents connector.
    """

    tenant_id: str = Field(
        description="Azure Tenant ID for Microsoft Graph API authentication.",
    )
    client_id: str = Field(
        description="Azure App Client ID for Microsoft Graph API authentication.",
    )
    client_secret: SecretStr = Field(
        description="Azure App Client Secret for Microsoft Graph API authentication.",
    )
    import_start_date: DatetimeFromIsoString = Field(
        description=(
            "Start date for importing incidents in ISO 8601 format "
            "(e.g. '2025-01-01T00:00:00Z'). "
            "Used only on the first run; subsequent runs use the stored state."
        ),
        # `default_factory` is used to set a dynamic default value (datetime) at runtime
        default=parse_iso_string("2025-01-01T00:00:00Z"),
    )
    api_base_url: str = Field(
        description="Microsoft Graph API base URL.",
        default="https://graph.microsoft.com/v1.0",
    )
    incident_path: str = Field(
        description="Microsoft Graph API path for retrieving security incidents.",
        default="/security/incidents",
    )


class ConnectorSettings(BaseConnectorSettings):
    """
    Global settings for the Microsoft Defender Incidents connector.

    Combines OpenCTI connection settings, connector configuration, and
    connector-specific Microsoft Defender parameters.
    """

    connector: ExternalImportConnectorConfig = Field(
        default_factory=ExternalImportConnectorConfig
    )
    microsoft_defender_incidents: MicrosoftDefenderIncidentsConfig = Field(
        default_factory=MicrosoftDefenderIncidentsConfig
    )

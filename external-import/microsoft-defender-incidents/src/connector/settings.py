from datetime import timedelta

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
    DatetimeFromIsoString,
    ListFromString,
)
from pydantic import Field, SecretStr, field_validator


def parse_status_mapping(value: str | dict[str, str] | None) -> dict[str, str]:
    """
    Coerce 'status:id,status:id' into a dict keyed by the lower-case Defender status.
    An empty string or None gives an empty mapping (the feature is off).
    """
    if value is None:
        return {}
    if isinstance(value, dict):
        items = value.items()
    else:
        items = []
        for pair in value.split(","):
            pair = pair.strip()
            if not pair or pair in ('""', "''"):
                continue
            if ":" not in pair:
                raise ValueError(
                    f"Invalid status mapping entry '{pair}', expected '<defender status>:<status id>'"
                )
            key, status_id = pair.split(":", 1)
            items.append((key, status_id))
    mapping = {}
    for key, status_id in items:
        key, status_id = str(key).strip(), str(status_id).strip()
        if not key or not status_id:
            raise ValueError(
                f"Invalid status mapping entry '{key}:{status_id}', expected '<defender status>:<status id>'"
            )
        mapping[key.lower()] = status_id
    return mapping


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
            "Start date for importing incidents, as an ISO-8601 datetime "
            "(e.g. '2025-01-01T00:00:00Z') or duration relative to now "
            "(e.g. 'P30D' for 30 days ago). "
            "Used only on the first run; subsequent runs use the stored state."
        ),
        default="P30D",
    )
    api_base_url: str = Field(
        description="Microsoft Graph API base URL.",
        default="https://graph.microsoft.com/v1.0",
    )
    incident_path: str = Field(
        description="Microsoft Graph API path for retrieving security incidents.",
        default="/security/incidents",
    )
    status_mapping: str = Field(
        description=(
            "Optional mapping from a Microsoft Defender incident status to an OpenCTI "
            "Case-Incident workflow status, as comma-separated "
            "'<defender status>:<status name or id>' pairs "
            "(e.g. 'active:NEW,inProgress:IN_PROGRESS,awaitingAction:IN_PROGRESS,"
            "resolved:CLOSED,redirected:CLOSED'). "
            "Defender statuses: active, inProgress, resolved, redirected, awaitingAction "
            "(matched case-insensitively). A status name is resolved once per run against "
            "the Case-Incident statuses; a UUID is used as the status id. When the "
            "incident's status is mapped, the Case-Incident workflow status is set; "
            "otherwise it is left unchanged. Empty (default): no workflow status is set."
        ),
        default="",
    )

    @field_validator("status_mapping")
    @classmethod
    def _validate_status_mapping(cls, value: str) -> str:
        # Fail at startup on a malformed mapping instead of at the first incident.
        parse_status_mapping(value)
        return value


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

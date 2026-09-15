from datetime import datetime, timedelta, timezone
from typing import Literal

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
    ConfigValidationError,
    DatetimeFromIsoString,
    DeprecatedField,
    ListFromString,
)
from pydantic import (
    Field,
    HttpUrl,
)


class ConfigRetrievalError(Exception):
    """Custom exception for configuration retrieval errors."""


class ConnectorConfig(BaseExternalImportConnectorConfig):
    id: str = Field(
        description="A UUID v4 to identify the connector in OpenCTI.",
        default="9850490a-4273-429b-95f8-47dacda88fbf",
    )
    name: str = Field(default="ThreatMatch", description="The name of the connector.")
    scope: ListFromString = Field(
        default=["threatmatch"], description="The scope of the connector."
    )
    duration_period: timedelta = Field(
        default=timedelta(days=1),
        description="Polling frequency as an ISO-8601 duration (e.g., 'P1D').",
    )


class ThreatmatchConfig(BaseConfigModel):
    client_id: str = Field(
        description="ThreatMatch OAuth2 client id (Client Credentials)."
    )
    client_secret: str = Field(description="ThreatMatch OAuth2 client secret.")

    url: HttpUrl = Field(
        default=HttpUrl("https://eu.threatmatch.com"),
        description="Base URL of the ThreatMatch API.",
    )
    import_from_date: DatetimeFromIsoString = Field(
        default_factory=lambda: datetime.now(tz=timezone.utc) - timedelta(days=30),
        description=(
            "Relative ISO-8601 duration (e.g., 'P30D') used to set the first import "
            "window. Applied on the first run only. Defaults to 30 days ago from the current date. "
        ),
    )
    import_profiles: bool = Field(
        default=True, description="Import the ThreatMatch profiles dataset."
    )
    import_alerts: bool = Field(
        default=True, description="Import the ThreatMatch alerts dataset."
    )
    import_iocs: bool = Field(
        default=True, description="Import the ThreatMatch IOCs dataset."
    )
    tlp_level: Literal["white", "clear", "green", "amber", "amber+strict", "red"] = (
        Field(
            default="amber",
            description="Default TLP marking applied when missing on source objects.",
        )
    )
    threat_actor_as_intrusion_set: bool = Field(
        default=True,
        description="Map ThreatMatch threat-actor objects to STIX intrusion-set.",
    )

    interval: int | None = DeprecatedField(
        default=None,
        deprecated="Use 'CONNECTOR_DURATION_PERIOD' in the 'connector' section instead.",
        new_namespace="connector",
        new_namespaced_var="duration_period",
        new_value_factory=lambda x: timedelta(days=int(x)),
        removal_date="2027-01-01",
    )


class ConnectorSettings(BaseConnectorSettings):
    connector: ConnectorConfig = Field(default_factory=ConnectorConfig)
    threatmatch: ThreatmatchConfig = Field(default_factory=ThreatmatchConfig)

    def __init__(self) -> None:
        """Initialize the configuration model, wrapping validation errors."""
        try:
            super().__init__()
        except ConfigValidationError as e:
            raise ConfigRetrievalError(
                "Invalid OpenCTI configuration.", e.__cause__
            ) from e

from datetime import timedelta
from typing import Literal

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
    ListFromString,
)
from connectors_sdk.models.enums import TLPLevel
from pydantic import Field, SecretStr, TypeAdapter, field_validator


class ExternalImportConnectorConfig(BaseExternalImportConnectorConfig):
    """
    Override the `BaseExternalImportConnectorConfig` to add parameters and/or defaults
    to the configuration for connectors of type `EXTERNAL_IMPORT`.
    """

    id: str = Field(
        description="The unique identifier of the connector.",
        default="92483abc-27f1-46b4-afcb-d9a0a405754a",
    )
    name: str = Field(
        description="The name of the connector.",
        default="Google DTM",
    )
    scope: ListFromString = Field(
        description="The scope of the connector, e.g. 'google-dtm'.",
        default=["google-dtm"],
    )
    duration_period: timedelta = Field(
        description="The period of time to await between two runs of the connector in ISO 8601 format e.g., 'PT1H' for 1 hour.",
        default=timedelta(hours=1),
    )


class GoogleDTMConfig(BaseConfigModel):
    """
    Define parameters and/or defaults for the configuration specific to the `GoogleDTMConnector`.
    """

    api_key: SecretStr = Field(
        description="Google DTM API Key",
    )
    tlp: TLPLevel = Field(
        default=TLPLevel.AMBER_STRICT,
        description="Default Traffic Light Protocol (TLP) marking for imported data.",
    )
    import_start_date: timedelta = Field(
        default=timedelta(days=10),
        description="ISO 8601 duration string specifying how far back to import alerts (e.g., P1D for 1 day, P7D for 7 days)",
    )
    alert_type: list[
        Literal[
            "Compromised Credentials",
            "Document",
            "Domain Discovery",
            "Email",
            "Forum Post",
            "Message",
            "Paste",
            "Shop Listing",
            "Tweet",
            "Web Content",
        ]
    ] = Field(
        default=[],
        description="Comma-separated list of alert types to ingest. Leave blank to retrieve alerts of all types.",
    )
    alert_severity: list[
        Literal[
            "high",
            "medium",
            "low",
        ]
    ] = Field(
        default=[],
        description="Comma-separated list of alert severities to ingest. Leave blank to retrieve alerts of all severities.",
    )

    @field_validator("alert_type", "alert_severity", mode="before")
    @classmethod
    def split_comma_separated_values(cls, value):
        """Validate and convert comma-separated string values into a list."""
        return TypeAdapter(ListFromString).validate_python(value)


class ConnectorSettings(BaseConnectorSettings):
    """
    Define the settings for the `GoogleDTMConnector`, including both the common connector configuration
    parameters and the specific ones for this connector.
    """

    connector: ExternalImportConnectorConfig = Field(
        default_factory=ExternalImportConnectorConfig,
    )
    google_dtm: GoogleDTMConfig = Field(
        default_factory=GoogleDTMConfig,
    )

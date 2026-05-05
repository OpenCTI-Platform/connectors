from datetime import timedelta

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
    ListFromString,
)
from connectors_sdk.models.enums import TLPLevel
from pydantic import Field, HttpUrl, SecretStr


class ExternalImportConnectorConfig(BaseExternalImportConnectorConfig):
    """
    Override the `BaseExternalImportConnectorConfig` to add parameters and/or defaults
    to the configuration for connectors of type `EXTERNAL_IMPORT`.
    """

    name: str = Field(
        description="The name of the connector.",
        default="Sublime Security",
    )
    scope: ListFromString = Field(
        default=["sublime"],
        description=(
            "The scope or type of data the connector is importing, "
            "either a MIME type or Stix Object (for information only)."
        ),
    )
    duration_period: timedelta = Field(
        description="The period of time to await between two runs of the connector.",
        default=timedelta(minutes=3),
    )
    id: str = Field(
        description="A UUID v4 to identify the connector in OpenCTI.",
        default="0a3a00ad-b5f0-4dca-83b6-9012662dcf80",
    )


class SublimeConfig(BaseConfigModel):
    """
    Define parameters and/or defaults for the configuration specific to the `SublimeConnector`.
    """

    url: HttpUrl = Field(
        description="Sublime platform URL for API connections.",
        default="https://platform.sublime.security",
    )
    token: SecretStr = Field(description="Sublime Security API authentication token.")
    incident_type: str = Field(
        default="phishing", description="Label to apply to incident type."
    )
    incident_prefix: str = Field(
        default="Sublime Incident - ", description="Prefix for incident object names."
    )
    case_prefix: str = Field(
        default="Case - ", description="Prefix for case object names."
    )
    auto_create_cases: bool = Field(
        default=False, description="Automatically create investigation cases."
    )
    verdicts: ListFromString = Field(
        default=["malicious"],
        description="Comma-separated attack score verdicts to process.",
    )
    set_priority: bool = Field(
        default=True, description="Enable priority mapping from attack score."
    )
    set_severity: bool = Field(
        default=True, description="Enable severity mapping from attack score."
    )
    first_run_duration: timedelta = Field(
        default=timedelta(hours=8),
        description="ISO 8601 duration for initial data fetch on first run.",
    )
    force_historical: bool = Field(
        default=False,
        description="Force historical fetch ignoring existing state for correcting improper states.",
    )
    batch_size: int = Field(
        default=100, description="Number of messages per processing batch."
    )
    tlp_level: TLPLevel = Field(
        default=TLPLevel.AMBER,
        description="TLP marking level applied to created STIX entities.",
    )


class ConnectorSettings(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include `ExternalImportConnectorConfig` and `SublimeConfig`.
    """

    connector: ExternalImportConnectorConfig = Field(
        default_factory=ExternalImportConnectorConfig
    )
    sublime: SublimeConfig = Field(default_factory=SublimeConfig)

import warnings
from datetime import timedelta

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
    ListFromString,
)
from pydantic import Field, HttpUrl, SecretStr, model_validator


class ExternalImportConnectorConfig(BaseExternalImportConnectorConfig):
    """
    Override the `BaseExternalImportConnectorConfig` to add parameters and/or defaults
    to the configuration for connectors of type `EXTERNAL_IMPORT`.
    """

    id: str = Field(
        description="The UUID of the connector.",
        default="8bbae241-6289-4faf-b7d6-7503bed50bbc",
    )
    name: str = Field(
        description="The name of the connector.",
        default="AlienVault",
    )
    duration_period: timedelta = Field(
        description="The period of time to await between two runs of the connector.",
        default=timedelta(minutes=30),
    )
    scope: ListFromString = Field(
        description="The scope of the connector.",
        default=["alienvault"],
    )


class AlienvaultConfig(BaseConfigModel):
    """
    Define parameters and/or defaults for the configuration specific to the `AlienvaultConnector`.
    """

    base_url: HttpUrl = Field(
        description="The base URL for the OTX DirectConnect API.",
        default="https://otx.alienvault.com",
    )
    api_key: SecretStr = Field(
        description="The OTX Key.",
    )
    tlp: str = Field(
        description="The default TLP marking used if the Pulse does not define TLP.",
        default="White",
    )
    create_observables: bool = Field(
        description="If true then observables will be created from Pulse indicators and added to the report.",
        default=True,
    )
    create_indicators: bool = Field(
        description="If true then indicators will be created from Pulse indicators and added to the report.",
        default=True,
    )
    pulse_start_timestamp: str = Field(
        description="The Pulses modified after this timestamp will be imported. Timestamp in ISO 8601 format, UTC.",
        default="2020-05-01T00:00:00",
    )
    report_type: str = Field(
        description="The type of imported reports in the OpenCTI.",
        default="threat-report",
    )
    report_status: str = Field(
        description="The status of imported reports in the OpenCTI.",
        default="New",
    )
    guess_malware: bool = Field(
        description="The Pulse tags are used to guess (queries malwares in the OpenCTI) malwares related to the given Pulse.",
        default=False,
    )
    guess_cve: bool = Field(
        description="The Pulse tags are used to guess (checks whether tag matches (CVE-\\d{4}-\\d{4,7})) vulnerabilities.",
        default=False,
    )
    excluded_pulse_indicator_types: ListFromString = Field(
        description="The Pulse indicator types that will be excluded from the import.",
        default=[],
    )
    enable_relationships: bool = Field(
        description="If true then the relationships will be created between SDOs.",
        default=True,
    )
    enable_attack_patterns_indicates: bool = Field(
        description="If true then the relationships `indicates` will be created between indicators and attack patterns.",
        default=True,
    )
    filter_indicators: bool = Field(
        description="This boolean filters out indicators created before the latest pulse datetime, ensuring only recent indicators are processed.",
        default=False,
    )
    default_x_opencti_score: int = Field(
        description="The default x_opencti_score to use for indicators. If a per indicator type score is not set, this is used.",
        default=50,
    )
    x_opencti_score_ip: int | None = Field(
        description="(Optional): The x_opencti_score to use for IP indicators.",
        default=None,
    )
    x_opencti_score_domain: int | None = Field(
        description="(Optional): The x_opencti_score to use for Domain indicators.",
        default=None,
    )
    x_opencti_score_hostname: int | None = Field(
        description="(Optional): The x_opencti_score to use for Hostname indicators.",
        default=None,
    )
    x_opencti_score_email: int | None = Field(
        description="(Optional): The x_opencti_score to use for Email indicators.",
        default=None,
    )
    x_opencti_score_file: int | None = Field(
        description="(Optional): The x_opencti_score to use for StixFile indicators.",
        default=None,
    )
    x_opencti_score_url: int | None = Field(
        description="(Optional): The x_opencti_score to use for URL indicators.",
        default=None,
    )
    x_opencti_score_mutex: int | None = Field(
        description="(Optional): The x_opencti_score to use for Mutex indicators.",
        default=None,
    )
    x_opencti_score_cryptocurrency_wallet: int | None = Field(
        description="(Optional): The x_opencti_score to use for Cryptocurrency Wallet indicators.",
        default=None,
    )
    interval_sec: int = Field(
        description="The interval in seconds between each run of the connector.",
        default=1800,
        deprecated="Use 'CONNECTOR_DURATION_PERIOD' in the 'connector' section instead.",
    )

    @model_validator(mode="after")
    def apply_default_scores(self) -> "AlienvaultConfig":
        """
        Apply the default x_opencti_score to per indicator type scores if they are not set.
        """
        updates: dict[str, int] = {}
        for field_name in __class__.model_fields:
            if (
                field_name.startswith("x_opencti_score_")
                and getattr(self, field_name) is None
            ):
                updates[field_name] = self.default_x_opencti_score
        if not updates:
            return self
        return self.model_copy(update=updates)


class ConnectorSettings(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include `ExternalImportConnectorConfig` and `AlienvaultConfig`.
    """

    connector: ExternalImportConnectorConfig = Field(
        default_factory=ExternalImportConnectorConfig
    )
    alienvault: AlienvaultConfig = Field(default_factory=AlienvaultConfig)

    @model_validator(mode="before")
    @classmethod
    def migrate_deprecated_interval(cls, data: dict) -> dict:
        """
        Env var `ALIENVAULT_INTERVAL_SEC` is deprecated.
        This is a workaround to keep the old config working while we migrate to `CONNECTOR_DURATION_PERIOD`.
        """
        connector_data: dict = data.get("connector", {})
        alienvault_data: dict = data.get("alienvault", {})
        if interval := alienvault_data.pop("interval_sec", None):
            if connector_data.get("duration_period") is not None:
                warnings.warn(
                    "Both 'ALIENVAULT_INTERVAL_SEC' and 'CONNECTOR_DURATION_PERIOD' are set. "
                    "'CONNECTOR_DURATION_PERIOD' will take precedence."
                )
            else:
                warnings.warn(
                    "Env var 'ALIENVAULT_INTERVAL_SEC' is deprecated. Use 'CONNECTOR_DURATION_PERIOD' instead."
                )
                connector_data["duration_period"] = timedelta(seconds=int(interval))

        return data

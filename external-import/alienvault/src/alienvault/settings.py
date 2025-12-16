from datetime import timedelta

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
)
from pydantic import Field, SecretStr


class ExternalImportConnectorConfig(BaseExternalImportConnectorConfig):
    """
    Override the `BaseExternalImportConnectorConfig` to add parameters and/or defaults
    to the configuration for connectors of type `EXTERNAL_IMPORT`.
    """

    name: str = Field(
        description="The name of the connector.",
        default="Alienvault",
    )
    duration_period: timedelta = Field(
        description="The period of time to await between two runs of the connector.",
        default=timedelta(hours=1),
    )


class AlienvaultConfig(BaseConfigModel):
    """
    Define parameters and/or defaults for the configuration specific to the `AlienvaultConnector`.
    """

    base_url: str = Field(
        description="The base URL for the OTX DirectConnect API.",
        default="https://otx.alienvault.com",
    )
    api_key: SecretStr = Field(
        description="The OTX Key.",
        default=SecretStr("ChangeMe"),
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
        description="The Pulse tags are used to guess (checks whether tag matches (CVE-\d{4}-\d{4,7})) vulnerabilities.",
        default=False,
    )
    excluded_pulse_indicator_types: str = Field(
        description="The Pulse indicator types that will be excluded from the import.",
        default="FileHash-MD5,FileHash-SHA1",
    )
    enable_relationships: bool = Field(
        description="If true then the relationships will be created between SDOs.",
        default=True,
    )
    enable_attack_patterns_indicates: bool = Field(
        description="If true then the relationships `indicates` will be created between indicators and attack patterns.",
        default=False,
    )
    filter_indicators: bool = Field(
        description="This boolean filters out indicators created before the latest pulse datetime, ensuring only recent indicators are processed.",
        default=False,
    )
    default_x_opencti_score: int = Field(
        description="The default x_opencti_score to use for indicators. If a per indicator type score is not set, this is used.",
        default=50,
    )
    x_opencti_score_ip: int = Field(
        description="(Optional): The x_opencti_score to use for IP indicators.",
        default=60,
    )
    x_opencti_score_domain: int = Field(
        description="(Optional): The x_opencti_score to use for Domain indicators.",
        default=70,
    )
    x_opencti_score_hostname: int = Field(
        description="(Optional): The x_opencti_score to use for Hostname indicators.",
        default=75,
    )
    x_opencti_score_email: int = Field(
        description="(Optional): The x_opencti_score to use for Email indicators.",
        default=70,
    )
    x_opencti_score_file: int = Field(
        description="(Optional): The x_opencti_score to use for StixFile indicators.",
        default=80,
    )
    x_opencti_score_url: int = Field(
        description="(Optional): The x_opencti_score to use for URL indicators.",
        default=80,
    )
    x_opencti_score_mutex: int = Field(
        description="(Optional): The x_opencti_score to use for Mutex indicators.",
        default=60,
    )
    x_opencti_score_cryptocurrency_wallet: int = Field(
        description="(Optional): The x_opencti_score to use for Cryptocurrency Wallet indicators.",
        default=80,
    )
    interval_sec: str = Field(
        description="The interval in seconds between each run of the connector.",
        default="1800",
    )


class ConnectorSettings(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include `ExternalImportConnectorConfig` and `AlienvaultConfig`.
    """

    connector: ExternalImportConnectorConfig = Field(
        default_factory=ExternalImportConnectorConfig
    )
    alienvault: AlienvaultConfig = Field(default_factory=AlienvaultConfig)

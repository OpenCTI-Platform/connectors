"""OpenCTI Kaspersky connector settings module."""

from datetime import timedelta

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
    DeprecatedField,
    ListFromString,
)
from pydantic import Field, SecretStr


class KasperskyConnectorConfig(BaseExternalImportConnectorConfig):
    """Defaults of the `connector` section for the Kaspersky connector."""

    id: str = Field(
        description="A UUID v4 to identify the connector in OpenCTI.",
        default="ec1217f4-241e-45a9-9ee9-b59e826c967f",
    )
    name: str = Field(
        description="The name of the connector.",
        default="Kaspersky",
    )
    scope: ListFromString = Field(
        description="The scope of the connector.",
        default=["kaspersky"],
    )
    duration_period: timedelta = Field(
        description="The period of time to await between two runs of the connector.",
        default=timedelta(hours=12),
    )


class KasperskyConfig(BaseConfigModel):
    """Settings specific to the Kaspersky connector."""

    base_url: str = Field(
        description="Kaspersky Threat Intelligence Portal API base URL.",
        default="https://tip.kaspersky.com",
    )
    user: str = Field(
        description="Kaspersky Threat Intelligence Portal username.",
    )
    password: SecretStr = Field(
        description="Kaspersky Threat Intelligence Portal password.",
    )
    certificate_path: str | None = Field(
        description=(
            "Path to the client certificate file (PEM, certificate and private key) "
            "provided by Kaspersky. When not set, no client certificate is sent."
        ),
        default=None,
    )
    tlp: str = Field(
        description="TLP marking of the imported objects (White, Green, Amber, Red).",
        default="Amber",
    )
    create_observables: bool = Field(
        description="Whether to create observables from the IoCs.",
        default=True,
    )
    create_indicators: bool = Field(
        description="Whether to create indicators from the IoCs.",
        default=True,
    )
    scopes: ListFromString = Field(
        description=(
            "Comma-separated list of data to import: "
            "'publication', 'master_ioc', 'master_yara'."
        ),
        default=["publication", "master_ioc", "master_yara"],
    )
    publication_start_timestamp: int = Field(
        description=(
            "Import publications updated after this Unix timestamp. "
            "The default value 0 imports the whole history, which is not recommended."
        ),
        default=0,
    )
    publication_report_type: str = Field(
        description="OpenCTI report type of the publications.",
        default="threat-report",
    )
    publication_report_status: str = Field(
        description=(
            "OpenCTI report status of the publications "
            "(New, In progress, Analyzed, Closed)."
        ),
        default="New",
    )
    publication_report_ignore_prefixes: ListFromString = Field(
        description=(
            "Comma-separated list of name prefixes of the publications to ignore, "
            "for example 'Monthly APT activity report'."
        ),
        default=[],
    )
    publication_excluded_ioc_indicator_types: ListFromString = Field(
        description=(
            "Comma-separated list of OpenIOC search values to exclude from the "
            "publications, for example 'Md5sum, FileItem/Sha1sum'."
        ),
        default=[],
    )
    master_ioc_fetch_weekday: int | None = Field(
        description=(
            "ISO weekday (1 is Monday) on which the Master IOC is fetched. "
            "When not set, the Master IOC is fetched on every run."
        ),
        default=None,
    )
    master_ioc_excluded_ioc_indicator_types: ListFromString = Field(
        description=(
            "Comma-separated list of OpenIOC indicator types to exclude from the "
            "Master IOC, for example 'md5Hash, sha1Hash'."
        ),
        default=[],
    )
    master_ioc_report_type: str = Field(
        description="OpenCTI report type of the Master IOC reports.",
        default="threat-report",
    )
    master_ioc_report_status: str = Field(
        description=(
            "OpenCTI report status of the Master IOC reports "
            "(New, In progress, Analyzed, Closed)."
        ),
        default="New",
    )
    master_yara_fetch_weekday: int | None = Field(
        description=(
            "ISO weekday (1 is Monday) on which the Master YARA is fetched. "
            "When not set, the Master YARA is fetched on every run."
        ),
        default=None,
    )
    master_yara_include_report: bool = Field(
        description="Whether to create a report for each group of Master YARA rules.",
        default=True,
    )
    master_yara_report_type: str = Field(
        description="OpenCTI report type of the Master YARA reports.",
        default="threat-report",
    )
    master_yara_report_status: str = Field(
        description=(
            "OpenCTI report status of the Master YARA reports "
            "(New, In progress, Analyzed, Closed)."
        ),
        default="New",
    )
    interval_sec: int | None = DeprecatedField(
        deprecated="Use 'CONNECTOR_DURATION_PERIOD' in the 'connector' section instead.",
        new_namespace="connector",
        new_namespaced_var="duration_period",
        new_value_factory=lambda seconds: timedelta(seconds=int(seconds)),
    )


class ConnectorSettings(BaseConnectorSettings):
    """Settings of the Kaspersky connector."""

    connector: KasperskyConnectorConfig = Field(
        default_factory=KasperskyConnectorConfig
    )
    kaspersky: KasperskyConfig = Field(default_factory=KasperskyConfig)

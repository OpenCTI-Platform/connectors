from datetime import timedelta
from typing import Optional

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
    DatetimeFromIsoString,
    DeprecatedField,
    ListFromString,
)
from pydantic import Field


class ExternalImportConnectorConfig(BaseExternalImportConnectorConfig):
    """
    Override `BaseExternalImportConnectorConfig` to add parameters and/or defaults
    to the configuration for connectors of type `EXTERNAL_IMPORT`.
    """

    id: str = Field(
        description="A UUID v4 to identify the connector in OpenCTI.",
        default="ChangeMe",
    )
    name: str = Field(
        description="The name of the connector.",
        default="TheHive",
    )
    scope: ListFromString = Field(
        description="The scope of the connector.",
        default=["thehive"],
    )
    duration_period: timedelta = Field(
        description="The period of time to await between two runs of the connector.",
        default=timedelta(minutes=5),
    )


class TheHiveConfig(BaseConfigModel):
    """
    Define parameters and/or defaults for the configuration specific to the TheHive connector.
    """

    url: str = Field(
        description="The URL of the TheHive instance.",
    )
    api_key: str = Field(
        description="The API key to authenticate to TheHive.",
    )
    check_ssl: bool = Field(
        description="Whether to verify SSL certificates when connecting to TheHive.",
        default=True,
    )
    organization_name: str = Field(
        description="The name of the organization in TheHive, used to create the identity in OpenCTI.",
    )
    import_from_date: DatetimeFromIsoString | None = Field(
        description="The date from which to start importing data (ISO format, e.g. 2021-01-01T00:00:00). Defaults to current time.",
        default=None,
    )
    import_only_tlp: ListFromString = Field(
        description="Comma-separated list of TLP levels to import (0=WHITE, 1=GREEN, 2=AMBER, 3=RED, 4=AMBER+STRICT).",
        default=["0", "1", "2", "3", "4"],
    )
    import_alerts: bool = Field(
        description="Whether to import alerts from TheHive.",
        default=True,
    )
    import_attachments: bool = Field(
        description="Whether to import attachments from TheHive cases.",
        default=False,
    )
    severity_mapping: ListFromString = Field(
        description="Comma-separated mapping of TheHive severity levels to OpenCTI severity labels (e.g. 1:low,2:medium,3:high,4:critical).",
        default=["1:01 - low", "2:02 - medium", "3:03 - high", "4:04 - critical"],
    )
    case_status_mapping: ListFromString = Field(
        description="Comma-separated mapping of TheHive case extended status to OpenCTI workflow status IDs (e.g. Resolved:status-id-1).",
        default=[],
    )
    case_tag_whitelist: ListFromString = Field(
        description="Comma-separated list of tags to whitelist for case import. If set, only cases with these tags are imported.",
        default=[],
    )
    task_status_mapping: ListFromString = Field(
        description="Comma-separated mapping of TheHive task status to OpenCTI workflow status IDs (e.g. Waiting:status-id-1,InProgress:status-id-2).",
        default=[],
    )
    alert_status_mapping: ListFromString = Field(
        description="Comma-separated mapping of TheHive alert extended status to OpenCTI workflow status IDs.",
        default=[],
    )
    user_mapping: ListFromString = Field(
        description="Comma-separated mapping of TheHive assignee emails to OpenCTI user IDs (e.g. user@example.com:user-id-1).",
        default=[],
    )
    interval: Optional[int] = DeprecatedField(
        default=None,
        deprecated="Use 'CONNECTOR_DURATION_PERIOD' in the 'connector' section instead.",
        new_namespace="connector",
        new_namespaced_var="duration_period",
        new_value_factory=lambda x: timedelta(minutes=int(x)),
    )


class ConnectorSettings(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include `ExternalImportConnectorConfig` and `TheHiveConfig`.
    """

    connector: ExternalImportConnectorConfig = Field(
        default_factory=ExternalImportConnectorConfig
    )
    thehive: TheHiveConfig = Field(default_factory=TheHiveConfig)

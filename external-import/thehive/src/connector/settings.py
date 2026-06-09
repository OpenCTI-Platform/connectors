from datetime import timedelta
from typing import Optional

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
    ListFromString,
)
from pydantic import Field, HttpUrl


class _TheHiveConnectorConfig(BaseExternalImportConnectorConfig):
    """
    Connector-level configuration (the ``connector`` section) for the TheHive connector.

    Overrides ``BaseExternalImportConnectorConfig`` to provide a sensible name default
    and a default ``duration_period`` so existing deployments — which schedule via
    ``THEHIVE_INTERVAL`` — keep loading without setting ``CONNECTOR_DURATION_PERIOD``.
    """

    name: str = Field(
        description="The name of the connector.",
        default="TheHive",
    )
    duration_period: timedelta = Field(
        description=(
            "Period of time to await between two runs of the connector (ISO-8601). "
            "Currently informational: scheduling still uses 'thehive.interval' (minutes); "
            "this becomes the scheduling source in a future version."
        ),
        default=timedelta(minutes=5),
    )


class _TheHiveConfig(BaseConfigModel):
    """Configuration specific to the TheHive integration (the ``thehive`` section)."""

    url: HttpUrl = Field(
        description="Base URL of the TheHive instance.",
        examples=["https://thehive.changeme.com"],
    )
    api_key: str = Field(
        description="API key used to authenticate against TheHive.",
    )
    organization_name: str = Field(
        description="Name of the organization used as the author of imported data in OpenCTI.",
        examples=["MyCompany"],
    )
    check_ssl: bool = Field(
        description="Whether to verify TheHive's TLS certificate.",
        default=True,
    )
    import_from_date: Optional[str] = Field(
        description=(
            "Earliest creation/update date to import from, as an ISO-8601 datetime "
            "(e.g. '2021-01-01T00:00:00'). Defaults to the connector's first start time."
        ),
        default=None,
        examples=["2021-01-01T00:00:00"],
    )
    import_only_tlp: ListFromString = Field(
        description="Comma-separated TheHive TLP levels (0-4) to import.",
        default=["0", "1", "2", "3", "4"],
        examples=["0,1,2,3,4"],
    )
    import_alerts: bool = Field(
        description="Whether to import TheHive alerts in addition to cases.",
        default=True,
    )
    import_attachments: bool = Field(
        description="Whether to import case attachments as STIX artifacts.",
        default=False,
    )
    severity_mapping: ListFromString = Field(
        description=(
            "Comma-separated mapping of TheHive severity (1-4) to an OpenCTI severity "
            "label, as 'level:label' pairs."
        ),
        default=["1:01 - low", "2:02 - medium", "3:03 - high", "4:04 - critical"],
        examples=["1:01 - low,2:02 - medium,3:03 - high,4:04 - critical"],
    )
    case_status_mapping: ListFromString = Field(
        description=(
            "Comma-separated mapping of TheHive case extendedStatus to an OpenCTI "
            "workflow status id, as 'thehive_status:opencti_status_id' pairs."
        ),
        default=[],
    )
    task_status_mapping: ListFromString = Field(
        description=(
            "Comma-separated mapping of TheHive task status to an OpenCTI workflow "
            "status id, as 'thehive_status:opencti_status_id' pairs."
        ),
        default=[],
    )
    alert_status_mapping: ListFromString = Field(
        description=(
            "Comma-separated mapping of TheHive alert status to an OpenCTI workflow "
            "status id, as 'thehive_status:opencti_status_id' pairs."
        ),
        default=[],
    )
    user_mapping: ListFromString = Field(
        description=(
            "Comma-separated mapping of TheHive assignee email to an OpenCTI user id, "
            "as 'email:opencti_user_id' pairs."
        ),
        default=[],
    )
    case_tag_whitelist: ListFromString = Field(
        description=(
            "Comma-separated list of case tags; if set, only cases bearing one of these "
            "tags are imported."
        ),
        default=[],
    )
    interval: int = Field(
        description="Number of minutes to wait between two runs of the connector.",
        default=5,
        ge=1,
    )


class ConnectorSettings(BaseConnectorSettings):
    """Top-level settings for the TheHive external import connector."""

    connector: _TheHiveConnectorConfig = Field(
        default_factory=_TheHiveConnectorConfig,
    )
    thehive: _TheHiveConfig = Field(default_factory=_TheHiveConfig)

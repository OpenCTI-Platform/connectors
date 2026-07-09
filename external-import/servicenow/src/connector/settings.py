from datetime import datetime, timedelta, timezone
from typing import Annotated, Literal, Optional

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
    DatetimeFromIsoString,
    ListFromString,
)
from pydantic import (
    Field,
    PlainSerializer,
    PositiveInt,
    SecretStr,
    field_validator,
)

TimedeltaInSeconds = Annotated[
    timedelta, PlainSerializer(lambda v: int(v.total_seconds()), return_type=int)
]
TLPToLower = Annotated[
    Literal["clear", "green", "amber", "amber+strict", "red"],
    PlainSerializer(lambda v: "".join(v), return_type=str),
]


class _ConnectorConfig(BaseExternalImportConnectorConfig):
    """Interface for loading Connector dedicated configuration.

    Overrides `BaseExternalImportConnectorConfig` to add ServiceNow defaults and the
    additional pycti helper parameters historically supported by this connector.
    """

    name: str = Field(
        default="ServiceNow",
        description="Name of the connector.",
    )
    id: str = Field(
        description="A UUID v4 to identify the connector in OpenCTI.",
        default="82c0a7e8-5b44-49dd-819b-855737fce95d",
    )
    scope: ListFromString = Field(
        default=["ServiceNow"],
        description="The scope or type of data the connector is importing, either a MIME type or Stix Object (for information only).",
    )
    duration_period: timedelta = Field(
        default=timedelta(hours=24),
        description="Duration between two scheduled runs of the connector (ISO 8601 format).",
    )
    queue_threshold: Optional[PositiveInt] = Field(
        default=None,
        description="Connector queue max size in Mbytes. Default to 500.",
    )
    run_and_terminate: Optional[bool] = Field(
        default=None,
        description="Connector run-and-terminate flag.",
    )
    send_to_queue: Optional[bool] = Field(
        default=None,
        description="Connector send-to-queue flag.",
    )
    send_to_directory: Optional[bool] = Field(
        default=None,
        description="Connector send-to-directory flag.",
    )
    send_to_directory_path: Optional[str] = Field(
        default=None,
        description="Connector send-to-directory path.",
    )
    send_to_directory_retention: Optional[PositiveInt] = Field(
        default=None,
        description="Connector send-to-directory retention in days.",
    )


class _ServiceNowConfig(BaseConfigModel):
    """Interface for loading ServiceNow dedicated configuration."""

    instance_name: str = Field(
        description="Corresponds to server instance name (will be used for API requests).",
    )
    api_key: SecretStr = Field(
        description="Secure identifier used to validate access to ServiceNow APIs.",
    )
    api_version: Optional[Literal["v1", "v2"]] = Field(
        default="v2",
        description="ServiceNow API version used for REST requests.",
    )
    api_leaky_bucket_rate: Optional[PositiveInt] = Field(
        default=10,
        description="Bucket refill rate (in tokens per second). Controls the rate at which API calls are allowed. "
        "For example, a rate of 10 means that 10 calls can be made per second, if the bucket is not empty.",
    )
    api_leaky_bucket_capacity: Optional[PositiveInt] = Field(
        default=10,
        description="Maximum bucket capacity (in tokens). Defines the number of calls that can be made immediately in a "
        "burst. Once the bucket is empty, it refills at the rate defined by 'api_leaky_bucket_rate'.",
    )
    api_retry: Optional[PositiveInt] = Field(
        default=5,
        description="Maximum number of retry attempts in case of API failure.",
    )
    api_backoff: timedelta = Field(
        default=timedelta(seconds=30),
        description="Exponential backoff duration between API retries (ISO 8601 duration format).",
    )
    import_start_date: DatetimeFromIsoString = Field(
        description="Start date of first import (ISO date format) - Default to 30 days ago.",
        default_factory=lambda: datetime.now(tz=timezone.utc) - timedelta(days=30),
    )
    state_to_exclude: Optional[list[str]] = Field(
        default=None,
        description="List of security incident states to exclude from import.",
    )
    severity_to_exclude: Optional[list[str]] = Field(
        default=None,
        description="List of security incident severities to exclude from import.",
    )
    priority_to_exclude: Optional[list[str]] = Field(
        default=None,
        description="List of security incident priorities to exclude from import.",
    )
    comment_to_exclude: Optional[list[Literal["private", "public", "auto"]]] = Field(
        default=None,
        description="List of comment types to exclude: private, public, auto",
    )
    tlp_level: Optional[TLPToLower] = Field(
        default="red",
        description="Traffic Light Protocol (TLP) level to apply on objects imported into OpenCTI.",
    )
    observables_default_score: Optional[PositiveInt] = Field(
        default=50,
        description="Allows you to define a default score for observables and indicators when the "
        "'promote_observables_as_indicators' variable is set to True.",
    )
    promote_observables_as_indicators: Optional[bool] = Field(
        default=True,
        description="Boolean to promote observables into indicators.",
    )
    sysparm_display_value: Optional[bool] = Field(
        default=True,
        description=(
            "Boolean controlling the ``sysparm_display_value`` query parameter "
            "sent to ServiceNow on every Table API call. Defaults to ``true`` "
            "(backwards-compatible — ServiceNow returns human-readable "
            "display strings). Set to ``false`` on instances that return "
            "non-ISO 8601 datetimes when ``sysparm_display_value=true`` is "
            "in effect, which the connector cannot parse."
        ),
    )

    @field_validator(
        "state_to_exclude",
        "severity_to_exclude",
        "priority_to_exclude",
        "comment_to_exclude",
        mode="before",
    )
    def parse_list(cls, value):
        if isinstance(value, str):
            return [x.strip().lower() for x in value.split(",") if x.strip()]
        return value


class ConnectorSettings(BaseConnectorSettings):
    """Interface for loading global configuration settings.

    Routes configuration through the connectors-sdk `BaseConnectorSettings`, which
    exposes `to_helper_config()` used to build the `OpenCTIConnectorHelper`
    (manager-supported mode).
    """

    connector: _ConnectorConfig = Field(default_factory=_ConnectorConfig)
    servicenow: _ServiceNowConfig = Field(default_factory=_ServiceNowConfig)

from datetime import datetime, timedelta, timezone

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
    DatetimeFromIsoString,
    DeprecatedField,
    ListFromString,
)
from pydantic import Field, SecretStr
from time_.interval import delta_from_interval


class ZeroFoxConnectorConfig(BaseExternalImportConnectorConfig):
    """Connector section configuration.

    Mirrors the existing ``CONNECTOR_*`` variables consumed by the ZeroFox connector.
    """

    name: str = Field(
        description="The name of the connector.",
        default="ZeroFox",
    )
    id: str = Field(
        description="A UUID v4 to identify the connector in OpenCTI.",
        default="77d4fd99-5789-43d8-babc-c8bf9130c8cf",
    )
    scope: ListFromString = Field(
        description="The scope of the connector.",
        default=["zerofox"],
    )
    duration_period: timedelta = Field(
        description="The period of time to await between two runs of the connector.",
        default=timedelta(days=1),
    )
    run_every: str | None = DeprecatedField(
        default=None,
        deprecated="Use 'CONNECTOR_DURATION_PERIOD' instead.",
        new_namespaced_var="duration_period",
        new_value_factory=delta_from_interval,
    )
    first_run: str | None = DeprecatedField(
        default=None,
        deprecated="Use 'ZEROFOX_FIRST_RUN' instead.",
        new_namespace="zerofox",
        new_namespaced_var="first_run",
        new_value_factory=lambda x: datetime.now(timezone.utc) - delta_from_interval(x),
    )
    update_existing_data: bool = Field(
        description="Whether to update data already ingested into the platform.",
        default=False,
    )


class ZeroFoxConfig(BaseConfigModel):
    """Configuration specific to the ZeroFox connector.

    Mirrors the existing ``ZEROFOX_*`` variables.
    """

    username: str = Field(
        description="The username used to authenticate against the ZeroFox API.",
    )
    password: SecretStr = Field(
        description="The password used to authenticate against the ZeroFox API.",
    )
    first_run: DatetimeFromIsoString = Field(
        description=(
            "Start date to look back on the connector's very first run (ISO 8601 "
            "format, absolute date or duration, e.g. '2023-10-01' or 'P1D')."
        ),
        # `default_factory` is used to set a dynamic default value (datetime) at runtime
        default_factory=lambda: datetime.now(timezone.utc) - timedelta(days=1),
        # but a fixed default value (ISO string) must be used in the schema for documentation purposes
        json_schema_extra={"default": "P1D"},
    )
    collectors: ListFromString = Field(
        description=(
            "Comma-separated list of ZeroFox CTI feeds to collect. When unset, "
            "all available feeds are collected."
            "Available values are:  'c2-domains', 'exploits', 'malware', 'phishing', "
            "'scanned_after', 'ransomware', 'vulnerabilities', 'botnet'. "
        ),
        default=[
            "c2-domains",
            "exploits",
            "malware",
            "phishing",
            "scanned_after",
            "ransomware",
            "vulnerabilities",
            "botnet",
        ],  # all feeds
    )


class ConnectorSettings(BaseConnectorSettings):
    """Global settings for the ZeroFox connector."""

    connector: ZeroFoxConnectorConfig = Field(
        default_factory=ZeroFoxConnectorConfig,
    )
    zerofox: ZeroFoxConfig = Field(default_factory=ZeroFoxConfig)

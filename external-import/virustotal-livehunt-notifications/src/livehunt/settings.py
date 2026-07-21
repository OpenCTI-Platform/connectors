from datetime import timedelta
from typing import Literal

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
    DeprecatedField,
    ListFromString,
)
from pydantic import Field, SecretStr


class ExternalImportConnectorConfig(BaseExternalImportConnectorConfig):
    """
    Override the `BaseExternalImportConnectorConfig` to add parameters and/or defaults
    to the configuration for connectors of type `EXTERNAL_IMPORT`.
    """

    id: str = Field(
        description="The ID of the connector.",
        default="325cbb22-ee42-4898-9d99-302ca216671b",
    )
    name: str = Field(
        description="The name of the connector.",
        default="VirusTotal Livehunt Notifications",
    )
    scope: ListFromString = Field(
        description="The scope of the connector.",
        default=[
            "StixFile",
            "Indicator",
            "Incident",
            "Domain-Name",
            "Url",
            "IPv4-Addr",
            "IPv6-Addr",
        ],
    )
    duration_period: timedelta = Field(
        description="The period of time to await between two runs of the connector.",
        default=timedelta(minutes=5),
    )


class VirusTotalLiveHuntNotificationsConfig(BaseConfigModel):
    """
    Define parameters and/or defaults for the configuration specific to the `VirusTotalLiveHuntNotificationsConfig`.
    """

    api_key: SecretStr = Field(
        description="VirusTotal Premium API key.",
    )
    tlp_level: Literal[
        "clear",
        "white",
        "green",
        "amber",
        "amber+strict",
        "red",
    ] = Field(
        description="Default TLP level of the imported entities.",
        default="clear",
    )
    create_alert: bool = Field(
        description="Create incident/alert for each notification.",
        default=True,
    )
    alert_prefix: str = Field(
        description="Prefix that is added in alerts titles.",
        default="VT ",
    )
    delete_notification: bool = Field(
        description="Delete notification from VT after processing.",
        default=False,
    )
    filter_with_tag: str | None = Field(
        description="Only process notifications with this tag.",
        default=None,
    )
    create_file: bool = Field(
        description="Create file observable for matched files.",
        default=True,
    )
    extensions: ListFromString = Field(
        description="Comma-separated file extensions to filter (e.g., `exe,dll`).",
        default=[],
    )
    max_age_days: int = Field(
        description="Only process files submitted within this many days.",
        default=3,
    )
    min_file_size: int = Field(
        description="Minimum file size in bytes to download.",
        default=1_000,
    )
    max_file_size: int = Field(
        description="Maximum file size in bytes to download(default: 50MB).",
        default=52_428_800,
    )
    min_positives: int = Field(
        description="Minimum number of vendors marking file to download as 'malicious'.",
        default=1,
    )
    upload_artifact: bool = Field(
        description="Upload file to OpenCTI as artifact.",
        default=False,
    )
    create_yara_rule: bool = Field(
        description="Create YARA indicator for the matching rule.",
        default=True,
    )
    av_list: ListFromString = Field(
        description="Comma-separated list of AVs to add in description, (e.g., `Kaspersky,Symantec`).",
        default=[],
    )
    livehunt_tag_prefix: str = Field(
        description="Prefix used to state that the tag is imported from Livehunt",
        default="",
    )
    yara_label_prefix: str = Field(
        description="Prefix that is added in yara labels.",
        default="vt:yara:",
    )
    livehunt_label_prefix: str = Field(
        description="Prefix that is added in livehunt labels.",
        default="vt:lh:",
    )
    enable_label_enrichment: bool = Field(
        description="Add livehunt name and matched yara rules label to the alert",
        default=True,
    )
    get_malware_config: bool = Field(
        description=(
            "Extract C2 infrastructure (domains, IPs, URLs) from VirusTotal's "
            "malware configuration analysis and add the resulting observables "
            "to the bundle. Only effective when ``create_file`` is true."
        ),
        default=False,
    )
    create_file_indicators: bool = Field(
        description=(
            "Create a File indicator (SHA-256 pattern) for each matched "
            "file. Only effective when ``create_file`` is true — the "
            "File indicator is emitted alongside the File observable in "
            "``LivehuntBuilder.create_file``, so leaving ``create_file`` "
            "off means this flag has no effect."
        ),
        default=False,
    )
    create_domain_name_indicators: bool = Field(
        description=(
            "Create Domain-Name indicators for domains extracted from the "
            "malware configuration."
        ),
        default=False,
    )
    create_ip_indicators: bool = Field(
        description=(
            "Create IPv4/IPv6 indicators for IP addresses extracted from the "
            "malware configuration."
        ),
        default=False,
    )
    create_url_indicators: bool = Field(
        description=(
            "Create URL indicators for URLs extracted from the malware "
            "configuration."
        ),
        default=False,
    )
    limit: int | None = Field(
        description=(
            "Maximum number of notifications to process per run. Useful when "
            "the VirusTotal API quota is small. Leave unset to process every "
            "available notification."
        ),
        default=None,
        ge=1,
    )
    interval_sec: int | None = DeprecatedField(
        new_namespace="connector",
        new_namespaced_var="duration_period",
        new_value_factory=lambda v: timedelta(seconds=int(v)),
    )


class ConnectorSettings(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include `ExternalImportConnectorConfig` and `VirusTotalLiveHuntNotificationsConfig`.
    """

    connector: ExternalImportConnectorConfig = Field(
        default_factory=ExternalImportConnectorConfig
    )
    virustotal_livehunt_notifications: VirusTotalLiveHuntNotificationsConfig = Field(
        default_factory=VirusTotalLiveHuntNotificationsConfig
    )

import warnings
from datetime import timedelta
from typing import Literal

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
    ListFromString,
)
from pydantic import Field, SecretStr, model_validator


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
        default=["StixFile", "Indicator", "Incident"],
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

    @model_validator(mode="before")
    @classmethod
    def migrate_deprecated_interval(cls, data: dict) -> dict:
        """
        Env var `VIRUSTOTAL_LIVEHUNT_NOTIFICATIONS_INTERVAL_SEC` is deprecated.
        This is a workaround to keep the old config working while we migrate to `CONNECTOR_DURATION_PERIOD`.
        """
        connector_data: dict = data.get("connector", {})
        virustotal_livehunt_notifications_data: dict = data.get(
            "virustotal_livehunt_notifications", {}
        )
        if interval := virustotal_livehunt_notifications_data.pop("interval_sec", None):
            if connector_data.get("duration_period") is not None:
                warnings.warn(
                    "Both 'VIRUSTOTAL_LIVEHUNT_NOTIFICATIONS_INTERVAL_SEC' and 'CONNECTOR_DURATION_PERIOD' are set. "
                    "'CONNECTOR_DURATION_PERIOD' will take precedence."
                )
            else:
                warnings.warn(
                    "Env var 'VIRUSTOTAL_LIVEHUNT_NOTIFICATIONS_INTERVAL_SEC' is deprecated. "
                    "Use 'CONNECTOR_DURATION_PERIOD' instead."
                )
                connector_data["duration_period"] = timedelta(seconds=int(interval))

        return data

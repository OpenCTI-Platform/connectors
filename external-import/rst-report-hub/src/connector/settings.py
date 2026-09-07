from datetime import timedelta

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
    ListFromString,
)
from pydantic import Field, SecretStr


class ExternalImportConnectorConfig(BaseExternalImportConnectorConfig):
    """
    Override the `BaseExternalImportConnectorConfig` to add parameters and/or defaults
    to the configuration for connectors of type `EXTERNAL_IMPORT`.
    """

    id: str = Field(
        description="A UUID v4 to identify the connector in OpenCTI.",
        default="6811c83a-6a01-4c2d-8d7d-db7d0284a0ee",
    )
    name: str = Field(
        description="The name of the connector.",
        default="RstReportHub",
    )
    scope: ListFromString = Field(
        description="The scope of the connector.",
        default=[],
    )
    duration_period: timedelta = Field(
        description="The period of time to await between two runs of the connector.",
        default=timedelta(hours=1),
    )


class RstReportHubConfig(BaseConfigModel):
    """
    Define parameters and/or defaults for the configuration specific to the `RstReportHubConnector`.
    """

    base_url: str = Field(
        default="https://api.rstcloud.net/v1",
        description="RST Report Hub Base URL. By default, use https://api.rstcloud.net/v1. In some cases, you may want to use a local API endpoint.",
    )
    api_key: SecretStr = Field(
        description="Your API Key for accessing RST Cloud.",
    )
    connection_timeout: int = Field(
        default=30,
        description="Connection timeout to the API in seconds.",
    )
    read_timeout: int = Field(
        default=60,
        description="Read timeout for each feed in seconds.",
    )
    retry_delay: int = Field(
        default=30,
        description="How long to wait in seconds before next attempt to connect to the API.",
    )
    retry_attempts: int = Field(
        default=5,
        description="Download retry count (number of attempts).",
    )
    import_start_date: str = Field(
        default="",
        description='Date from which you want to retrieve the reports in the format "%Y%m%d" (for example, 20240527). By default, this start date is calculated as 7 days ago.',
    )
    fetch_interval: int = Field(
        default=300,
        description="Fetch interval in seconds.",
    )
    language: str = Field(
        default="eng",
        description="Language of the RST Report Hub content. Reach out to support@rstcloud.net if you want to update this parameter.",
    )
    create_observables: bool = Field(
        default=False,
        description="Whether observables are to be created in addition to indicators.",
    )
    create_related_to: bool = Field(
        default=True,
        description="Whether `related-to` relationships are to be created or not.",
    )
    create_custom_ttps: bool = Field(
        default=True,
        description="Whether `attack-pattern` objects with custom names (not present in MITRE ATT&CK) are to be created or not.",
    )
    report_labels_disabled: str = Field(
        default="",
        description="Comma-separated list of labels to ignore when creating Report objects. It does not prevent reports from being created.",
    )
    set_detection_flag: bool = Field(
        default=False,
        description="Whether indicators from reports should be set for detection or not.",
    )


class ConnectorSettings(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include `ExternalImportConnectorConfig` and `RstReportHubConfig`.
    """

    connector: ExternalImportConnectorConfig = Field(
        default_factory=ExternalImportConnectorConfig
    )
    rst_report_hub: RstReportHubConfig = Field(default_factory=RstReportHubConfig)

from datetime import timedelta

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
    ListFromString,
)
from pydantic import AliasChoices, Field, SecretStr


class ExternalImportConnectorConfig(BaseExternalImportConnectorConfig):
    """
    Override the `BaseExternalImportConnectorConfig` to add parameters and/or defaults
    to the configuration for connectors of type `EXTERNAL_IMPORT`.
    """

    id: str = Field(
        description="A UUID v4 to identify the connector in OpenCTI.",
        default="391fd869-a6f4-4b3f-812a-88a77c557ecd",
    )
    name: str = Field(
        description="The name of the connector.",
        default="TenableVulnManagement",
    )
    scope: ListFromString = Field(
        description="The scope of the connector.",
        default=[],
    )
    duration_period: timedelta = Field(
        description="The period of time to await between two runs of the connector.",
        default=timedelta(hours=1),
    )


class TenableVulnManagementConfig(BaseConfigModel):
    """
    Define parameters and/or defaults for the configuration specific to the `TenableVulnManagementConnector`.
    """

    api_base_url: str = Field(
        description="Base URL for the Tenable API.",
        default="https://cloud.tenable.com",
    )
    api_access_key: SecretStr = Field(
        description="Tenable API access key.",
    )
    api_secret_key: SecretStr = Field(
        description="Tenable API secret key.",
    )
    api_timeout: int = Field(
        description="Timeout for API requests in seconds.",
        default=30,
    )
    api_backoff: int = Field(
        description="Time (in seconds) to wait before retrying after receiving a 429 response from the API.",
        default=1,
    )
    api_retries: int = Field(
        description="Number of retries in case of failure.",
        default=5,
    )
    export_since: str = Field(
        description="Date from which to start pulling vulnerability data.",
        default="1970-01-01T00:00:00+00",
    )
    min_severity: str = Field(
        description="The minimum severity level of vulnerabilities to import (`low`, `medium`, `high`, `critical`).",
        default="low",
    )
    marking_definition: str = Field(
        description="Default marking definition for imported data (e.g., `TLP:AMBER`, `TLP:GREEN`, `TLP:CLEAR`).",
        default="TLP:CLEAR",
    )
    num_threads: int = Field(
        description="Number of threads to use for the connector.",
        default=1,
    )


class ConnectorSettings(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include `ExternalImportConnectorConfig` and `TenableVulnManagementConfig`.
    """

    connector: ExternalImportConnectorConfig = Field(
        default_factory=ExternalImportConnectorConfig
    )
    tio: TenableVulnManagementConfig = Field(
        default_factory=TenableVulnManagementConfig,
        alias=AliasChoices("tenable_vuln_management", "tio"),
    )

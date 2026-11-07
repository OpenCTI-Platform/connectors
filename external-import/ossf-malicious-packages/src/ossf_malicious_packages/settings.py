"""Settings module for the OSSF Malicious Packages connector."""

from datetime import timedelta

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
)
from pydantic import Field, HttpUrl


class ExternalImportConnectorConfig(BaseExternalImportConnectorConfig):
    """
    Override the `BaseExternalImportConnectorConfig` to add parameters and/or defaults
    to the configuration for the OSSF Malicious Packages connector.
    """

    name: str = Field(
        description="The name of the connector.",
        default="OSSF Malicious Packages",
    )
    duration_period: timedelta = Field(
        description="The period of time to await between two runs of the connector.",
        default=timedelta(hours=1),
    )


class OSSFConfig(BaseConfigModel):
    """
    Define parameters and/or defaults for the configuration specific to the
    OSSF Malicious Packages connector.
    """

    github_repo_url: HttpUrl = Field(
        description="URL of the OSSF malicious-packages GitHub repository to clone/pull.",
    )
    branch: str = Field(
        description="Git branch to track in the OSSF malicious-packages repository.",
        default="main",
    )
    local_repo_path: str = Field(
        description="Local filesystem path where the OSSF repository is cloned.",
        default="/opt/ossf-malicous-packages-repo",
    )
    default_score: int = Field(
        description="Default score assigned to created indicators (0-100).",
        default=80,
    )
    source_name: str = Field(
        description="Source name label applied to created entities.",
        default="ossf/malicious-packages",
    )


class ConnectorSettings(BaseConnectorSettings):
    """
    Override `BaseConnectorSettings` to include `ExternalImportConnectorConfig` and `OSSFConfig`.
    """

    connector: ExternalImportConnectorConfig = Field(
        default_factory=ExternalImportConnectorConfig
    )
    ossf: OSSFConfig = Field(default_factory=OSSFConfig)

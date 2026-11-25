"""OpenCTI cvelistV5 connector settings module."""

from datetime import timedelta
from typing import Literal

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
    ListFromString,
)
from pydantic import Field, field_validator


class CVEListV5ConnectorConfig(BaseExternalImportConnectorConfig):
    """Defaults of the `connector` section for the cvelistV5 connector."""

    id: str = Field(
        description="A UUID v4 to identify the connector in OpenCTI.",
        default="4459cb70-312b-449c-941e-30a6c04b7a14",
    )
    name: str = Field(
        description="The name of the connector.",
        default="CVEProject cvelistV5",
    )
    scope: ListFromString = Field(
        description="The scope of the connector.",
        default=["identity", "vulnerability", "software"],
    )
    log_level: Literal["debug", "info", "warn", "warning", "error"] = Field(
        description="The minimum level of logs to display.",
        default="info",
    )
    duration_period: timedelta = Field(
        description="The period of time to await between two runs of the connector, "
        "as an ISO 8601 duration (e.g. `PT1H` for one hour). Must be greater than zero: "
        "the connector runs continuously and is not meant to run once and exit.",
        default=timedelta(hours=1),
    )

    @field_validator("duration_period")
    @classmethod
    def _duration_period_must_be_positive(cls, value: timedelta) -> timedelta:
        if value <= timedelta(0):
            raise ValueError("duration_period must be greater than zero")
        return value


class CVEListV5Config(BaseConfigModel):
    """Settings specific to the cvelistV5 connector."""

    repo_url: str = Field(
        description="Upstream git repository. Override only if you mirror cvelistV5 internally.",
        default="https://github.com/CVEProject/cvelistV5.git",
    )
    repo_branch: str = Field(
        description="Branch of the upstream git repository to follow.",
        default="main",
    )
    local_path: str = Field(
        description="Local path where the clone is kept. Must be writable by the connector; "
        "mount a volume there to keep the clone across restarts.",
        default="/opt/cvelistV5",
    )
    history_start_year: int = Field(
        description="Oldest year of CVE records to import on the initial run "
        "(minimum 1999; a lower value falls back to the default).",
        default=2024,
    )


class ConnectorSettings(BaseConnectorSettings):
    """Settings of the cvelistV5 connector."""

    connector: CVEListV5ConnectorConfig = Field(
        default_factory=CVEListV5ConnectorConfig
    )
    cvelistv5: CVEListV5Config = Field(default_factory=CVEListV5Config)

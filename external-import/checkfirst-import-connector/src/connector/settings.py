from __future__ import annotations

from datetime import timedelta
from typing import Literal

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
)
from pydantic import Field


class ExternalImportConnectorConfig(BaseExternalImportConnectorConfig):
    """Common configuration for connectors of type `EXTERNAL_IMPORT`."""

    name: str = Field(
        description="The name of the connector.",
        default="Checkfirst Import Connector",
    )
    log_level: Literal["debug", "info", "warn", "warning", "error"] = Field(
        description="The minimum level of logs to display.",
        default="info",
    )
    duration_period: timedelta = Field(
        description="The period of time to await between two runs of the connector.",
        default=timedelta(hours=1),
    )


class CheckfirstConfig(BaseConfigModel):
    """Connector-specific configuration."""

    dataset_path: str = Field(
        description="Path to the dataset root (file or directory)."
    )
    batch_size: int = Field(
        description="Number of rows to include per sent STIX bundle.",
        default=1000,
    )
    run_mode: Literal["loop", "once"] = Field(
        description="Run mode: loop (scheduled) or once (one-shot).",
        default="loop",
    )

    force_reprocess: bool = Field(
        description=(
            "If true, ignore any saved connector state and start reading each file "
            "from the beginning. Useful for debugging or re-importing the same dataset."
        ),
        default=False,
    )

    tlp_level: Literal[
        "clear",
        "white",
        "green",
        "amber",
        "amber+strict",
        "red",
    ] = Field(
        description="TLP marking level applied to created STIX entities.",
        default="clear",
    )

    # Resource guards (optional)
    max_file_bytes: int | None = Field(
        description="Skip any dataset file larger than this number of bytes.",
        default=None,
    )
    max_row_bytes: int | None = Field(
        description="Skip any row larger than this approximate number of bytes.",
        default=None,
    )
    max_rows_per_file: int | None = Field(
        description="Stop reading a file after this number of rows.",
        default=None,
    )


class MQConfig(BaseConfigModel):
    """Message-queue configuration used by `pycti.OpenCTIConnectorHelper`."""

    host: str = Field(description="MQ host.")
    port: int = Field(description="MQ port.", default=5672)
    user: str = Field(description="MQ username.")
    password: str = Field(
        description="MQ password.",
        validation_alias="pass",
        serialization_alias="pass",
    )
    vhost: str = Field(description="MQ vhost.", default="/")
    use_ssl: bool = Field(description="Use SSL to connect to MQ.", default=False)


class ConnectorSettings(BaseConnectorSettings):
    """Settings model loaded from env vars / config.yml."""

    connector: ExternalImportConnectorConfig = Field(
        default_factory=ExternalImportConnectorConfig
    )
    checkfirst: CheckfirstConfig = Field(default_factory=CheckfirstConfig)
    mq: MQConfig = Field(default_factory=MQConfig)

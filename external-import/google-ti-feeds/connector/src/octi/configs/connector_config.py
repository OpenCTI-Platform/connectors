"""Connector-specific configuration definitions for OpenCTI external imports."""

from datetime import timedelta
from typing import ClassVar, Literal, Optional

from connector.src.octi.interfaces.base_config import BaseConfig
from pydantic import Field
from pydantic_settings import SettingsConfigDict


class ConnectorConfig(BaseConfig):
    """Configuration for the connector."""

    yaml_section: ClassVar[str] = "connector"
    model_config = SettingsConfigDict(env_prefix="connector_")

    id: str = Field(
        ...,
        description="Unique identifier for the connector instance",
        min_length=1,
    )
    type: Literal["EXTERNAL_IMPORT"] = Field(
        default="EXTERNAL_IMPORT",
        description="Type of connector - must be EXTERNAL_IMPORT for import connectors",
    )
    name: str = Field(
        default="Google Threat Intel Feeds",
        description="Display name for the connector",
        min_length=1,
    )
    scope: str = Field(
        default="report,location,identity,attack_pattern,domain,file,ipv4,ipv6,malware,sector,intrusion_set,url,vulnerability,campaign",
        description="Comma-separated list of OpenCTI entity types that this connector can import",
    )
    log_level: Literal["debug", "info", "warn", "warning", "error"] = Field(
        default="error",
        description="Logging level for the connector",
    )
    duration_period: timedelta = Field(
        default=timedelta(hours=2),
        description="ISO 8601 duration between connector runs (e.g., PT2H for 2 hours)",
    )
    queue_threshold: int = Field(
        default=500,
        description="Maximum number of messages in the connector queue before throttling",
        ge=1,
    )
    tlp_level: Literal[
        "WHITE",
        "GREEN",
        "AMBER",
        "RED",
        "WHITE+STRICT",
        "GREEN+STRICT",
        "AMBER+STRICT",
        "RED+STRICT",
    ] = Field(
        default="AMBER+STRICT",
        description="Traffic Light Protocol (TLP) marking for imported data",
    )
    run_and_terminate: Optional[bool] = Field(
        default=None,
        description="If True, connector runs once and exits; if False/None, runs continuously",
    )
    send_to_queue: Optional[bool] = Field(
        default=None,
        description="Whether to send imported data to the OpenCTI processing queue",
    )
    send_to_directory: Optional[bool] = Field(
        default=None,
        description="Whether to save imported data to a local directory",
    )
    send_to_directory_path: Optional[str] = Field(
        default=None,
        description="Local directory path for saving imported data (if send_to_directory is True)",
    )
    send_to_directory_retention: Optional[int] = Field(
        default=None,
        description="Number of days to retain files in the directory before cleanup",
        ge=1,
    )

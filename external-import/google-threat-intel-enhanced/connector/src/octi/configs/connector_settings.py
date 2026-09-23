"""Connectors-sdk based settings for the standard OpenCTI/connector framework fields."""

from datetime import timedelta
from typing import Literal, Optional

from connectors_sdk.settings.annotated_types import ListFromString
from connectors_sdk.settings.base_settings import (
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
)
from pydantic import Field


class _ConnectorFrameworkConfig(BaseExternalImportConnectorConfig):
    """The standard connectors-sdk external-import fields, extended with this
    connector's additional framework-level settings that are not part of the SDK base.
    """

    name: str = Field(
        default="Google Threat Intel Feeds",
        description="The name of the connector.",
    )
    scope: ListFromString = Field(
        default=[
            "report",
            "location",
            "identity",
            "attack_pattern",
            "domain",
            "file",
            "ipv4",
            "ipv6",
            "malware",
            "sector",
            "intrusion_set",
            "url",
            "vulnerability",
        ],
        description="The scope of the connector, e.g. 'indicator, vulnerability'.",
    )
    duration_period: timedelta = Field(
        default=timedelta(hours=2),
        description="The period of time to await between two runs of the connector.",
    )
    queue_threshold: int = Field(
        default=500,
        description="Maximum number of messages in the connector queue before throttling.",
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
        description="Traffic Light Protocol (TLP) marking for imported data.",
    )
    enrichment_resolution: str = Field(
        default="PT1M",
        description="ISO 8601 duration between enrichment scheduler checks.",
    )
    run_and_terminate: Optional[bool] = Field(default=None)
    send_to_queue: Optional[bool] = Field(default=None)
    send_to_directory: Optional[bool] = Field(default=None)
    send_to_directory_path: Optional[str] = Field(default=None)
    send_to_directory_retention: Optional[int] = Field(default=None)


class ConnectorSettings(BaseConnectorSettings):
    """Aggregates the standard OpenCTI/connector framework settings using connectors-sdk."""

    connector: _ConnectorFrameworkConfig = Field(
        default_factory=_ConnectorFrameworkConfig
    )

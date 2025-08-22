"""Connector-specific configuration definitions for OpenCTI external imports."""

from typing import ClassVar, Literal, Optional

from connector.src.octi.interfaces.base_config import BaseConfig
from pydantic_settings import SettingsConfigDict


class ConnectorConfig(BaseConfig):
    """Configuration for the connector."""

    yaml_section: ClassVar[str] = "connector"
    model_config = SettingsConfigDict(env_prefix="connector_")

    id: str
    type: Literal["EXTERNAL_IMPORT"] = "EXTERNAL_IMPORT"
    name: str = "Google Threat Intel Feeds"
    scope: str = (
        "report,location,identity,attack_pattern,domain,file,ipv4,ipv6,malware,sector,intrusion_set,url,vulnerability"
    )
    log_level: Literal["debug", "info", "warn", "error"] = "error"
    duration_period: str = "PT2H"
    queue_threshold: int = 500
    tlp_level: Literal[
        "WHITE",
        "GREEN",
        "AMBER",
        "RED",
        "WHITE+STRICT",
        "GREEN+STRICT",
        "AMBER+STRICT",
        "RED+STRICT",
    ] = "AMBER+STRICT"
    run_and_terminate: Optional[bool] = None
    send_to_queue: Optional[bool] = None
    send_to_directory: Optional[bool] = None
    send_to_directory_path: Optional[str] = None
    send_to_directory_retention: Optional[int] = None

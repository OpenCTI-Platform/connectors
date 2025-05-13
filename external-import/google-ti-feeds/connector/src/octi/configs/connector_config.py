"""Connector-specific configuration definitions for OpenCTI external imports."""

from typing import ClassVar, Literal, Optional
from uuid import uuid4

from connector.src.octi.interfaces.base_config import BaseConfig
from pydantic_settings import SettingsConfigDict


class ConnectorConfig(BaseConfig):
    """Configuration for the connector."""

    yaml_section: ClassVar[str] = "connector"
    model_config = SettingsConfigDict(env_prefix="connector_")

    id: str = f"{uuid4()}"
    type: Literal["EXTERNAL_IMPORT"] = "EXTERNAL_IMPORT"
    name: str = "Google Threat Intel Feeds"
    scope: str = "report,location,identity"
    log_level: Literal["debug", "info", "warn", "error"] = "info"
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
    split_work: bool = False
    run_and_terminate: Optional[bool] = None
    send_to_queue: Optional[bool] = None
    send_to_directory: Optional[bool] = None
    send_to_directory_path: Optional[str] = None
    send_to_directory_retention: Optional[int] = None

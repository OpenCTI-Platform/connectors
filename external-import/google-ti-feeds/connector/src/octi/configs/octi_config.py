"""Global OpenCTI connector configuration—common settings for all connectors."""

from connector.src.octi.interfaces.base_config import BaseConfig
from pydantic_settings import SettingsConfigDict


class OctiConfig(BaseConfig):
    """Configuration for the OpenCTI platform."""

    yaml_section = "opencti"

    model_config = SettingsConfigDict(env_prefix="opencti_")

    url: str
    token: str

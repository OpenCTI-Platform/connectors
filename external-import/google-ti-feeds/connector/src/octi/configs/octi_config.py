"""Global OpenCTI connector configuration—common settings for all connectors."""

from pydantic_settings import SettingsConfigDict

from connector.src.octi.interfaces.base_config import BaseConfig


class OctiConfig(BaseConfig):
    """Configuration for the OpenCTI platform."""

    yaml_section = "opencti"

    model_config = SettingsConfigDict(env_prefix="opencti_")

    url: str
    token: str

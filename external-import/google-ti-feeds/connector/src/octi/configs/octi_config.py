"""Global OpenCTI connector configuration—common settings for all connectors."""

from connector.src.octi.interfaces.base_config import BaseConfig
from pydantic import Field, HttpUrl
from pydantic_settings import SettingsConfigDict


class OctiConfig(BaseConfig):
    """Configuration for the OpenCTI platform."""

    yaml_section = "opencti"

    model_config = SettingsConfigDict(env_prefix="opencti_")

    url: HttpUrl = Field(
        ...,
        description="The URL of the OpenCTI platform instance",
        examples=["http://localhost:8080", "https://opencti.example.com"],
    )
    token: str = Field(
        ...,
        description="Authentication token for accessing the OpenCTI API",
        min_length=1,
    )

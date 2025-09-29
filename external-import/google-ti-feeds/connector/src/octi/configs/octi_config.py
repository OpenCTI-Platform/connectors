"""Global OpenCTI connector configuration—common settings for all connectors."""

from typing import Annotated

from connector.src.octi.interfaces.base_config import BaseConfig
from pydantic import Field, HttpUrl, PlainSerializer
from pydantic_settings import SettingsConfigDict

HttpUrlToString = Annotated[HttpUrl, PlainSerializer(str, return_type=str)]


class OctiConfig(BaseConfig):
    """Configuration for the OpenCTI platform."""

    yaml_section = "opencti"

    model_config = SettingsConfigDict(env_prefix="opencti_")

    url: HttpUrlToString = Field(
        ...,
        description="The URL of the OpenCTI platform instance",
        examples=["http://localhost:8080", "https://opencti.example.com"],
    )
    token: str = Field(
        ...,
        description="Authentication token for accessing the OpenCTI API",
        min_length=1,
    )

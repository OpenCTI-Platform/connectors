from typing import Literal

from pydantic import AwareDatetime, Field, HttpUrl, SecretStr
from pydantic_settings import BaseSettings

from config.base_config import BaseConfig

TLPLevelTypes = Literal["clear", "green", "amber", "amber+strict", "red"]


class DragosConfig(BaseSettings):
    api_base_url: HttpUrl = Field(description="Dragos API base URL.")
    api_token: SecretStr = Field(description="Dragos API token.")
    import_start_date: AwareDatetime = Field(description="Start date of first import.")
    tlp_level: TLPLevelTypes = Field(description="TLP level to apply")


class Config(BaseConfig):
    dragos: DragosConfig

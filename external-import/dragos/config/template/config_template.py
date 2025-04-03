from pydantic_settings import BaseSettings

from config.base_config import BaseConfig


class ChangeMeConfig(BaseSettings):
    change_me: str


class Config(BaseConfig):
    change_me: ChangeMeConfig

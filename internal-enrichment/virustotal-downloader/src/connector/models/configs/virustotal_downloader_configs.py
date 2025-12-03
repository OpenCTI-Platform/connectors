from pydantic import Field, SecretStr
from src.connector.models.configs.base_settings import ConfigBaseSettings


class _ConfigLoaderVirusTotalDownloader(ConfigBaseSettings):
    """Interface for loading VirusTotal Downloader dedicated configuration."""

    # Config Loader
    api_key: SecretStr = Field(
        description="API key used to authenticate requests to the VirusTotal Downloader service.",
    )

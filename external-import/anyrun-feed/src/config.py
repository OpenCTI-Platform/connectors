import os

import yaml
from pycti import get_config_variable

config_file_path: str = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "config.yml"
)

config: dict = (
    yaml.safe_load(open(config_file_path, encoding="utf-8"))
    if os.path.isfile(config_file_path)
    else {}
)


class Config:
    """Base configuration class."""

    VERSION = "OpenCTI:7.260422.0"
    DATE_TIME_FORMAT = "%Y-%m-%d %H:%M:%S"
    FEEDS_CHUNK_LIMIT = 5000

    def __init__(self) -> None:
        self._create_base_config()
        self.anyrun_api_key = get_config_variable(
            "ANYRUN_API_KEY", ["anyrun", "api_key"], config
        )

    def _create_base_config(self) -> None:
        """
        Updates connector parameters using content of docker-compose.yml or config.yml file
        """
        self.fetch_interval = get_config_variable(
            "ANYRUN_FEED_FETCH_INTERVAL",
            ["anyrun", "feed_fetch_interval"],
            config,
            isNumber=True,
            default=120,
        )

        self.fetch_depth = get_config_variable(
            "ANYRUN_FEED_FETCH_DEPTH",
            ["anyrun", "feed_fetch_depth"],
            config,
            isNumber=True,
            default=90,
        )

        self.update_existing_data = get_config_variable(
            "CONNECTOR_UPDATE_EXISTING_DATA",
            ["connector", "update_existing_data"],
            config,
            default=False,
        )

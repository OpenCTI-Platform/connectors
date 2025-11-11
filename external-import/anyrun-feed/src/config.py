import os

import yaml
from pycti import get_config_variable

config_file_path: str = os.path.dirname(os.path.abspath(__file__)) + '/config.yml'

config: dict = (
    yaml.load(open(config_file_path), Loader=yaml.FullLoader)
    if os.path.isfile(config_file_path)
    else {}
)

class Config:
    """ Base configuration class """
    VERSION = 'OpenCTI:6.7.4'
    DATE_TIME_FORMAT = '%Y-%m-%d %H:%M:%S'
    FEEDS_CHUNK_LIMIT = 5000

    def __init__(self) -> None:
        self._create_base_config()
        self.anyrun_token = f"{get_config_variable('ANYRUN_BASIC_TOKEN', ['anyrun', 'token'], config)}"

    def _create_base_config(self) -> None:
        """
        Updates connector parameters using content of docker-compose.yml or config.yml file
        """
        self.fetch_interval = get_config_variable(
            'ANYRUN_FEED_FETCH_INTERVAL',
            ['anyrun', 'feed_fetch_interval'],
            config,
            isNumber=True
        )

        self.fetch_depth = get_config_variable(
            'ANYRUN_FEED_FETCH_DEPTH',
            ['anyrun', 'feed_fetch_depth'],
            config,
            isNumber=True
        )

        self.update_existing_data = get_config_variable(
            'CONNECTOR_UPDATE_EXISTING_DATA',
            ['connector', 'update_existing_data'],
            config,
            isNumber=True
        )

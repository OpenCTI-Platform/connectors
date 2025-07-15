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
    VERSION = 'OpenCTI:6.7.4'
    DATE_TIME_FORMAT = '%Y-%m-%d %H:%M:%S'
    FEEDS_CHUNK_LIMIT = 5000

    def __init__(self) -> None:
        self._create_base_config()
        self.anyrun_token = f"API-KEY {get_config_variable('ANYRUN_API_KEY', ['anyrun', 'token'], config)}"

    def _create_base_config(self) -> None:
        """
        Updates connector parameters using content of docker-compose.yml or config.yml file
        """
        self.lookup_depth = get_config_variable(
            'ANYRUN_LOOKUP_DEPTH',
            ['anyrun', 'lookup_depth'],
            config,
            isNumber=True
        )

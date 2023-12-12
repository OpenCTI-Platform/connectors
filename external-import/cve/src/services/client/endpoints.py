"""
API URL VARIABLES
"""
from services.utils.config_variables import ConfigCVE  # type: ignore

# Base
config = ConfigCVE()
API_URL = config.base_url
API_VERSION = "/2.0"
BASE_URL = API_URL + API_VERSION

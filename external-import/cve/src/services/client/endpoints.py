"""
API URL VARIABLES
"""

from src.services.utils import CVEConfig  # type: ignore

# Base
config = CVEConfig()
config_instance = config.load
API_URL = config_instance.cve.base_url
API_VERSION = "/2.0"
BASE_URL = API_URL + API_VERSION

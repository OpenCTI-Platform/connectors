"""
API URL VARIABLES
"""

from services.utils import ConfigLoader  # type: ignore

# Base
config = ConfigLoader()
API_URL = config.cve.base_url
API_VERSION = "/2.0"
BASE_URL = API_URL + API_VERSION

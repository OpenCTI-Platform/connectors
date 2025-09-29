"""
API URL VARIABLES
"""

from src import ConfigLoader

# Base
config = ConfigLoader()  # To fix
API_URL = config.cve.base_url
API_VERSION = "/2.0"
BASE_URL = API_URL + API_VERSION

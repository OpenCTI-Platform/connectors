import time

import requests
from requests.adapters import HTTPAdapter
from urllib3.util import Retry

from falconpy import Intel as CrowdstrikeIntel
from crowdstrike_feeds_connector import CrowdStrike


class BaseCrowdstrikeClient:
    """
    Working with FalconPy library
    """
    def __init__(self, helper):
        self.helper = helper



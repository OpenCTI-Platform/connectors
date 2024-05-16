import time

import requests
from crowdstrike_feeds_connector import CrowdStrike
from falconpy import Intel as CrowdstrikeIntel
from requests.adapters import HTTPAdapter
from urllib3.util import Retry


class BaseCrowdstrikeClient:
    """
    Working with FalconPy library
    """

    def __init__(self, helper):
        self.helper = helper

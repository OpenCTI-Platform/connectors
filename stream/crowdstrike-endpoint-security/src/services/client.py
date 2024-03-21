from .config_variables import ConfigCrowdstrike
from falconpy import IOC as CrowdstrikeIOC


class CrowdstrikeClient:
    """
    Working with Falcon Py for Crowdstrike API call
    """
    def __init__(self, helper):
        self.config = ConfigCrowdstrike()
        self.helper = helper
        self.cs = CrowdstrikeIOC(
            client_id=self.config.client_id,
            client_secret=self.config.client_secret,
            base_url=self.config.api_base_url
        )

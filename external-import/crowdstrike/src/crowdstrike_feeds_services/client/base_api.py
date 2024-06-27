from falconpy import Intel as CrowdstrikeIntel

from ..utils.config_variables import ConfigCrowdstrike


class BaseCrowdstrikeClient:
    """
    Working with FalconPy library
    """

    def __init__(self, helper):
        """
        Initialize API with necessary configurations
        :param helper: Helper OpenCTI
        """
        self.config = ConfigCrowdstrike()
        self.helper = helper
        self.cs_intel = CrowdstrikeIntel(
            client_id=self.config.client_id,
            client_secret=self.config.client_secret,
            base_url=self.config.base_url,
        )

    def handle_api_error(self, response: dict) -> None:
        """
        Handle API error from Crowdstrike
        :param response: Response in dict
        :return: None
        """

        if response["status_code"] >= 400:
            error_message = response["body"]["errors"][0]["message"]
            self.helper.connector_logger.error(
                "[API] Error while processing fetching data",
                {"error_message": error_message},
            )

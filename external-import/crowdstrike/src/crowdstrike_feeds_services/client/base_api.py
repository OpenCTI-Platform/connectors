from typing import TYPE_CHECKING

from falconpy import Intel as CrowdstrikeIntel

if TYPE_CHECKING:
    from crowdstrike_feeds_connector import ConnectorSettings
    from pycti import OpenCTIConnectorHelper


class BaseCrowdstrikeClient:
    """
    Working with FalconPy library
    """

    def __init__(self, config: "ConnectorSettings", helper: "OpenCTIConnectorHelper"):
        """
        Initialize API with necessary configurations
        :param helper: Helper OpenCTI
        """
        self.config = config
        self.helper = helper
        self.cs_intel = CrowdstrikeIntel(
            client_id=self.config.crowdstrike.client_id.get_secret_value(),
            client_secret=self.config.crowdstrike.client_secret.get_secret_value(),
            base_url=str(self.config.crowdstrike.base_url),
        )

    def handle_api_error(self, response: dict) -> None:
        """
        Handle API error from Crowdstrike
        :param response: Response in dict
        :return: None
        """

        if response["status_code"] >= 400:
            error_message = response["body"]["errors"][0]["message"]
            status_code = response["status_code"]

            # Log 403 (permission denied) as warning since it's often expected/handled gracefully
            if status_code == 403:
                self.helper.connector_logger.warning(
                    "[API] Permission denied accessing resource",
                    {"error_message": error_message},
                )
            else:
                self.helper.connector_logger.error(
                    "[API] Error while querying CrowdStrike API",
                    {"error_message": error_message},
                )

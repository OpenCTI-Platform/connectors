import requests
from malbeacon_config_variables import ConfigMalbeacon


class MalbeaconClient:
    """
    Working with Malbeacon API
    """

    def __init__(self, helper):
        self.config = ConfigMalbeacon()
        self.helper = helper
        # Define headers in session and update when needed
        headers = {"X-Api-Key": self.config.api_key}
        self.session = requests.Session()
        self.session.headers.update(headers)

    def request_data(self, url_path: str) -> list | None:
        """
        Handle API requests
        :param url_path: URL path in string
        :return: Response in JSON list format or None
        """
        try:
            response = self.session.get(url_path)

            return response.json()

        except requests.exceptions.RequestException as err:
            error_msg = "[API] Error while fetching data: "
            self.helper.connector_logger.error(
                error_msg, {"url_path": {url_path}, "error": {str(err)}}
            )
            return None

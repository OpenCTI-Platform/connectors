import requests
import time

class Teamt5Client:

    def __init__(self, helper, config) -> None:
        """
        Initialises the the Teamt5Client.

        :param helper: The OpenCTI connector helper object.
        :param config: The connector configuration object.
        """

        self.helper = helper
        self.config = config

        self.session = requests.Session()
        headers = {"Authorization": f"Bearer {self.config.teamt5.api_key.get_secret_value()}"}
        self.session.headers.update(headers)
        

    def _request_data(self, url: str, params=None) -> dict:
        """
        Make a get request based upon the specified URL. 

        :param url: The URL to request data from.
        :param params: Optional dictionary of query parameters.
        :return: The json of the response object on success, or None on failure.
        """
        timeout = 15

        try:
            # validate the response and add a small delay as to not overload the API
            response = self.session.get(url, params=params, timeout=timeout)
            response.raise_for_status()
            time.sleep(1)
            return response.json()

        except (
            requests.exceptions.HTTPError,
            requests.ConnectionError,
            requests.ConnectTimeout,
        ) as e:
            self.helper.connector_logger.warning(f"Failed request to: {url} {e}")
        return None
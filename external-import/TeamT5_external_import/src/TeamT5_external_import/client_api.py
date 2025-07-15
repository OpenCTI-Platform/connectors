import time

import requests


class ConnectorClient:

    def __init__(self, helper, config) -> None:
        """
        Initialises the the ConnectorClient.

        :param helper: The OpenCTI connector helper object.
        :param config: The connector configuration object.
        """

        self.helper = helper
        self.config = config

        self.session = requests.Session()
        headers = {"Authorization": f"Bearer {self.config.api_key}"}
        self.session.headers.update(headers)

    def _request_data(self, url: str, params=None):
        """
        Makes a get request to a Team T5 API url, with required retry
        and delay logic included as a means of basic rate handling.

        :param url: The URL to request data from.
        :param params: Optional dictionary of query parameters.
        :return: A response object on success, or None on failure.
        """

        DELAY_BETWEEN_CALLS = 1
        NUM_RETIRES = 5
        RETRY_DELAY = 2
        TIMEOUT = 5

        for i in range(NUM_RETIRES):

            try:
                # validate the response and add a small delay as to not overload the API
                response = self.session.get(url, params=params, timeout=TIMEOUT)
                response.raise_for_status()
                time.sleep(DELAY_BETWEEN_CALLS)
                return response

            except requests.RequestException as err:
                self.helper.connector_logger.error(
                    "Request Error while fetching data",
                    {"url_path": {url}, "error": {str(err)}},
                )

            except Exception as e:
                self.helper.connector_logger.error(
                    "General Error while fetching data",
                    {"url_path": {url}, "error": {str(e)}},
                )

            # If a request attempt failed, wait and then retry until retries are maxed out.
            time.sleep(RETRY_DELAY)

        self.helper.connector_logger.error(
            f"Error fetching data from {url}, retires exceeded with no response received. "
        )
        return None

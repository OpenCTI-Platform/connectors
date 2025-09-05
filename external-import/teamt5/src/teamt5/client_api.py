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
        Makes a get request to a Team T5 API url.

        :param url: The URL to request data from.
        :param params: Optional dictionary of query parameters.
        :return: A response object on success, or None on failure.
        """
        timeout = 10

        try:
            # validate the response and add a small delay as to not overload the API
            response = self.session.get(url, params=params, timeout=timeout)

            response.raise_for_status()
            return response

        except requests.RequestException as err:
            self.helper.connector_logger.error(
                "Request Error while fetching data",
                {"url_path": {url}, "error": {str(err)}},
            )
        return None

import requests
from pycti import OpenCTIConnectorHelper
from pydantic import HttpUrl


class SilentpushClient:
    def __init__(
        self,
        helper: OpenCTIConnectorHelper,
        base_url: HttpUrl,
        api_key: str,
        verify: bool,
    ):
        """Initialize the Silent Push API client.

        :param helper: Connector helper, used for logging.
        :param base_url: Silent Push API base URL.
        :param api_key: API key for authentication.
        :param verify: Whether to verify SSL certificates.
        """
        self.helper = helper

        self.base_url = base_url
        self.verify = verify
        # Define headers in session and update when needed
        headers = {"x-api-key": api_key}
        self.session = requests.Session()
        self.session.headers.update(headers)

    def _request_data(self, api_url: str) -> dict | None:
        """
        Internal method to handle API requests
        :return: Response in JSON format
        """
        try:
            response = self.session.get(api_url, verify=self.verify)
            self.helper.connector_logger.info(
                "[API] HTTP GET request",
                {"url": api_url},
            )
            response.raise_for_status()
            return response.json()

        except requests.RequestException as err:
            error_msg = "[API] Error while fetching data: "
            self.helper.connector_logger.error(
                error_msg, {"url_path": {api_url}, "error": {str(err)}}
            )
            return None

    def get_enrichment_data(self, api_type: str, value: str) -> dict | None:
        """Fetch enrichment data from Silent Push API.

        :param api_type: API type (e.g. ipv4, domain).
        :param value: Observable value.
        :return: Parsed JSON response or None on error.
        """
        enrichment_url = f"{self.base_url}enrich/{api_type}/{value}/enrich/"

        return self._request_data(enrichment_url)

    def get_diversity_data(self, value: str) -> dict | None:
        """Fetch PADNS diversity data from Silent Push API.

        :param value: Domain name.
        :return: Parsed JSON response or None on error.
        """
        diversity_url = f"{self.base_url}enrich/domain/{value}/ip-diversity/"

        return self._request_data(diversity_url)

import requests


class RansomwareAPIError(Exception):
    """Custom wrapper for exceptions raised in RansomwareAPIClient"""


class RansomwareAPIClient:
    def __init__(
        self,
    ):
        """
        Initialize the client with necessary configurations
        """
        self.api_base_url = "https://api.ransomware.live/v2/"

    def _send_request(self, url: str):
        """
        Send a request to Ransomware API.
        :param url: request URL in string
        :return: response data returned by the API
        """
        try:
            response = requests.get(
                url, headers={"accept": "application/json", "User-Agent": "OpenCTI"}
            )
            response.raise_for_status()

            if response.content:
                return response.json()
        except requests.RequestException as err:
            raise RansomwareAPIError(
                f"Error while fetching Ransomware API: {err}",
                {"url": f"GET {url}", "error": err},
            ) from err

    def get_feed(self, path: str) -> list[dict]:
        """
        Get feed for given path.
        :param path: path to get feed from.
        :return: data's feed items
        """
        url = f"{self.api_base_url}{path}"
        data = self._send_request(url)

        return data

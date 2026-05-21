import time
from typing import Optional

import requests


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
        headers = {
            "Authorization": f"Bearer {self.config.teamt5.api_key.get_secret_value()}"
        }
        self.session.headers.update(headers)

    def request_data(self, url: str, params=None) -> Optional[dict]:
        """
        Make a get request based upon the specified URL.

        :param url: The URL to request data from.
        :param params: Optional dictionary of query parameters.
        :return: The decoded JSON body of the response on success, or ``None`` on failure (HTTP error, network error, or invalid JSON).
        """
        timeout = 15

        try:
            response = self.session.get(url, params=params, timeout=timeout)
            response.raise_for_status()
            # Small delay so we do not hammer the API on tight pagination loops.
            time.sleep(1)
            return response.json()

        except (
            requests.exceptions.HTTPError,
            requests.ConnectionError,
            requests.ConnectTimeout,
            requests.exceptions.ReadTimeout,
        ) as err:
            self.helper.connector_logger.warning(f"Failed request to: {url} {err}")
        except ValueError as err:
            # ``response.json()`` raises ValueError (a JSONDecodeError) when
            # the body is not valid JSON; treat it like any other transport
            # failure rather than crashing the connector run.
            self.helper.connector_logger.warning(
                f"Failed to decode JSON response from {url}: {err}"
            )
        return None

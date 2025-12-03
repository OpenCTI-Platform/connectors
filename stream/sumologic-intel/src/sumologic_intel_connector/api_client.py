import time
from typing import List, Optional

import requests
from pycti import OpenCTIConnectorHelper
from requests.adapters import HTTPAdapter
from requests.exceptions import ConnectionError, HTTPError, Timeout
from requests.models import Response
from urllib3.util.retry import Retry

from .config_loader import ConfigConnector


class SumologicClient:
    def __init__(self, helper: OpenCTIConnectorHelper, config: ConfigConnector):
        self.helper = helper
        self.config = config
        self.session = requests.Session()
        self.session.auth = (self.config.access_id, self.config.access_key)

    def upload_stix_indicator(self, source_name: str, stix_indicator: dict):
        """
        https://api.sumologic.com/docs/#operation/uploadStixIndicators
        :param source_name:
        :param stix_indicator:
        :return:
        """
        # STIX extensions not supported by sumologic
        del stix_indicator["extensions"]

        body = {"source": source_name, "indicators": [stix_indicator]}

        self.helper.connector_logger.debug(
            f"Uploading STIX Indicator name: {stix_indicator.get('name')}"
        )

        url = self.config.api_base_url + "/api/v1/threatIntel/datastore/indicators/stix"

        try:
            response = self._send_request(
                method="POST", url=url, body=body, retry_status_forcelist=[429]
            )
            if response.status_code == 200:
                return response.ok
            else:
                response.raise_for_status()

        except HTTPError as err:
            self.helper.connector_logger.error(
                "An HTTP error occurred while uploading indicator",
                {"http_error": str(err)},
            )
            return None

        except Timeout as err:
            self.helper.connector_logger.error(
                "A timeout error has occurred while uploading indicator",
                {"timeout_error": str(err)},
            )
            return None

        except ConnectionError as err:
            self.helper.connector_logger.error(
                "A connection error occurred while uploading indicator",
                {"connection_error": str(err)},
            )
            return None

        except Exception as err:
            self.helper.connector_logger.error(
                "An unexpected error occurred while uploading indicator",
                {"error": str(err)},
            )
            return None

        return response

    def delete_stix_indicator(self, source_name: str, stix_indicator: dict):
        """
        https://api.sumologic.com/docs/#operation/removeIndicators
        :param source_name:
        :param stix_indicator:
        :return:
        """

        body = {"source": source_name, "indicatorIds": [stix_indicator.get("id")]}

        self.helper.connector_logger.debug(
            f"Deleting STIX Indicator name: {stix_indicator.get('name')}"
        )

        url = self.config.api_base_url + "/api/v1/threatIntel/datastore/indicators"

        try:
            response = self._send_request(
                method="DELETE", url=url, body=body, retry_status_forcelist=[429]
            )

            if response.status_code == 204:
                return response.ok
            else:
                response.raise_for_status()

        except HTTPError as err:
            self.helper.connector_logger.error(
                "An HTTP error occurred during while deleting the indicator",
                {"http_error": str(err)},
            )
            return None

        except Timeout as err:
            self.helper.connector_logger.error(
                "A timeout error has occurred while deleting the indicator",
                {"timeout_error": str(err)},
            )
            return None

        except ConnectionError as err:
            self.helper.connector_logger.error(
                "A connection error occurred while deleting the indicator",
                {"connection_error": str(err)},
            )
            return None

        except Exception as err:
            self.helper.connector_logger.error(
                "An unexpected error occurred while deleting the indicator",
                {"error": str(err)},
            )
            return None

        return response

    @staticmethod
    def backoff_delay(backoff_factor: float, attempts: int) -> float:
        """
        Calculate the delay for a retry attempt using an exponential backoff algorithm.

        :param backoff_factor: float, the base delay time in seconds. This value is
                               multiplied by the exponential factor to determine the delay.
        :param attempts: int, the number of retry attempts already made (1-based).
        :return: float, the calculated delay time in seconds.

        Example:
            For `backoff_factor` = 0.5 and `attempts` = 3, the delay is calculated as:
            delay = 0.5 * (2 ** (3 - 1)) = 0.5 * 4 = 2.0 seconds.
        """
        delay = backoff_factor * (2 ** (attempts - 1))
        return delay

    def _send_request(
        self,
        method: str,
        url: str,
        body: dict,
        backoff_factor: int = 30,
        total: int = 4,
        retry_status_forcelist: Optional[List[int]] = None,
    ) -> Optional[Response]:
        """
        Send a POST request with retry logic and exponential backoff for specified HTTP statuses.
        :param backoff_factor: int, the base delay factor (in seconds) for exponential backoff. Defaults to 10.
        :param total: int, the maximum number of retry attempts. Defaults to 4.
        :param retry_status_forcelist: Optional[List[int]], a list of HTTP status codes that should trigger retries.
                                 Defaults to an empty list.
        :return: Optional[Response], the HTTP response object from the final successful request, or the last
                 response after all retries fail.

        Retry Logic:
            - If the response status code matches any in `status_forcelist`, the method retries the request
              after a delay calculated using the `backoff_delay` function.
            - Delays between retries increase exponentially, and logs are generated for each retry attempt.

        Error Handling:
            - Tracks and logs responses with status codes in `status_forcelist` during retries.
            - Returns the most recent response (`last_response`) if all retries fail.
        """
        if retry_status_forcelist is None:
            retry_status_forcelist = []
        last_response: Optional[Response] = None

        # Implement retry logic
        for attempt in range(total):

            response = self.session.request(method=method, url=url, json=body)
            if response.status_code in retry_status_forcelist:
                # Implement backoff
                delay = self.backoff_delay(backoff_factor, attempt)
                time.sleep(delay)

                self.helper.connector_logger.info(
                    "[API] Request failed. Retrying in a few seconds",
                    {"status_code": response.status_code, "delay_in_seconds": delay},
                )

                # Track the last response
                last_response = response
                continue
            else:
                return response

        # Return the last response after all retries fail
        return last_response

    def retries_builder(self) -> None:
        """
        Configures the session's retry strategy for API requests.

        Sets up the session to retry requests upon encountering specific HTTP status codes (429) using
        exponential backoff. The retry mechanism will be applied for both HTTP and HTTPS requests.
        This function uses the `Retry` and `HTTPAdapter` classes from the `requests.adapters` module.

        - Retries up to 5 times with an increasing delay between attempts.
        """
        retry_strategy = Retry(total=5, backoff_factor=2, status_forcelist=[429])
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("https://", adapter)

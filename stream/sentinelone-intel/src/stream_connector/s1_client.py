import json
import logging
import time
from typing import Optional

import requests

from .config_variables import ConfigConnector
from .custom_exceptions import SentinelOnePermissionError

# The endpoint for the POST request to SentinelOne
IOC_POST_ENDPOINT = "/web/api/v2.1/threat-intelligence/iocs?accountIds="

# The timeout for the API request (rare backup)
REQUEST_TIMEOUT = (10, 30)


class SentinelOneClient:

    def __init__(self, logger: logging.Logger, config: ConfigConnector):
        self.logger = logger
        self.config = config
        self.logger.info("SentinelOne Client Initialised Successfully.")

    def send_indicators(self, indicators: list) -> bool:
        """
        Sends a batch of indicators/iocs to SentinelOne by
        generating a formatted POST payload based upon the
        retrieved indicators.

        Functionality is also included to log the uuids of
        these indicators. These can be used in a myriad of
        ways as a means of showing that the indicators (iocs)
        are successfully present in an s1 instance.
        """

        # Generate the payload for the POST request.
        payload = json.dumps(
            {
                "data": indicators,
                "filter": {"tenant": False, "accountIds": [self.config.s1_account_id]},
            }
        )

        url = f"{self.config.s1_url}{IOC_POST_ENDPOINT}{self.config.s1_account_id}"
        request_type = "POST"
        s1_response = self._send_api_req(url, request_type, payload)

        if s1_response and self.config.log_s1_response:
            indicator_uuids = [
                indicator.get("uuid") for indicator in s1_response.get("data", {})
            ]
            self.logger.info(
                f"Batch of UUIDs as provided by SentinelOne response: {indicator_uuids}"
            )

        return s1_response

    # TODO: probably more formatting.
    def _send_api_req(
        self,
        url: str,
        request_type: str,
        payload: dict = {},
        wait_time: int = 1,
        attempts: int = 0,
    ) -> Optional[dict]:
        """
        Dynamic API request sender handling all
        important cases and retries.

        Returns a dictionary of the response from the API
        if all succeeds, otherwise returns False.
        """

        def calculate_exponential_delay(last_wait_time):
            return last_wait_time * 2

        HEADERS = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Authorization": self.config.s1_api_key,
        }

        response = requests.request(
            method=request_type,
            url=url,
            headers=HEADERS,
            data=payload,
            timeout=REQUEST_TIMEOUT,
        )

        # Authentication Errors should be raised and halt execution, nothing can continue if they are present.
        if response.status_code == 401:
            raise SentinelOnePermissionError(
                "Permissions Error, SentinelOne returned a 401, please check your API key and account ID."
            )

        # Rate Limiting requires an exponential backoff as a workaround.
        elif response.status_code == 429:
            if attempts < self.config.max_api_attempts:
                new_wait_time = calculate_exponential_delay(wait_time)
                self.logger.info(
                    f"Too many requests to S1, waiting: {new_wait_time} seconds"
                )
                time.sleep(new_wait_time)
                return self._send_api_req(
                    url, request_type, payload, new_wait_time, attempts + 1
                )
            else:
                self.logger.error(
                    f"Error, unable to send Payload to SentinelOne after: {self.config.max_api_attempts} attempts, please check your configuration."
                )
            return False

        # Random errors should be logged with context of their origin
        elif response.status_code != 200:
            self.logger.info(f"Error, Request got Response: {response.status_code}")
            self.logger.debug(f"URL Used: {url}")
            self.logger.debug(f"S1 responded with: {response.text}")
            return False

        # Dynamic, return the response as a dict.
        return response.json()

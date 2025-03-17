import logging
import time
from typing import Optional

import requests

from .config_variables import ConfigConnector
from .custom_exceptions import SentinelOnePermissionError

# The timeout for the API request (rare backup)
REQUEST_TIMEOUT = (10, 30)

INCIDENTS_API_LOCATION = "/web/api/v2.1/private/threat-groups?limit=50&sortBy=createdAt&sortOrder=desc&accountIds="
INCIDENT_NOTES_API_LOCATION_TEMPLATE = "/web/api/v2.1/threats/{incident_id}/notes?limit=1000&sortBy=createdAt&sortOrder=desc"
INCIDENT_API_LOCATION_TEMPLATE = "/web/api/v2.1/private/threats/{incident_id}/analysis"


class SentinelOneClient:

    def __init__(self, logger: logging.Logger, config: ConfigConnector):
        self.logger = logger
        self.config = config
        self.logger.info("SentinelOne Client Initialised Successfully.")

    def fetch_incidents(self) -> list:
        """
        Fetches all incidents from SentinelOne via API
        """

        url = self.config.s1_url + INCIDENTS_API_LOCATION + self.config.s1_account_id
        raw_incidents = self._send_api_req(url, "GET")
        return [
            inc.get("threatInfo", {}).get("threatId")
            for inc in raw_incidents.get("data", [])
        ]

    def fetch_incident(self, incident_id: str) -> dict:
        """
        Fetches a single incident from SentinelOne via API
        """

        url = self.config.s1_url + INCIDENT_API_LOCATION_TEMPLATE.format(
            incident_id=incident_id
        )
        return self._send_api_req(url, "GET").get("data", {})

    def fetch_incident_notes(self, incident_id: str) -> list:
        """
        Fetches all notes from a single incident from SentinelOne via API
        """

        url = self.config.s1_url + INCIDENT_NOTES_API_LOCATION_TEMPLATE.format(
            incident_id=incident_id
        )
        return self._send_api_req(url, "GET").get("data", [])

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

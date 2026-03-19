import logging
import time
from datetime import datetime, timezone
from typing import Optional

import requests

from .config_variables import ConfigConnector
from .custom_exceptions import SentinelOnePermissionError

# The timeout for the API request (rare backup)
REQUEST_TIMEOUT = (10, 30)

INCIDENTS_API_LOCATION = (
    "/web/api/v2.1/threats?limit=50&sortBy=createdAt&sortOrder=desc&accountIds="
)
INCIDENT_NOTES_API_LOCATION_TEMPLATE = "/web/api/v2.1/threats/{incident_id}/notes?limit=1000&sortBy=createdAt&sortOrder=desc"


def _parse_utc(dt_str: str) -> datetime:
    """Parse an ISO 8601 datetime string and ensure it is UTC-aware.
    Handles both 'Z' suffix and missing timezone (assumes UTC).
    Compatible with Python 3.9+.
    """
    if not dt_str:
        return datetime(1970, 1, 1, tzinfo=timezone.utc)
    dt_str = dt_str.replace("Z", "+00:00")
    dt = datetime.fromisoformat(dt_str)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


class SentinelOneClient:

    def __init__(self, logger: logging.Logger, config: ConfigConnector):
        self.logger = logger
        self.config = config
        self.logger.info("SentinelOne Client Initialised Successfully.")

    def fetch_incidents(self, start_date: datetime) -> list:
        """
        Fetches all incidents from SentinelOne created after start_date.
        Results are sorted descending by createdAt, so we stop as soon
        as we hit an incident older than start_date.
        """
        url = self.config.s1_url + INCIDENTS_API_LOCATION + self.config.s1_account_id
        incidents = []
        skip = 0
        stop_fetching = False

        while not stop_fetching:
            page_url = url + (f"&skip={skip}" if skip > 0 else "")
            response = self._send_api_req(page_url, "GET")

            if not response:
                self.logger.error("API request failed, stopping fetch.")
                break

            page_data = response.get("data", [])
            total_items = response.get("pagination", {}).get("totalItems", 0)

            if not page_data:
                break

            for incident in page_data:
                threat_info = incident.get("threatInfo", {})
                incident_created_at = _parse_utc(threat_info.get("createdAt", ""))

                if incident_created_at < start_date:
                    self.logger.info(
                        f"Incident created at {incident_created_at} is before "
                        f"start_date {start_date}, stopping fetch."
                    )
                    stop_fetching = True
                    break

                incidents.append(incident)

            skip += len(page_data)

            # Stop if we've fetched everything
            if skip >= total_items:
                break

        self.logger.info(f"Fetched {len(incidents)} incidents since {start_date}.")
        return incidents

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

        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Authorization": self.config.s1_api_key,
        }

        response = requests.request(
            method=request_type,
            url=url,
            headers=headers,
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
                    f"Error, unable to send Payload to SentinelOne after: {self.config.max_api_attempts} attempts."
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

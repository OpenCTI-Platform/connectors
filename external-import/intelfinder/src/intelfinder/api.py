import logging
from time import sleep

import requests

from .constants import (
    INTELFINDER_ALERT_DATA,
    INTELFINDER_DEFAULT_PAGE_SIZE,
    INTELFINDER_ERROR_CODE_MAP,
    INTELFINDER_HEADERS,
    INTELFINDER_URL,
    RATE_LIMIT,
)
from .transform import TransformIntelFinder2Stix
from .utils import get_cursor_id, validate_api_key

LOGGER = logging.getLogger(__name__)


class Intelfinder:
    """Intelfinder API class"""

    def __init__(
        self,
        api_key,
        author,
        cursor=None,
        labels=None,
        object_marking_refs="TLP:WHITE",
        rate_limit=RATE_LIMIT,
    ):
        """Initialize Intelfinder API class"""
        self.url = INTELFINDER_URL
        self.alerts_post_data = INTELFINDER_ALERT_DATA
        self.headers = INTELFINDER_HEADERS
        self.has_next = True
        self.cursor = cursor
        self.labels = labels
        self.index = 0
        self.rate_limit = rate_limit
        self.object_marking_refs = object_marking_refs
        self.author = author
        # Validate API key
        if validate_api_key(api_key):
            self.alerts_post_data["key"] = api_key

    def _request_data(self):
        """Request data from Intelfinder"""
        try:
            response = requests.post(
                self.url, data=self.alerts_post_data, headers=self.headers
            )
            response.raise_for_status()
            return response.json()
        except Exception as e:
            LOGGER.error(f"Error while fetching data from: {str(e)}")
            return None

    def set_cursor(self, cursor):
        """Set cursor"""
        self.cursor = cursor

    def get_cursor(self):
        """Get cursor"""
        return self.cursor

    def get_index(self):
        """Get index"""
        return self.index

    def get_alerts(self, cursor=None):
        """Get alerts from Intelfinder"""
        # Check if cursor is provided, add to post data if so.
        if cursor is not None:
            self.alerts_post_data["gta"] = cursor
        # Check if there are more alerts to retrieve, return empty list if not.
        if not self.has_next:
            LOGGER.warning("No more alerts to retrieve from Intelfinder")
            return []
        # Make request to Intelfinder and check for success.
        request_data = self._request_data()
        # Check if response is valid
        if "code" in request_data and request_data.get("code") == 0:
            alerts = request_data.get("alerts", [])
            LOGGER.info(f"Retrieved alert(s) ({len(alerts)}) from Intelfinder")
            self.index = self.index + len(alerts)
            # Check if there are more alerts to retrieve, set has_next to False if not.
            if len(alerts) < INTELFINDER_DEFAULT_PAGE_SIZE:
                self.has_next = False
            if len(alerts) > 0:
                self.set_cursor(get_cursor_id(alerts[-1]))
            return alerts
        # Check if response is rate limited
        elif "code" in request_data and request_data.get("code") == 4:
            LOGGER.warning(
                f"Request frequency exceeded limit, attempting to retrieve alerts again in ({self.rate_limit}) second(s)"
            )
            # sleep for self.rate_limit seconds and try again
            sleep(self.rate_limit)
            return self.get_alerts(cursor=cursor)
        # Check if response is invalid
        else:
            # Check if error code is in map, return error message
            if (
                "code" in request_data
                and request_data.get("code") in INTELFINDER_ERROR_CODE_MAP
            ):
                raise Exception(
                    "Error retrieving alerts: {}, {}".format(
                        INTELFINDER_ERROR_CODE_MAP.get(request_data.get("code")),
                        request_data.get("error"),
                    )
                )
            # Check if error code is not in map, return error code
            else:
                raise Exception(
                    "Error retrieving alerts: {}".format(request_data.get("error"))
                )

    def get_stix_objects(self, cursor=None):
        """Get STIX objects from Intelfinder"""
        # Get alerts from Intelfinder
        alerts = self.get_alerts(cursor=cursor)
        stix_objects = []
        # Transform alerts into STIX objects
        for alert in alerts:
            # Transform alert into STIX objects
            transform = TransformIntelFinder2Stix(
                author=self.author,
                intelfinder=alert,
                labels=self.labels,
                object_marking_refs=self.object_marking_refs,
            )
            stix_objects.extend(transform.get_stix_objects())
        LOGGER.info(f"Total STIX objects retrieved from Intelfinder: {self.index}")
        return stix_objects

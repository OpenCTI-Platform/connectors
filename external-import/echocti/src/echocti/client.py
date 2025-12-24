"""
Echo CTI API Client

This module connects to the Echo CTI API and fetches IOC feeds.
"""

import requests
from typing import Optional, List, Dict, Any
import logging


class EchoCTIClient:
    """Echo CTI API client."""

    API_URL = "https://api.echocti.com/ioc2/feeds"

    # Supported type values
    VALID_TYPES = ["ip", "url", "hash", "ip-range"]

    # Supported state values
    VALID_STATES = ["active", "removed", "false-positive", "white-listed", "all"]

    # Supported time range values
    VALID_TIME_RANGES = ["1h", "1d", "7d", "30d", "1y"]

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        api_url: Optional[str] = None,
        verify_ssl: bool = True,
    ):
        """
        Initialize the Echo CTI API client.

        Args:
            client_id: Echo CTI client ID
            client_secret: Echo CTI client secret
            api_url: Custom API URL (default: https://api.echocti.com/ioc2/feeds)
            verify_ssl: SSL certificate verification
        """
        self.client_id = client_id
        self.client_secret = client_secret
        self.api_url = api_url or self.API_URL
        self.verify_ssl = verify_ssl
        self.logger = logging.getLogger("echocti_client")

    def get_feeds(
        self,
        feed_type: Optional[str] = None,
        state: Optional[str] = None,
        random: Optional[str] = None,
        tag: Optional[str] = None,
        vendor: Optional[str] = None,
        time_since_created: Optional[str] = None,
        time_since_updated: Optional[str] = None,
        max_count: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        """
        Fetch IOC feeds from Echo CTI API.

        Args:
            feed_type: Feed type (ip, url, hash, ip-range or None=all)
            state: Feed state (active, removed, false-positive, white-listed, all)
            random: Random feed
            tag: Tag filter
            vendor: Vendor filter
            time_since_created: Creation time filter (1h, 1d, 7d, 30d, 1y)
            time_since_updated: Update time filter (1h, 1d, 7d, 30d, 1y)
            max_count: Maximum record count

        Returns:
            List of IOC feeds
        """
        params = {}

        # Type parameter
        if feed_type and feed_type.lower() != "all":
            if feed_type not in self.VALID_TYPES:
                self.logger.warning(
                    f"Invalid type value: {feed_type}. "
                    f"Valid values: {self.VALID_TYPES}"
                )
            else:
                params["type"] = feed_type

        # State parameter
        if state:
            if state not in self.VALID_STATES:
                self.logger.warning(
                    f"Invalid state value: {state}. "
                    f"Valid values: {self.VALID_STATES}"
                )
            else:
                params["state"] = state

        # Random parameter
        if random:
            params["random"] = random

        # Tag parameter
        if tag:
            params["tag"] = tag

        # Vendor parameter
        if vendor:
            params["vendor"] = vendor

        # Time since created parameter
        if time_since_created:
            if time_since_created not in self.VALID_TIME_RANGES:
                self.logger.warning(
                    f"Invalid time_since_created value: {time_since_created}. "
                    f"Valid values: {self.VALID_TIME_RANGES}"
                )
            else:
                params["time_since_created"] = time_since_created

        # Time since updated parameter
        if time_since_updated:
            if time_since_updated not in self.VALID_TIME_RANGES:
                self.logger.warning(
                    f"Invalid time_since_updated value: {time_since_updated}. "
                    f"Valid values: {self.VALID_TIME_RANGES}"
                )
            else:
                params["time_since_updated"] = time_since_updated

        # Max count parameter (0 = fetch all)
        if max_count and max_count > 0:
            params["max_count"] = max_count
        # If max_count is 0 or None, parameter is not sent, API returns all

        self.logger.info(f"Sending request to Echo CTI API: {self.api_url}")
        self.logger.debug(f"Parameters: {params}")

        try:
            response = requests.get(
                self.api_url,
                params=params,
                auth=(self.client_id, self.client_secret),
                verify=self.verify_ssl,
                timeout=300,  # 5 minute timeout (for all IOCs)
            )
            response.raise_for_status()

            content_type = response.headers.get("content-type", "")

            # API response is in text/plain format (line by line IOC)
            if "text/plain" in content_type or not content_type.startswith(
                "application/json"
            ):
                lines = response.text.strip().split("\n")
                feeds = []
                for line in lines:
                    line = line.strip()
                    if line:
                        feeds.append(
                            {
                                "value": line,
                                "type": params.get("type"),  # Type from API
                            }
                        )
            else:
                # JSON response case
                data = response.json()
                if isinstance(data, list):
                    feeds = data
                elif isinstance(data, dict):
                    feeds = data.get("data", data.get("feeds", [data]))
                else:
                    feeds = []

            self.logger.info(f"Received {len(feeds)} IOC feeds")
            return feeds

        except requests.exceptions.RequestException as e:
            self.logger.error(f"Echo CTI API request failed: {e}")
            raise

    def get_all_feed_types(
        self,
        state: Optional[str] = None,
        time_since_created: Optional[str] = None,
        time_since_updated: Optional[str] = None,
        max_count: Optional[int] = None,
    ) -> Dict[str, List[Dict[str, Any]]]:
        """
        Fetch all feed types separately.

        Args:
            state: Feed state
            time_since_created: Creation time filter
            time_since_updated: Update time filter
            max_count: Maximum record count per type

        Returns:
            IOC list grouped by feed type
        """
        all_feeds = {}

        for feed_type in self.VALID_TYPES:
            self.logger.info(f"Fetching {feed_type} type feeds...")
            try:
                feeds = self.get_feeds(
                    feed_type=feed_type,
                    state=state,
                    time_since_created=time_since_created,
                    time_since_updated=time_since_updated,
                    max_count=max_count,
                )
                all_feeds[feed_type] = feeds
            except Exception as e:
                self.logger.error(f"Failed to fetch {feed_type} feeds: {e}")
                all_feeds[feed_type] = []

        return all_feeds

    def test_connection(self) -> bool:
        """
        Test API connection.

        Returns:
            True if connection is successful
        """
        try:
            # Send a small test request
            self.get_feeds(max_count=1)
            self.logger.info("Echo CTI API connection successful")
            return True
        except Exception as e:
            self.logger.error(f"Echo CTI API connection test failed: {e}")
            return False

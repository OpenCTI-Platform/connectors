import json
from datetime import datetime
from typing import Generator
from urllib.parse import urljoin

import requests
from pycti import OpenCTIConnectorHelper

from .config_loader import ConfigLoader
from ..models.spycloud import BreachCatalog, BreachRecord


class SpyCloudClient:
    def __init__(
        self, helper: OpenCTIConnectorHelper = None, config: ConfigLoader = None
    ):
        """
        Initialize the client with necessary configurations
        """
        self.helper = helper
        self.config = config

        # Define headers in session and update when needed
        headers = {
            "Accept": "application/json",
            "X-API-KEY": self.config.spycloud.api_key,
        }
        self.session = requests.Session()
        self.session.headers.update(headers)

    def _read_json(self, file_name) -> list[dict]:
        with open(f"data_samples/{file_name}", encoding="utf-8") as f:
            data = json.load(f)
            return data

    def _request(self, **kwargs):
        """
        Internal method to handle API requests.
        :param kwargs: Any arguments accepted by request.request()
        :return: Parsed response body
        """
        method = kwargs.get("method")
        url = kwargs.get("url")

        try:
            # TODO: implement retry logic
            response = self.session.request(**kwargs)
            response.raise_for_status()

            self.helper.connector_logger.info(
                f"[API] HTTP {method.upper()} Request to endpoint", {"url": url}
            )

            return response.json() if response.content else None
        except requests.RequestException as err:
            error_msg = f"[API] Error while sending {method.upper()} request: "
            self.helper.connector_logger.error(error_msg, {"url": url, "error": err})

    def get_breach_catalog(self, breach_catalog_id: str = None) -> BreachCatalog:
        """
        Retrieve a breach catalog from Spycloud.
        :param breach_catalog_id: ID of breach catalog to retrieve
        :return: Found breach catalog
        """
        url = urljoin(
            self.config.spycloud.api_base_url, f"/breach/catalog/{breach_catalog_id}"
        )

        data = self._request(method="GET", url=url)
        # data = self._read_json(
        #     "get_catalog.json"
        # )  # TODO: remove once spycloud account is re-activated
        if not data:
            return None

        results = data["results"]
        if not results:
            return None

        result = results[0]

        return BreachCatalog(**result)

    def get_breach_records(
        self,
        watchlist_types: list = None,
        breach_severities: list = None,
        since: datetime = None,
    ) -> Generator[BreachRecord, None, None]:
        """
        Retrieve breach records from Spycloud.
        :param watchlist_type: Optional query param to filter breach records by watchlist
        :param severity: Optional query param to filter breach records by severity level
        :param since: Optional query param to filter breach records by publish date
        :return: List of breach records
        """
        url = urljoin(self.config.spycloud.api_base_url, "/breach/data/watchlist")
        params = {
            "watchlist_type": ",".join(watchlist_types) if watchlist_types else None,
            "severity": ",".join(breach_severities) if breach_severities else None,
            "since": since.isoformat() if since else None,
        }

        cursor = True  # only to enter while loop
        while cursor:
            data = self._request(method="GET", url=url, params=params)
            # data = self._read_json(
            #     "all_watchlist.json"
            # )  # TODO: remove once spycloud account is re-activated

            results = data["results"] if data else []
            for result in results:
                yield BreachRecord(**result)

            cursor = data["cursor"] if data else None
            if cursor:
                params["cursor"] = cursor
                # cursor = None  # TODO: remove once spycloud account is re-activated

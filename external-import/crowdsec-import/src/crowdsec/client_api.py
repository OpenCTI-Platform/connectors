# -*- coding: utf-8 -*-
"""CrowdSec client module."""

from typing import Any, Dict
from urllib.parse import urljoin

import requests


class CrowdSecClient:
    CTI_API_URL = "https://cti.api.crowdsec.net/"
    API_VERSION = "v2"

    def __init__(self, helper, config):
        """
        Initialize the client with necessary configurations
        """
        self.helper = helper
        self.config = config
        self.url = f"{self.CTI_API_URL}{self.API_VERSION}/smoke/search"

        # Define headers in session and update when needed
        headers = {
            "x-api-key": self.config.crowdsec_key,
            "User-Agent": "crowdsec-opencti-import/v1.0.0",
        }

        self.session = requests.Session()
        self.session.headers.update(headers)

    def _request_data(self, api_url: str, params=None, timeout=None):
        """
        Internal method to handle API requests
        :return: Response in JSON format
        """
        try:
            response = self.session.get(api_url, params=params, timeout=timeout)
            self.helper.connector_logger.info(
                "[API] HTTP Get Request to endpoint", {"url_path": api_url}
            )

            response.raise_for_status()
            return response

        except requests.RequestException as err:
            error_msg = "[API] Error while fetching data: "
            self.helper.connector_logger.error(
                error_msg, {"url_path": {api_url}, "error": {str(err)}}
            )
            return None

    def get_entities(self) -> Dict[str, Dict[str, Any]]:
        """
        Pull every page of Smoke Search results that match the current
        query and return them as a dict keyed by IP.
        @see https://crowdsecurity.github.io/cti-api/#/Freemium/get_smoke_search

        Returns
        -------
        Dict[str, Dict]
            ``{ip: full_item_dict, ...}``
        """
        try:
            since_param = f"{self.config.query_since}h"
            query = self.config.query
            enrichment_threshold = self.config.enrichment_threshold_per_import
            self.helper.log_info(
                f"Pulling IPs from {self.url} since {since_param} with query: {query}"
            )

            # 1. Build the constant parameters and headers for first request
            params = {"query": query, "since": since_param}

            # 2. Pagination loop
            ip_list: Dict[str, Dict] = {}
            page_url = self.url  # start with the base URL
            page_idx = 1

            while page_url and len(ip_list) < enrichment_threshold:
                try:
                    resp = self._request_data(
                        page_url,
                        params=params if page_idx == 1 else None,
                        timeout=(10, 60),
                    )
                    if resp is None:
                        raise requests.RequestException("Request failed")
                    body = resp.json()
                except (requests.RequestException, ValueError) as err:
                    # network error OR invalid JSON
                    self.helper.log_error(
                        f"Smoke Search request failed on page {page_idx}: {err}"
                    )
                    raise

                # -- harvest items from this page --
                items = body.get("items", [])
                for item in items:
                    ip_list[item["ip"]] = item

                self.helper.log_info(
                    f"Page {page_idx}: fetched {len(items)} items "
                    f"(running total {len(ip_list)})"
                )

                # Discover the next page if any (absent when we are on the last page)
                next_link = (
                    body.get("_links", {})
                    .get("next", {})  # absent when we are on the last page
                    .get("href")
                )
                if next_link:
                    # absolute vs. relative hrefs – both handled by urljoin
                    page_url = urljoin(page_url, next_link)
                    page_idx += 1
                else:
                    page_url = None  # loop terminates

            self.helper.log_info(f"Retrieved {len(ip_list)} unique Smoke Search IPs")
            return ip_list
        except Exception as err:
            self.helper.connector_logger.error(err)
            return {}

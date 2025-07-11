# -*- coding: utf-8 -*-
"""CrowdSec client module."""

from dataclasses import dataclass
from typing import Any, Dict
from urllib.parse import urljoin

import requests
from pycti import OpenCTIConnectorHelper


@dataclass
class CrowdSecClient:
    """CrowdSec client."""

    helper: OpenCTIConnectorHelper
    url: str
    api_key: str

    def get_searched_ips(
        self, since: str, query: str, enrichment_threshold: int
    ) -> Dict[str, Dict[str, Any]]:
        """
        Pull every page of Smoke Search results that match the current
        query and return them as a dict keyed by IP.
        @see https://crowdsecurity.github.io/cti-api/#/Freemium/get_smoke_search

        Returns
        -------
        Dict[str, Dict]
            ``{ip: full_item_dict, ...}``
        """
        since_param = f"{since}h"
        self.helper.log_info(
            f"Pulling IPs from {self.url} since {since_param} with query: {query}"
        )

        # 1. Build the constant parameters and headers for first request
        params = {"query": query, "since": since_param}
        headers = {
            "x-api-key": self.api_key,
            "User-Agent": "crowdsec-import-opencti/v1.0.0",
        }

        session = requests.Session()
        session.headers.update(headers)

        # 2. Pagination loop
        ip_list: Dict[str, Dict] = {}
        page_url = self.url  # start with the base URL
        page_idx = 1

        while page_url and len(ip_list) < enrichment_threshold:
            try:
                resp = session.get(
                    page_url, params=params if page_idx == 1 else None, timeout=(10, 60)
                )  # (connect, read) seconds
                resp.raise_for_status()  # converts 4xx/5xx to HTTPError
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

        self.helper.log_info(f"Downloaded {len(ip_list)} unique Smoke Search IPs")
        return ip_list

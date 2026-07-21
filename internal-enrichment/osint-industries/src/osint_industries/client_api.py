# -*- coding: utf-8 -*-
"""Client for the OSINT Industries API.

Endpoint : POST https://api.osint.industries/v2/request
Auth     : header `api-key: <key>`
Body     : JSON {"type": <email|phone|username|name|wallet>, "query": <value>, ...}
Response : 200 -> list of per-module objects (each with a spec_format field).
"""

from __future__ import annotations

import time

import requests


class OsintIndustriesClient:
    DEFAULT_BASE_URL = "https://api.osint.industries"

    # OpenCTI observable type -> selector type expected by the API
    SELECTOR_BY_TYPE = {
        "Email-Addr": "email",
        "Phone-Number": "phone",
        "User-Account": "username",
        "Cryptocurrency-Wallet": "wallet",
    }

    def __init__(
        self,
        helper,
        api_key: str,
        base_url: str | None = None,
        timeout: int = 60,
    ):
        self.helper = helper
        self.api_key = api_key
        self.base_url = (base_url or self.DEFAULT_BASE_URL).rstrip("/")
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update(
            {
                "api-key": self.api_key,
                "Accept": "application/json",
                "Content-Type": "application/json",
                "User-Agent": "opencti-osint-industries-connector/1.0",
            }
        )

    def selector_type_for(self, entity_type: str) -> str | None:
        return self.SELECTOR_BY_TYPE.get(entity_type)

    def query(
        self,
        selector_type: str,
        value: str,
        exact_match: bool = True,
        premium: bool = False,
        premium_modules_only: bool = False,
    ) -> list | dict | None:
        """Query the API (POST) for a (type, value) pair and return the raw JSON.

        Returns:
          - a list/dict on success,
          - [] when there is no result (404),
          - None on error (logged).
        """
        url = "%s/v2/request" % self.base_url
        body = {
            "type": selector_type,
            "query": value,
            "timeout": self.timeout,
            "exact_match": exact_match,
            "premium": premium,
            "premium_modules_only": premium_modules_only,
        }

        max_retries = 3
        for attempt in range(1, max_retries + 1):
            try:
                resp = self.session.post(url, json=body, timeout=self.timeout + 20)
            except requests.RequestException as exc:
                self.helper.connector_logger.error(
                    "OSINT Industries request failed", meta={"error": str(exc)}
                )
                return None

            # rate limit -> backoff then retry
            if resp.status_code == 429:
                retry_after = resp.headers.get("Retry-After")
                wait = int(retry_after) if retry_after and retry_after.isdigit() else 30
                self.helper.connector_logger.warning(
                    "OSINT Industries rate limited, backing off",
                    meta={"wait_seconds": wait, "attempt": attempt},
                )
                time.sleep(wait)
                continue

            if resp.status_code == 401:
                self.helper.connector_logger.error(
                    "OSINT Industries: invalid API key (401)."
                )
                return None
            if resp.status_code == 402:
                self.helper.connector_logger.error(
                    "OSINT Industries: insufficient credits (402)."
                )
                return None
            if resp.status_code == 404:
                # no result for this selector -- normal behaviour
                return []
            if resp.status_code >= 400:
                self.helper.connector_logger.error(
                    "OSINT Industries: error response",
                    meta={"status": resp.status_code, "body": resp.text[:500]},
                )
                return None

            try:
                return resp.json()
            except ValueError:
                self.helper.connector_logger.error(
                    "OSINT Industries: invalid JSON in response."
                )
                return None

        self.helper.connector_logger.error(
            "OSINT Industries: failed after several attempts (rate limit)."
        )
        return None

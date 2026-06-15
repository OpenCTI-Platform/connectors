"""HTTP client for the Redpanda HTTP Proxy (Pandaproxy)."""

from __future__ import annotations

import json
import time
from typing import TYPE_CHECKING, Optional

import requests
from pycti import OpenCTIConnectorHelper

if TYPE_CHECKING:
    from connector.settings import ConnectorSettings

# Content type expected by the Redpanda HTTP Proxy for JSON records.
CONTENT_TYPE = "application/vnd.kafka.json.v2+json"


class RedpandaClient:
    """Thin client around the Redpanda HTTP Proxy produce endpoint."""

    REQUEST_ATTEMPTS = 3
    BACKOFF_FACTOR = 5
    TIMEOUT = 30

    def __init__(
        self, config: ConnectorSettings, helper: OpenCTIConnectorHelper
    ) -> None:
        """
        Initialize the Redpanda client.

        :param config: The connector settings.
        :param helper: The OpenCTI connector helper (used for logging).
        """
        self.helper = helper
        self.config = config.redpanda

        self._base_url = str(self.config.http_proxy_url).rstrip("/")

        self.session = requests.Session()
        self.session.verify = self.config.ssl_verify
        self.session.headers.update({"Content-Type": CONTENT_TYPE})
        if self.config.username:
            self.session.auth = (
                self.config.username,
                self.config.password.get_secret_value(),
            )

    def produce_event(self, operation: str, data: dict) -> bool:
        """
        Produce a single OpenCTI stream event to the configured Redpanda topic.

        :param operation: The stream operation (create, update, delete).
        :param data: The STIX object carried by the stream event.
        :return: True if the record was produced, False otherwise.
        """
        # Leave the record key unset when the STIX id is missing or falsy, so a
        # None id is not serialized to the literal string "None" (str(None) is
        # truthy), which would skew Kafka partitioning/compaction downstream.
        raw_id = data.get("id")
        record = {
            "key": str(raw_id) if raw_id else None,
            "value": {"operation": operation, "data": data},
        }
        payload = {"records": [record]}
        url = f"{self._base_url}/topics/{self.config.topic}"
        response = self._request(url, json.dumps(payload).encode("utf-8"))
        return response is not None

    def _request(self, url: str, data: bytes) -> Optional[requests.Response]:
        """Perform an HTTP request with retry/backoff on rate limiting and transient errors.

        Retries are applied to 429 responses and to transient network/5xx errors.
        Non-retriable client errors (4xx other than 429, e.g. 401/403 bad
        credentials or 400 invalid payload) are logged once at error level and
        return ``None`` immediately instead of being retried with backoff.
        """
        for attempt in range(self.REQUEST_ATTEMPTS):
            try:
                response = self.session.post(url, data=data, timeout=self.TIMEOUT)
                if response.status_code == 429 and attempt < self.REQUEST_ATTEMPTS - 1:
                    time.sleep(self.BACKOFF_FACTOR * (2**attempt))
                    continue
                response.raise_for_status()
                return response
            except requests.HTTPError as err:
                status_code = (
                    err.response.status_code if err.response is not None else None
                )
                if (
                    status_code is not None
                    and 400 <= status_code < 500
                    and status_code != 429
                ):
                    self.helper.connector_logger.error(
                        "[API] Redpanda client error, not retrying",
                        meta={
                            "url": url,
                            "status_code": status_code,
                            "error": str(err),
                        },
                    )
                    return None
                self.helper.connector_logger.warning(
                    "[API] Redpanda request failed",
                    meta={"error": str(err)},
                )
                if attempt < self.REQUEST_ATTEMPTS - 1:
                    time.sleep(self.BACKOFF_FACTOR * (2**attempt))
            except requests.RequestException as err:
                self.helper.connector_logger.warning(
                    "[API] Redpanda request failed",
                    meta={"error": str(err)},
                )
                if attempt < self.REQUEST_ATTEMPTS - 1:
                    time.sleep(self.BACKOFF_FACTOR * (2**attempt))
        return None

"""HTTP client for the Vectra AI threat feed import API."""

from __future__ import annotations

import time
from typing import TYPE_CHECKING, Optional

import requests
from pycti import OpenCTIConnectorHelper
from vectra_client.stix_builder import build_stix_package, extract_indicator

if TYPE_CHECKING:
    from connector.settings import ConnectorSettings


class VectraClient:
    """Thin client around the Vectra AI threat feed import API."""

    REQUEST_ATTEMPTS = 3
    BACKOFF_FACTOR = 5
    TIMEOUT = 30

    def __init__(
        self, config: ConnectorSettings, helper: OpenCTIConnectorHelper
    ) -> None:
        """
        Initialize the Vectra AI client.

        :param config: The connector settings.
        :param helper: The OpenCTI connector helper (used for logging).
        """
        self.helper = helper
        self.config = config.vectra_ai

        self._base_url = str(self.config.api_base_url).rstrip("/")
        self._api_version = self.config.api_version.strip("/")
        self._feed_id: Optional[str] = None

        self.session = requests.Session()
        self.session.verify = self.config.ssl_verify
        self.session.headers.update(
            {"Authorization": f"Token {self.config.api_token.get_secret_value()}"}
        )

    def add_indicator(self, indicator: dict) -> bool:
        """
        Push a single OpenCTI indicator to the managed Vectra threat feed.

        :param indicator: The STIX indicator object received from the live stream.
        :return: True if the indicator was sent to Vectra, False if it was skipped.
        """
        pattern = indicator.get("pattern", "")
        extracted = extract_indicator(pattern)
        if extracted is None:
            self.helper.connector_logger.debug(
                "[API] Skipping indicator with unsupported pattern",
                meta={"pattern": pattern},
            )
            return False

        feed_id = self.get_or_create_feed()
        if feed_id is None:
            self.helper.connector_logger.error(
                "[API] Unable to resolve the Vectra threat feed, indicator not sent"
            )
            return False

        stix_document = build_stix_package([extracted])
        return self._upload_stix_file(feed_id, stix_document)

    def get_or_create_feed(self) -> Optional[str]:
        """Return the id of the managed threat feed, creating it if necessary."""
        if self._feed_id is not None:
            return self._feed_id

        feed_id = self._find_feed_id(self.config.feed_name)
        if feed_id is None:
            feed_id = self._create_feed()

        # Only cache a successfully resolved id. Caching ``None`` would persist a
        # transient failure (network hiccup, temporary 5xx) for the lifetime of
        # the connector process; leaving ``_feed_id`` unset lets the next call
        # retry feed resolution instead.
        if feed_id is not None:
            self._feed_id = feed_id
        return feed_id

    def _endpoint(self, *parts: str) -> str:
        suffix = "/".join(part.strip("/") for part in parts if part)
        return f"{self._base_url}/api/{self._api_version}/{suffix}"

    @staticmethod
    def _extract_feeds(payload: dict) -> list:
        for key in ("threatFeeds", "threat_feeds", "results"):
            value = payload.get(key)
            if isinstance(value, list):
                return value
        return []

    @staticmethod
    def _extract_feed_id(payload: dict) -> Optional[str]:
        for key in ("threatFeed", "threat_feed"):
            nested = payload.get(key)
            if isinstance(nested, dict) and nested.get("id") is not None:
                return str(nested["id"])
        if payload.get("id") is not None:
            return str(payload["id"])
        return None

    def _find_feed_id(self, name: str) -> Optional[str]:
        response = self._request("get", self._endpoint("threatFeeds"))
        if response is None:
            return None
        try:
            feeds = self._extract_feeds(response.json())
        except ValueError:
            return None
        for feed in feeds:
            if (
                isinstance(feed, dict)
                and feed.get("name") == name
                and feed.get("id") is not None
            ):
                return str(feed["id"])
        return None

    def _create_feed(self) -> Optional[str]:
        payload = {
            "name": self.config.feed_name,
            "defaults": {
                "category": self.config.feed_category,
                "certainty": self.config.feed_certainty,
                "duration": self.config.feed_duration,
            },
        }
        response = self._request("post", self._endpoint("threatFeeds"), json=payload)
        if response is None:
            return None
        try:
            feed_id = self._extract_feed_id(response.json())
        except ValueError:
            feed_id = None
        if feed_id is not None:
            self.helper.connector_logger.info(
                "[API] Created Vectra threat feed",
                meta={"name": self.config.feed_name, "feed_id": feed_id},
            )
        return feed_id

    def _upload_stix_file(self, feed_id: str, stix_document: str) -> bool:
        files = {"file": ("opencti.stix.xml", stix_document, "application/xml")}
        response = self._request(
            "post", self._endpoint("threatFeeds", feed_id), files=files
        )
        if response is None:
            return False
        # The upload response body is not used; release the connection back to the
        # Session pool instead of leaving it checked out until garbage collection.
        response.close()
        return True

    def _request(self, method: str, url: str, **kwargs) -> Optional[requests.Response]:
        """Perform an HTTP request with retry/backoff on rate limiting and transient errors.

        Retries are applied to 429 responses and to transient network/5xx errors.
        Non-retriable client errors (4xx other than 429, e.g. 401/403 bad token or
        400 invalid payload) are logged once at error level and return ``None``
        immediately instead of being retried with backoff.
        """
        for attempt in range(self.REQUEST_ATTEMPTS):
            try:
                response = self.session.request(
                    method, url, timeout=self.TIMEOUT, **kwargs
                )
                if response.status_code == 429 and attempt < self.REQUEST_ATTEMPTS - 1:
                    delay = self.BACKOFF_FACTOR * (2**attempt)
                    self.helper.connector_logger.warning(
                        "[API] Rate limited, retrying",
                        meta={"url": url, "delay": delay},
                    )
                    # Release the connection before sleeping/retrying: the body is
                    # not consumed on this path.
                    response.close()
                    time.sleep(delay)
                    continue
                response.raise_for_status()
                return response
            except requests.HTTPError as err:
                status_code = (
                    err.response.status_code if err.response is not None else None
                )
                # The error response body is not consumed; close it so the
                # connection returns to the Session pool instead of being held.
                if err.response is not None:
                    err.response.close()
                if (
                    status_code is not None
                    and 400 <= status_code < 500
                    and status_code != 429
                ):
                    self.helper.connector_logger.error(
                        "[API] Client error, not retrying",
                        meta={
                            "url": url,
                            "status_code": status_code,
                            "error": str(err),
                        },
                    )
                    return None
                self.helper.connector_logger.warning(
                    "[API] Request failed",
                    meta={"url": url, "error": str(err)},
                )
                if attempt < self.REQUEST_ATTEMPTS - 1:
                    time.sleep(self.BACKOFF_FACTOR * (2**attempt))
            except requests.RequestException as err:
                self.helper.connector_logger.warning(
                    "[API] Request failed",
                    meta={"url": url, "error": str(err)},
                )
                if attempt < self.REQUEST_ATTEMPTS - 1:
                    time.sleep(self.BACKOFF_FACTOR * (2**attempt))
        return None

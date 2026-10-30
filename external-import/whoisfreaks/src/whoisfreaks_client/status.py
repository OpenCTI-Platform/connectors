"""WhoisFreaks API status client."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import requests
from connectors_sdk.exceptions.error import DataRetrievalError


class WhoisFreaksStatusError(DataRetrievalError):
    """Raised when the WhoisFreaks status endpoint cannot be processed."""


@dataclass(frozen=True)
class FeedStatus:
    """Availability information for one WhoisFreaks feed."""

    last_update: str
    available_from: str

    @property
    def is_available(self) -> bool:
        """True when a concrete last_update date is present."""
        value = (self.last_update or "").strip().lower()
        return bool(value) and value not in {
            "not available",
            "n/a",
            "none",
            "null",
        }


@dataclass(frozen=True)
class WhoisFreaksStatus:
    """Relevant daily-feed availability returned by WhoisFreaks."""

    malware: FeedStatus
    phishing: FeedStatus
    spam: FeedStatus
    gtld: FeedStatus
    cctld: FeedStatus

    def get_threat_feed_status(self, feed_type: str) -> FeedStatus:
        """Return status for a threat feed."""
        try:
            return {
                "malware": self.malware,
                "phishing": self.phishing,
                "spam": self.spam,
            }[feed_type]
        except KeyError as exc:
            raise ValueError(f"Unsupported threat feed: {feed_type}") from exc

    def get_nrd_feed_status(self, feed_type: str) -> FeedStatus:
        """Return status for an NRD feed."""
        try:
            return {
                "gtld": self.gtld,
                "cctld": self.cctld,
            }[feed_type]
        except KeyError as exc:
            raise ValueError(f"Unsupported NRD feed type: {feed_type}") from exc


class WhoisFreaksStatusClient:
    """Client for the WhoisFreaks v3.4 status endpoint."""

    STATUS_PATH = "/v3.4/status"

    def __init__(
        self,
        api_key: str,
        base_url: str = "https://files.whoisfreaks.com",
        timeout: int = 120,
    ) -> None:
        self._timeout = timeout
        self._session = requests.Session()
        self._session.headers.update(
            {
                "X-API-KEY": api_key,
                "Accept": "application/json",
                "Accept-Encoding": "identity",
            }
        )
        self._base_url = str(base_url).rstrip("/")

    def get_status(self) -> WhoisFreaksStatus:
        """Fetch and validate the current WhoisFreaks feed status."""

        try:
            response = self._session.get(
                f"{self._base_url}{self.STATUS_PATH}",
                timeout=self._timeout,
            )
            response.raise_for_status()
            payload = response.json()
        except requests.RequestException as exc:
            status_code = getattr(
                getattr(exc, "response", None),
                "status_code",
                None,
            )

            if status_code is not None:
                message = f"WhoisFreaks status request returned HTTP {status_code}"
            else:
                message = "WhoisFreaks status request failed"

            raise WhoisFreaksStatusError(message) from exc
        except ValueError as exc:
            raise WhoisFreaksStatusError(
                "WhoisFreaks status response was not valid JSON"
            ) from exc

        try:
            return self._parse_status(payload)
        except (KeyError, TypeError, ValueError) as exc:
            raise WhoisFreaksStatusError(
                "WhoisFreaks status response has an invalid structure"
            ) from exc

    @staticmethod
    def _parse_status(payload: Any) -> WhoisFreaksStatus:
        """Parse the fields required by the daily feed processors."""

        if not isinstance(payload, dict):
            raise WhoisFreaksStatusError("Status payload has invalid structure")

        threat_feed = payload.get("threat_feed")
        newly = payload.get("newly")

        if not isinstance(threat_feed, dict) or not isinstance(newly, dict):
            raise WhoisFreaksStatusError("Status payload has invalid structure")

        required_threat_feeds = ("malware", "phishing", "spam")
        required_newly_feeds = ("gtld", "cctld")

        if any(feed not in threat_feed for feed in required_threat_feeds):
            raise WhoisFreaksStatusError("Status payload has invalid structure")

        if any(feed not in newly for feed in required_newly_feeds):
            raise WhoisFreaksStatusError("Status payload has invalid structure")

        try:
            return WhoisFreaksStatus(
                malware=WhoisFreaksStatusClient._parse_feed_status(
                    threat_feed["malware"]
                ),
                phishing=WhoisFreaksStatusClient._parse_feed_status(
                    threat_feed["phishing"]
                ),
                spam=WhoisFreaksStatusClient._parse_feed_status(threat_feed["spam"]),
                gtld=WhoisFreaksStatusClient._parse_feed_status(newly["gtld"]),
                cctld=WhoisFreaksStatusClient._parse_feed_status(newly["cctld"]),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise WhoisFreaksStatusError(
                "Status payload has invalid structure"
            ) from exc

    @staticmethod
    def _parse_feed_status(value: Any) -> FeedStatus:
        """Parse one feed's status object."""

        if not isinstance(value, dict):
            raise TypeError("Feed status must be an object")

        last_update = value["last_update"]
        available_from = value["available_from"]

        if not isinstance(last_update, str):
            raise TypeError("last_update must be a string")

        if not isinstance(available_from, str):
            raise TypeError("available_from must be a string")

        return FeedStatus(
            last_update=last_update,
            available_from=available_from,
        )

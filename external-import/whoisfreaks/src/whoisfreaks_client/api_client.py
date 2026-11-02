"""WhoisFreaks threat-feed HTTP client (stream + pagination)."""

from __future__ import annotations

import csv
import io
import time
from collections.abc import Iterator
from datetime import date, datetime
from itertools import count
from typing import Any

import requests
import urllib3.exceptions as _urllib3_exc
from connectors_sdk.exceptions.error import DataRetrievalError
from connectors_sdk.logger import get_logger
from whoisfreaks_client.models import ThreatFeedRecord

_LOGGER = get_logger(__name__)


class ThreatFeedPage(list[ThreatFeedRecord]):
    """Parsed records plus the number of source rows consumed from the API."""

    def __init__(
        self,
        records: list[ThreatFeedRecord],
        source_record_count: int,
    ) -> None:
        super().__init__(records)
        self.source_record_count = source_record_count


class WhoisFreaksClientError(DataRetrievalError):
    """Raised when a WhoisFreaks request or response is invalid."""


class WhoisFreaksSubscriptionError(WhoisFreaksClientError):
    """Raised when the API key lacks access to the requested feed (401/403)."""


class WhoisFreaksClient:
    """Client for the WhoisFreaks v3.4 stream threat feeds.

    Uses offset/limit pagination. Designed for feeds that can contain
    tens or hundreds of millions of rows per day: responses are streamed
    into a CSV reader (no full-body materialisation beyond one page),
    and callers can resume from an arbitrary start_offset.
    """

    DEFAULT_BASE_URL = "https://files.whoisfreaks.com/v3.4/stream"
    VALID_FEEDS = frozenset({"malware", "phishing", "spam"})

    def __init__(
        self,
        api_key: str,
        base_url: str = DEFAULT_BASE_URL,
        timeout: int = 180,
        max_retries: int = 5,
        retry_backoff_seconds: float = 2.0,
    ) -> None:
        self._api_key = api_key
        self._base_url = str(base_url).rstrip("/")
        self._timeout = timeout
        self._max_retries = max_retries
        self._retry_backoff = retry_backoff_seconds

        self._session = requests.Session()
        # Header-based auth is sufficient; do NOT include apiKey as a query
        # parameter to prevent the key appearing in server/proxy access logs
        # and in exception tracebacks via requests URL chaining.
        self._session.headers.update(
            {
                "X-API-KEY": api_key,
                "Accept": "text/csv",
                # The feeds are plain-text CSV and response.raw is read
                # undecoded, so do not let requests advertise gzip.
                "Accept-Encoding": "identity",
            }
        )

    def iter_threat_feed(
        self,
        feed_type: str,
        feed_date: date,
        limit: int,
        start_offset: int = 0,
    ) -> Iterator[ThreatFeedPage]:
        """Yield parsed pages from one daily WhoisFreaks threat feed."""

        if feed_type not in self.VALID_FEEDS:
            raise ValueError(f"Unsupported threat feed: {feed_type}")

        if limit < 1:
            raise ValueError("limit must be greater than zero")

        if start_offset < 0:
            raise ValueError("start_offset cannot be negative")

        offset = start_offset
        date_value = feed_date.isoformat()

        for offset_page in count(offset, limit):
            rows = self._fetch_page(
                feed_type=feed_type,
                date_value=date_value,
                offset=offset_page,
                limit=limit,
            )

            if rows.source_record_count == 0:
                return

            yield rows

            if rows.source_record_count < limit:
                return

    def _fetch_page(
        self,
        feed_type: str,
        date_value: str,
        offset: int,
        limit: int,
    ) -> ThreatFeedPage:
        """GET one page with retries and stream-based CSV parsing."""

        url = f"{self._base_url}/threat-feed/{feed_type}"
        params: dict[str, Any] = {
            "date": date_value,
            "offset": offset,
            "limit": limit,
        }

        last_exc: Exception | None = None

        for attempt in range(self._max_retries + 1):
            try:
                response = self._session.get(
                    url,
                    params=params,
                    timeout=self._timeout,
                    stream=True,
                )

                if response.status_code in (401, 403):
                    response.close()
                    raise WhoisFreaksSubscriptionError(
                        f"WhoisFreaks denied access to threat feed '{feed_type}' "
                        f"(HTTP {response.status_code}). "
                        f"This feed is not included in the current subscription "
                        f"or the API key is invalid. "
                        f"Disable '{feed_type}' in WHOISFREAKS_FEED_TYPES "
                        f"or upgrade the WhoisFreaks plan."
                    )

                if response.status_code == 429 or response.status_code >= 500:
                    response.close()
                    if attempt < self._max_retries:
                        delay = self._retry_backoff * (2**attempt)
                        time.sleep(delay)
                        continue
                    raise WhoisFreaksClientError(
                        f"WhoisFreaks returned HTTP {response.status_code} "
                        f"for {feed_type} on {date_value} after retries"
                    )

                response.raise_for_status()
                return self._parse_csv_stream(response)

            except WhoisFreaksSubscriptionError:
                raise
            except requests.RequestException as exc:
                last_exc = exc
                status_code = getattr(
                    getattr(exc, "response", None),
                    "status_code",
                    None,
                )
                if status_code in (401, 403):
                    raise WhoisFreaksSubscriptionError(
                        f"WhoisFreaks denied access to threat feed '{feed_type}' "
                        f"(HTTP {status_code}). "
                        f"Disable it in WHOISFREAKS_FEED_TYPES or upgrade "
                        f"the subscription."
                    ) from exc

                if status_code is not None and status_code < 500:
                    if exc.response is not None:
                        exc.response.close()
                    raise WhoisFreaksClientError(
                        f"WhoisFreaks returned HTTP {status_code} "
                        f"for {feed_type} on {date_value}"
                    ) from exc

                if attempt < self._max_retries:
                    delay = self._retry_backoff * (2**attempt)
                    time.sleep(delay)
                    continue

                message = (
                    f"WhoisFreaks returned HTTP {status_code} "
                    f"for {feed_type} on {date_value}"
                    if status_code is not None
                    else (
                        f"Failed to request WhoisFreaks {feed_type} "
                        f"feed for {date_value}"
                    )
                )
                raise WhoisFreaksClientError(message) from exc

        raise WhoisFreaksClientError(
            f"Failed to fetch {feed_type} for {date_value}"
        ) from last_exc

    @staticmethod
    def _parse_datetime(value: str) -> datetime:
        """Parse WhoisFreaks timestamps into datetime objects."""

        normalized = value.strip().replace(" ", "T", 1)

        try:
            return datetime.fromisoformat(normalized)
        except ValueError as exc:
            raise ValueError(f"Invalid WhoisFreaks datetime: {value}") from exc

    @classmethod
    def _parse_csv(cls, payload: str) -> ThreatFeedPage:
        """Parse one CSV page from a complete string (tests and non-stream use)."""

        reader = csv.DictReader(io.StringIO(payload))
        return cls._parse_csv_rows(reader)

    @classmethod
    def _parse_csv_rows(cls, reader: Any) -> ThreatFeedPage:
        """Parse CSV rows while retaining source offsets for skipped rows."""

        fieldnames = reader.fieldnames
        if fieldnames is not None and "domain" not in fieldnames:
            raise WhoisFreaksClientError(
                "WhoisFreaks threat-feed CSV response is missing required 'domain' header"
            )

        records: list[ThreatFeedRecord] = []
        source_record_count = 0

        for row_number, raw in enumerate(reader, start=2):
            if not raw or not any(raw.values()):
                continue

            domain = (raw.get("domain") or "").strip()
            if domain.lower() == "domain":
                continue

            source_record_count += 1
            try:
                if not domain:
                    raise ValueError("domain is missing")
                records.append(
                    ThreatFeedRecord(
                        domain=domain,
                        threat_type=(raw.get("threat_type") or "").strip(),
                        confidence_score=float(raw.get("confidence") or 0),
                        first_seen=cls._parse_datetime(raw.get("first_seen") or ""),
                        last_seen=cls._parse_datetime(raw.get("last_seen") or ""),
                        No_of_threat_matched_pivots=int(
                            raw.get("No_of_threat_matched_pivots") or 0
                        ),
                        source_fields={
                            key: (value or "").strip()
                            for key, value in raw.items()
                            if key is not None
                        },
                    )
                )
            except (KeyError, TypeError, ValueError) as exc:
                _LOGGER.warning(
                    "Skipping malformed WhoisFreaks threat-feed CSV row",
                    meta={"row_number": row_number, "error": str(exc)},
                )

        return ThreatFeedPage(records, source_record_count)

    def _parse_csv_stream(
        self,
        response: requests.Response,
    ) -> ThreatFeedPage:
        """Parse one CSV page from a streamed HTTP response body."""

        # Decode incrementally; page size is bounded by limit so memory is OK.
        # urllib3 closes response.raw once the last body byte is read, while
        # TextIOWrapper may still hold buffered rows; keep it open until the
        # finally block closes the response.
        response.raw.auto_close = False
        text_stream = io.TextIOWrapper(
            response.raw,
            encoding=response.encoding or "utf-8",
            errors="replace",
            newline="",
        )
        try:
            reader = csv.DictReader(text_stream)
            return self._parse_csv_rows(reader)
        except (_urllib3_exc.HTTPError, _urllib3_exc.IncompleteRead) as exc:
            raise requests.ConnectionError(
                f"Threat-feed stream read failed: {exc}"
            ) from exc
        finally:
            # urllib3 may auto-close response.raw after EOF, which marks the
            # TextIOWrapper closed and makes detach() raise ValueError — that
            # would mask a successful parse. Always close the HTTP response.
            try:
                if not text_stream.closed:
                    text_stream.detach()
            except ValueError:
                pass
            response.close()

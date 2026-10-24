"""WhoisFreaks Newly Registered Domains client (stream + pagination)."""

from __future__ import annotations

import csv
import io
import time
from dataclasses import dataclass
from datetime import date
from itertools import count
from typing import Any, Iterator

import requests
import urllib3.exceptions as _urllib3_exc
from connectors_sdk.exceptions.error import DataRetrievalError
from connectors_sdk.logger import get_logger


class WhoisFreaksNRDError(DataRetrievalError):
    """Raised when an NRD request or response cannot be processed."""


class WhoisFreaksNRDSubscriptionError(WhoisFreaksNRDError):
    """Raised when the API key lacks access to the requested NRD feed."""


@dataclass(frozen=True)
class NRDRecord:
    """A newly registered domain record."""

    domain_name: str
    fields: dict[str, str]


class NRDPage(list[NRDRecord]):
    """Parsed records plus the number of source rows consumed from the API."""

    def __init__(self, records: list[NRDRecord], source_record_count: int) -> None:
        super().__init__(records)
        self.source_record_count = source_record_count


_LOGGER = get_logger(__name__)


class WhoisFreaksNRDClient:
    """Client for the WhoisFreaks v3.3 NRD stream.

    Offset/limit pagination with streamed CSV parsing and resume support
    for multi-million-row daily files.
    """

    DEFAULT_BASE_URL = "https://files.whoisfreaks.com/v3.3/stream/domainer"
    VALID_FEEDS = frozenset({"gtld", "cctld"})

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
        # Header-based auth only — do NOT include apiKey as a query parameter
        # to prevent the key appearing in server/proxy logs and exception URLs.
        self._session.headers.update(
            {
                "X-API-KEY": api_key,
                "Accept": "text/csv",
                # The feeds are plain-text CSV and response.raw is read
                # undecoded, so do not let requests advertise gzip.
                "Accept-Encoding": "identity",
            }
        )

    def iter_feed(
        self,
        feed_type: str,
        whois: bool,
        feed_date: date,
        limit: int,
        start_offset: int = 0,
    ) -> Iterator[NRDPage]:
        """Yield NRD pages from the WhoisFreaks stream."""

        if feed_type not in self.VALID_FEEDS:
            raise ValueError(f"Unsupported NRD feed type: {feed_type}")

        if limit < 1:
            raise ValueError("limit must be greater than zero")

        if start_offset < 0:
            raise ValueError("start_offset cannot be negative")

        date_value = feed_date.isoformat()

        for offset in count(start_offset, limit):
            records = self._fetch_page(
                feed_type=feed_type,
                whois=whois,
                date_value=date_value,
                offset=offset,
                limit=limit,
            )

            if records.source_record_count == 0:
                return

            yield records

            if records.source_record_count < limit:
                return

    def _fetch_page(
        self,
        feed_type: str,
        whois: bool,
        date_value: str,
        offset: int,
        limit: int,
    ) -> NRDPage:
        """GET one NRD page with retries and stream parsing."""

        url = f"{self._base_url}/{feed_type}"
        params: dict[str, Any] = {
            "whois": str(whois).lower(),
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
                    raise WhoisFreaksNRDSubscriptionError(
                        f"WhoisFreaks denied access to NRD feed "
                        f"'{feed_type}' (whois={whois}, HTTP "
                        f"{response.status_code}). This feed is not "
                        f"included in the current subscription or the "
                        f"API key is invalid. Remove the corresponding "
                        f"entry from WHOISFREAKS_NRD_FEED_TYPES or "
                        f"upgrade the WhoisFreaks plan."
                    )

                if response.status_code == 429 or response.status_code >= 500:
                    response.close()
                    if attempt < self._max_retries:
                        delay = self._retry_backoff * (2**attempt)
                        time.sleep(delay)
                        continue
                    raise WhoisFreaksNRDError(
                        f"WhoisFreaks NRD request returned "
                        f"HTTP {response.status_code} after retries"
                    )

                response.raise_for_status()

                if whois:
                    return self._parse_whois_stream(response)
                return self._parse_domains_stream(response)

            except WhoisFreaksNRDSubscriptionError:
                raise
            except requests.RequestException as exc:
                last_exc = exc
                status_code = getattr(
                    getattr(exc, "response", None),
                    "status_code",
                    None,
                )
                if status_code in (401, 403):
                    raise WhoisFreaksNRDSubscriptionError(
                        f"WhoisFreaks denied access to NRD feed "
                        f"'{feed_type}' (HTTP {status_code}). "
                        f"Disable it in WHOISFREAKS_NRD_FEED_TYPES or "
                        f"upgrade the subscription."
                    ) from exc

                if status_code is not None and status_code < 500:
                    if exc.response is not None:
                        exc.response.close()
                    raise WhoisFreaksNRDError(
                        f"WhoisFreaks NRD request returned HTTP {status_code}"
                    ) from exc

                if attempt < self._max_retries:
                    delay = self._retry_backoff * (2**attempt)
                    time.sleep(delay)
                    continue

                message = (
                    f"WhoisFreaks NRD request returned HTTP {status_code}"
                    if status_code is not None
                    else "WhoisFreaks NRD request failed"
                )
                raise WhoisFreaksNRDError(message) from exc

        raise WhoisFreaksNRDError(
            "WhoisFreaks NRD request failed after retries"
        ) from last_exc

    @classmethod
    def _parse_whois_csv(cls, payload: str) -> NRDPage:
        """Parse a WHOIS-enriched NRD CSV page from a complete string."""

        reader = csv.DictReader(io.StringIO(payload))
        return cls._parse_whois_rows(reader)

    @classmethod
    def _parse_whois_rows(cls, reader: Any) -> NRDPage:
        """Parse WHOIS rows and retain source offsets for skipped records."""
        fieldnames = reader.fieldnames
        if not fieldnames:
            return NRDPage([], 0)
        if "domain_name" not in fieldnames:
            raise WhoisFreaksNRDError(
                "WhoisFreaks WHOIS NRD CSV response is missing required 'domain_name' header"
            )

        records: list[NRDRecord] = []
        source_record_count = 0

        for row_number, row in enumerate(reader, start=2):
            if not row or not any(row.values()):
                continue

            domain = (row.get("domain_name") or "").strip()
            if domain.lower() == "domain_name":
                continue

            source_record_count += 1
            if not domain:
                _LOGGER.warning(
                    "Skipping malformed WhoisFreaks NRD CSV row",
                    meta={"row_number": row_number},
                )
                continue

            fields = {
                key: (value or "").strip()
                for key, value in row.items()
                if key is not None
            }

            records.append(
                NRDRecord(
                    domain_name=domain,
                    fields=fields,
                )
            )

        return NRDPage(records, source_record_count)

    @classmethod
    def _parse_domains(cls, payload: str) -> NRDPage:
        """Parse a domains-only NRD page from a complete string."""

        return cls._parse_domain_lines(io.StringIO(payload))

    @staticmethod
    def _parse_domain_lines(lines: Any) -> NRDPage:
        """Parse domain lines while retaining the number of source records."""

        records: list[NRDRecord] = []
        source_record_count = 0

        for line in lines:
            domain = line.strip()

            if not domain:
                continue
            if domain.lower() == "domain_name":
                continue

            source_record_count += 1
            records.append(
                NRDRecord(
                    domain_name=domain,
                    fields={"domain_name": domain},
                )
            )

        return NRDPage(records, source_record_count)

    def _parse_whois_stream(
        self,
        response: requests.Response,
    ) -> NRDPage:
        """Parse a WHOIS-enriched NRD CSV page from a stream."""

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
            return self._parse_whois_rows(reader)
        except (_urllib3_exc.HTTPError, _urllib3_exc.IncompleteRead) as exc:
            raise requests.ConnectionError(
                f"NRD WHOIS stream read failed: {exc}"
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

    def _parse_domains_stream(
        self,
        response: requests.Response,
    ) -> NRDPage:
        """Parse a domains-only NRD page (no CSV header)."""

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
            return self._parse_domain_lines(text_stream)
        except (_urllib3_exc.HTTPError, _urllib3_exc.IncompleteRead) as exc:
            raise requests.ConnectionError(
                f"NRD domains stream read failed: {exc}"
            ) from exc
        finally:
            try:
                if not text_stream.closed:
                    text_stream.detach()
            except ValueError:
                pass
            response.close()

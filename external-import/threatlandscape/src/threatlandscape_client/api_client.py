import time
from typing import Optional

import requests
from pycti import OpenCTIConnectorHelper
from pydantic import HttpUrl


class ThreatLandscapeClient:
    """
    HTTP client for the Threat Landscape REST API.

    Communicates with the PostgREST-based `/stix_bundles` endpoint using
    cursor-based pagination ordered by `seq_id`.
    """

    _BUNDLES_PATH = "/stix_bundles"
    _IOCS_PATH = "/actionable_iocs"

    def __init__(
        self,
        helper: OpenCTIConnectorHelper,
        base_url: HttpUrl,
        api_key: str,
    ) -> None:
        """
        Initialise the client.

        Args:
            helper: OpenCTI connector helper, used for structured logging.
            base_url: Threat Landscape API base URL.
            api_key: API key sent in the ``apikey`` request header.
        """
        self.helper = helper
        self._base_url = str(base_url).rstrip("/")
        self._session = requests.Session()
        self._session.headers.update({"apikey": api_key})

    def _get(self, url: str, params: dict, timeout: int = 60) -> requests.Response:
        """
        GET with automatic retry on 429 Too Many Requests.

        Respects the ``Retry-After`` response header when present; otherwise
        uses exponential backoff starting at 5 seconds (capped at 120 seconds).
        Retries up to 6 times before returning the final response for the
        caller to raise on.
        """
        backoff = 5
        for attempt in range(6):
            response = self._session.get(url, params=params, timeout=timeout)
            if response.status_code != 429:
                return response

            retry_after_header = response.headers.get("Retry-After", str(backoff))
            try:
                retry_after = int(retry_after_header)
            except (TypeError, ValueError):
                retry_after = backoff

            self.helper.connector_logger.warning(
                "Rate limited (429); retrying after delay",
                meta={
                    "retry_after_seconds": retry_after,
                    "attempt": attempt + 1,
                    "status_code": response.status_code,
                },
            )
            time.sleep(retry_after)
            backoff = min(backoff * 2, 120)
        # Final attempt — let caller handle the status.
        return self._session.get(url, params=params, timeout=timeout)

    def get_stix_bundles(
        self,
        *,
        since_seq_id: Optional[int] = None,
        since_date: Optional[str] = None,
        source_type: Optional[str] = None,
        page_size: int = 100,
        offset: int = 0,
    ) -> list[dict]:
        """
        Fetch a page of STIX bundle rows from the API.

        Exactly one of ``since_seq_id`` or ``since_date`` should be provided:

        - ``since_seq_id``: used on subsequent runs — filters ``seq_id=gt.<value>``.
        - ``since_date``: used on the first run — filters
          ``stix_published_at=gte.<ISO-8601 timestamp>``.

        Args:
            since_seq_id: Cursor from the previous run; returns only newer rows.
            since_date: ISO 8601 UTC timestamp; returns bundles published on or after this date.
            source_type: Optional ``osint`` or ``darknet`` filter.
            page_size: Maximum rows to return in this page.
            offset: Zero-based row offset for pagination.

        Returns:
            List of row dicts, each containing at minimum ``seq_id`` and ``stix_bundle``.

        Raises:
            requests.HTTPError: On any non-2xx response.
        """
        if (since_seq_id is None) == (since_date is None):
            raise ValueError("Provide exactly one of since_seq_id or since_date")

        params: dict = {
            "select": "seq_id,stix_bundle",
            "order": "seq_id.asc",
            "limit": page_size,
            "offset": offset,
        }

        if since_seq_id is not None:
            params["seq_id"] = f"gt.{since_seq_id}"
        else:
            params["stix_published_at"] = f"gte.{since_date}"

        if source_type is not None:
            params["source_type"] = f"eq.{source_type}"

        url = self._base_url + self._BUNDLES_PATH

        self.helper.connector_logger.debug(
            "Fetching STIX bundles",
            meta={"url": url, "offset": offset, "page_size": page_size},
        )

        response = self._get(url, params=params)
        response.raise_for_status()

        rows: list[dict] = response.json()

        self.helper.connector_logger.debug(
            "Fetched STIX bundles page",
            meta={"offset": offset, "count": len(rows)},
        )

        return rows

    def get_actionable_iocs(
        self,
        *,
        since_seq_id: Optional[int] = None,
        since_date: Optional[str] = None,
        page_size: int = 100,
        offset: int = 0,
    ) -> list[dict]:
        """
        Fetch a page of IOC rows from the IOC API.

        Exactly one of ``since_seq_id`` or ``since_date`` should be provided:

        - ``since_seq_id``: used on subsequent runs — filters ``seq_id=gt.<value>``.
        - ``since_date``: used on the first run — filters
          ``created_at=gte.<ISO-8601 timestamp>``.

        Args:
            since_seq_id: Cursor from the previous run; returns only newer rows.
            since_date: ISO 8601 UTC timestamp; returns IOCs created on or after this date.
            page_size: Maximum rows to return in this page.
            offset: Zero-based row offset for pagination.

        Returns:
            List of row dicts, each containing at minimum ``seq_id`` and ``stix_bundle``.

        Raises:
            requests.HTTPError: On any non-2xx response.
        """
        if (since_seq_id is None) == (since_date is None):
            raise ValueError("Provide exactly one of since_seq_id or since_date")

        params: dict = {
            "select": "seq_id,stix_bundle",
            "order": "seq_id.asc",
            "limit": page_size,
            "offset": offset,
        }

        if since_seq_id is not None:
            params["seq_id"] = f"gt.{since_seq_id}"
        else:
            params["created_at"] = f"gte.{since_date}"

        url = self._base_url + self._IOCS_PATH

        self.helper.connector_logger.debug(
            "Fetching actionable IOCs",
            meta={"url": url, "offset": offset, "page_size": page_size},
        )

        response = self._get(url, params=params)
        response.raise_for_status()

        rows: list[dict] = response.json()

        self.helper.connector_logger.debug(
            "Fetched actionable IOCs page",
            meta={"offset": offset, "count": len(rows)},
        )

        return rows

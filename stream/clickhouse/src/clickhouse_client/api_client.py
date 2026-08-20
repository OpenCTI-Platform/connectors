"""HTTP client for the ClickHouse HTTP interface."""

from __future__ import annotations

import json
import time
from typing import TYPE_CHECKING, Optional

import requests
from pycti import OpenCTIConnectorHelper

if TYPE_CHECKING:
    from connector.settings import ConnectorSettings


class ClickHouseClient:
    """Thin client around the ClickHouse HTTP interface."""

    REQUEST_ATTEMPTS = 3
    BACKOFF_FACTOR = 5
    TIMEOUT = 30

    def __init__(
        self, config: ConnectorSettings, helper: OpenCTIConnectorHelper
    ) -> None:
        """
        Initialize the ClickHouse client.

        :param config: The connector settings.
        :param helper: The OpenCTI connector helper (used for logging).
        """
        self.helper = helper
        self.config = config.clickhouse

        self._base_url = str(self.config.base_url).rstrip("/")

        self.session = requests.Session()
        self.session.verify = self.config.ssl_verify
        self.session.auth = (
            self.config.username,
            self.config.password.get_secret_value(),
        )

    def ensure_table(self) -> bool:
        """Create the destination database and table if they do not exist yet."""
        if not self.config.create_table:
            return True

        statements = [
            f"CREATE DATABASE IF NOT EXISTS {self.config.database}",
            (
                f"CREATE TABLE IF NOT EXISTS {self._qualified_table()} "
                "(id String, entity_type String, operation String, data String, "
                "event_date DateTime DEFAULT now()) "
                "ENGINE = MergeTree ORDER BY (event_date, id)"
            ),
        ]
        for statement in statements:
            if self._request(params={"query": statement}) is None:
                self.helper.connector_logger.error(
                    "[API] Failed to ensure ClickHouse schema exists",
                    meta={"statement": statement},
                )
                return False
        return True

    def insert_event(
        self, operation: str, data: dict, event_date: Optional[int] = None
    ) -> bool:
        """
        Insert a single OpenCTI stream event into the ClickHouse table.

        :param operation: The stream operation (create, update, delete).
        :param data: The STIX object carried by the stream event.
        :param event_date: The OpenCTI event time as a Unix timestamp (seconds).
            Stored explicitly so the row reflects when the event occurred in
            OpenCTI rather than the ClickHouse server insertion time. Defaults to
            the current time when not provided.
        :return: True if the row was written, False otherwise.
        """
        row = {
            "id": str(data.get("id", "")),
            "entity_type": str(data.get("type", "")),
            "operation": operation,
            "data": json.dumps(data, separators=(",", ":")),
            "event_date": int(event_date if event_date is not None else time.time()),
        }
        query = f"INSERT INTO {self._qualified_table()} FORMAT JSONEachRow"
        response = self._request(
            params={"query": query},
            data=json.dumps(row).encode("utf-8"),
        )
        return response is not None

    def _qualified_table(self) -> str:
        return f"{self.config.database}.{self.config.table}"

    def _request(
        self, params: Optional[dict] = None, data: Optional[bytes] = None
    ) -> Optional[requests.Response]:
        """Perform an HTTP request with retry/backoff on rate limiting and transient errors.

        Retries are applied to 429 responses and to transient network/5xx errors.
        Non-retriable client errors (4xx other than 429, e.g. 401/403 bad credentials
        or 400 bad request) are logged once at error level and return ``None``
        immediately instead of being retried with backoff.
        """
        for attempt in range(self.REQUEST_ATTEMPTS):
            try:
                response = self.session.post(
                    f"{self._base_url}/",
                    params=params,
                    data=data,
                    timeout=self.TIMEOUT,
                )
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
                        "[API] ClickHouse client error, not retrying",
                        meta={"status_code": status_code, "error": str(err)},
                    )
                    return None
                self.helper.connector_logger.warning(
                    "[API] ClickHouse request failed",
                    meta={"error": str(err)},
                )
                if attempt < self.REQUEST_ATTEMPTS - 1:
                    time.sleep(self.BACKOFF_FACTOR * (2**attempt))
            except requests.RequestException as err:
                self.helper.connector_logger.warning(
                    "[API] ClickHouse request failed",
                    meta={"error": str(err)},
                )
                if attempt < self.REQUEST_ATTEMPTS - 1:
                    time.sleep(self.BACKOFF_FACTOR * (2**attempt))
        return None

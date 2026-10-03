"""Log Analytics query API client of the Microsoft Sentinel hunt connector."""

import json
from datetime import datetime, timezone
from typing import Any
from urllib.parse import quote

import requests
from azure.core.credentials import TokenCredential
from azure.core.exceptions import AzureError
from connectors_sdk.connectors.internal_hunt import (
    HuntApiClient,
    HuntExecutionError,
    RunDeadline,
    api_error_message,
)

SERVER_WAIT_MAX_SECONDS = 600
"""Longest server-side execution time the Log Analytics query API accepts."""


def iso_time(value: datetime) -> str:
    """Format a datetime as an ISO 8601 UTC time with milliseconds."""
    utc = value.astimezone(timezone.utc)
    return utc.strftime("%Y-%m-%dT%H:%M:%S.") + f"{utc.microsecond // 1000:03d}Z"


class LogAnalyticsResult:
    """Primary table of a Log Analytics query answer.

    Attributes:
        rows: Rows as dictionaries; ``dynamic`` columns are decoded from JSON.
        partial_error: Message of a partial error (incomplete results), if any.
    """

    def __init__(self, rows: list[dict[str, Any]], partial_error: str | None) -> None:
        """Initialize the result.

        Args:
            rows: Rows of the primary table.
            partial_error: Message of a partial error, or ``None``.
        """
        self.rows = rows
        self.partial_error = partial_error


class LogAnalyticsClient(HuntApiClient):
    """Client of the Log Analytics query API (the data plane of Microsoft Sentinel).

    Every request carries a Microsoft Entra access token for the query API,
    refreshed by the Azure credential when it expires.
    """

    def __init__(
        self,
        api_url: str,
        workspace_id: str,
        credential: TokenCredential,
        additional_workspaces: list[str],
        raw_columns: frozenset[str],
    ) -> None:
        """Initialize the client.

        Args:
            api_url: URL of the Log Analytics query API.
            workspace_id: ID of the Log Analytics workspace.
            credential: Azure credential issuing the access tokens.
            additional_workspaces: Other workspaces queried with the main one.
            raw_columns: Columns holding raw payloads, never decoded.
        """
        super().__init__(base_url=api_url)
        self._scope = f"{api_url.rstrip('/')}/.default"
        self._workspace_id = workspace_id
        self._credential = credential
        self._additional_workspaces = additional_workspaces
        self._raw_columns = {name.lower() for name in raw_columns}

    def _access_token(self) -> str:
        """Return a valid access token for the Log Analytics query API.

        Raises:
            HuntExecutionError: If Microsoft Entra refuses the credentials.
        """
        try:
            return self._credential.get_token(self._scope).token
        except AzureError as err:
            raise HuntExecutionError(
                f"Microsoft Entra authentication failed: {api_error_message(str(err))}"
            ) from err

    def _raw_request(self, method: str, path: str, **kwargs: Any) -> requests.Response:
        """Send a request with a fresh access token."""
        headers = dict(kwargs.pop("headers", None) or {})
        headers["Authorization"] = f"Bearer {self._access_token()}"
        return super()._raw_request(method, path, headers=headers, **kwargs)

    def query(
        self, query: str, start: datetime, end: datetime, deadline: RunDeadline
    ) -> LogAnalyticsResult:
        """Run a KQL query over a time window.

        Args:
            query: KQL query.
            start: Start of the time window.
            end: End of the time window.
            deadline: Run deadline.

        Returns:
            The rows of the primary table and the partial error, if any.

        Raises:
            HuntExecutionError: If Log Analytics rejects the query.
            HuntTimeoutError: If the query does not complete before the deadline.
        """
        body: dict[str, Any] = {
            "query": query,
            "timespan": f"{iso_time(start)}/{iso_time(end)}",
        }
        if self._additional_workspaces:
            body["workspaces"] = list(self._additional_workspaces)
        server_wait = max(1, min(SERVER_WAIT_MAX_SECONDS, int(deadline.remaining())))
        response = self.hunt_request(
            "POST",
            f"/v1/workspaces/{quote(self._workspace_id, safe='')}/query",
            deadline,
            "The Log Analytics query",
            max_timeout=SERVER_WAIT_MAX_SECONDS + 30,
            json=body,
            headers={"Prefer": f"wait={server_wait}"},
        )
        if not isinstance(response, dict):
            raise HuntExecutionError("Log Analytics returned an unexpected answer.")
        tables = response.get("tables") or []
        rows = self._table_rows(tables[0]) if tables else []
        error = response.get("error")
        return LogAnalyticsResult(rows, api_error_message(error) if error else None)

    def _table_rows(self, table: dict[str, Any]) -> list[dict[str, Any]]:
        """Turn a result table into dictionaries, decoding the dynamic columns."""
        columns = [
            (str(column.get("name")), column.get("type"))
            for column in table.get("columns") or []
        ]
        rows: list[dict[str, Any]] = []
        for raw_row in table.get("rows") or []:
            row: dict[str, Any] = {}
            for (name, kind), value in zip(columns, raw_row, strict=False):
                if kind == "dynamic" and name.lower() not in self._raw_columns:
                    value = _decode_dynamic(value)
                row[name] = value
            rows.append(row)
        return rows


def _decode_dynamic(value: Any) -> Any:
    """Decode the JSON text of a dynamic column (kept as text when not JSON)."""
    if not isinstance(value, str) or not value.strip():
        return value
    try:
        return json.loads(value)
    except ValueError:
        return value

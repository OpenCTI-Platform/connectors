"""Log Analytics query API client of the Microsoft Sentinel hunt connector."""

import json
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any
from urllib.parse import quote

import requests
from azure.core.credentials import TokenCredential
from azure.core.exceptions import AzureError
from azure.core.pipeline.transport import RequestsTransport
from connectors_sdk.connectors.internal_hunt import (
    HuntApiClient,
    HuntExecutionError,
    HuntTimeoutError,
    RunDeadline,
    api_error_message,
)

SERVER_WAIT_MAX_SECONDS = 600
"""Longest server-side execution time the Log Analytics query API accepts."""

TOKEN_TIMEOUT_SECONDS = 30.0
"""Longest wait of a single Microsoft Entra token request."""

AUTHENTICATION_OPERATION = "The Microsoft Entra authentication"


class TokenRequestTransport(RequestsTransport):
    """Azure transport of the credential whose token requests are bounded by the run deadline.

    Every request, retries included, waits at most the time left before the run
    deadline (and at most ``TOKEN_TIMEOUT_SECONDS``), and no request is sent once
    the deadline is reached, so a stalled authentication never outlives its run.
    """

    def __init__(self, **kwargs: Any) -> None:
        """Initialize the transport (``RequestsTransport`` options)."""
        super().__init__(**kwargs)
        self._deadline: RunDeadline | None = None

    @property
    def deadline(self) -> RunDeadline | None:
        """Deadline bounding the token requests in progress, if any."""
        return self._deadline

    @contextmanager
    def bounded_by(self, deadline: RunDeadline | None) -> Iterator[None]:
        """Bound the token requests sent in the block by ``deadline``."""
        self._deadline = deadline
        try:
            yield
        finally:
            self._deadline = None

    def send(self, request: Any, **kwargs: Any) -> Any:  # type: ignore[override]
        """Send a token request with a timeout bounded by the run deadline."""
        deadline = self._deadline
        timeout = TOKEN_TIMEOUT_SECONDS
        if deadline is not None:
            timeout = deadline.request_timeout(
                TOKEN_TIMEOUT_SECONDS, AUTHENTICATION_OPERATION
            )
        kwargs["connection_timeout"] = timeout
        kwargs["read_timeout"] = timeout
        return super().send(request, **kwargs)


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
    refreshed by the Azure credential when it expires. Token requests are
    serialized and bounded by the deadline of the run that needs them.
    """

    def __init__(
        self,
        api_url: str,
        workspace_id: str,
        credential: TokenCredential,
        additional_workspaces: list[str],
        raw_columns: frozenset[str],
        token_transport: TokenRequestTransport | None = None,
    ) -> None:
        """Initialize the client.

        Args:
            api_url: URL of the Log Analytics query API.
            workspace_id: ID of the Log Analytics workspace.
            credential: Azure credential issuing the access tokens.
            additional_workspaces: Other workspaces queried with the main one.
            raw_columns: Columns holding raw payloads, never decoded.
            token_transport: Transport the credential sends its token requests
                with, bounded by the run deadline during each token acquisition.
        """
        super().__init__(base_url=api_url)
        self._scope = f"{api_url.rstrip('/')}/.default"
        self._workspace_id = workspace_id
        self._credential = credential
        self._additional_workspaces = additional_workspaces
        self._raw_columns = {name.lower() for name in raw_columns}
        self._token_transport = token_transport
        self._token_lock = threading.Lock()
        self._run = threading.local()

    def _access_token(self, deadline: RunDeadline | None) -> str:
        """Return a valid access token for the Log Analytics query API.

        Args:
            deadline: Deadline of the run needing the token, if any.

        Raises:
            HuntExecutionError: If Microsoft Entra refuses the credentials.
            HuntTimeoutError: If no token is obtained before the deadline.
        """
        with self._token_lock:
            if deadline is not None:
                deadline.check(AUTHENTICATION_OPERATION)
            try:
                if self._token_transport is None:
                    return self._credential.get_token(self._scope).token
                with self._token_transport.bounded_by(deadline):
                    return self._credential.get_token(self._scope).token
            except AzureError as err:
                # Credential chains report the deadline expiry of a member as an authentication error
                if deadline is not None and deadline.expired():
                    raise HuntTimeoutError(
                        f"{AUTHENTICATION_OPERATION} did not complete within the run timeout."
                    ) from err
                raise HuntExecutionError(
                    f"Microsoft Entra authentication failed: {api_error_message(str(err))}"
                ) from err

    def _raw_request(self, method: str, path: str, **kwargs: Any) -> requests.Response:
        """Send a request with a fresh access token."""
        headers = dict(kwargs.pop("headers", None) or {})
        deadline = getattr(self._run, "deadline", None)
        headers["Authorization"] = f"Bearer {self._access_token(deadline)}"
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
        self._run.deadline = deadline
        try:
            response = self.hunt_request(
                "POST",
                f"/v1/workspaces/{quote(self._workspace_id, safe='')}/query",
                deadline,
                "The Log Analytics query",
                max_timeout=SERVER_WAIT_MAX_SECONDS + 30,
                json=body,
                headers={"Prefer": f"wait={server_wait}"},
            )
        except HuntExecutionError as err:
            details = _error_chain(getattr(err.__cause__, "response_body", None))
            if not details:
                raise
            # The class says whether a retry can succeed: a rejected query stays rejected
            raise type(err)(
                f"The Log Analytics query failed ({err.__cause__}): {details}"
            ) from err.__cause__
        finally:
            self._run.deadline = None
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


def _error_chain(body: Any) -> str | None:
    """Join the messages of a Log Analytics error and of its nested inner errors."""
    error = body.get("error") if isinstance(body, dict) else None
    messages: list[str] = []
    while isinstance(error, dict) and len(messages) < 5:
        message = error.get("message")
        if isinstance(message, str) and message.strip():
            messages.append(message.strip())
        error = error.get("innererror")
    return api_error_message(" - ".join(messages)) if messages else None


def _decode_dynamic(value: Any) -> Any:
    """Decode the JSON text of a dynamic column (kept as text when not JSON)."""
    if not isinstance(value, str) or not value.strip():
        return value
    try:
        return json.loads(value)
    except ValueError:
        return value

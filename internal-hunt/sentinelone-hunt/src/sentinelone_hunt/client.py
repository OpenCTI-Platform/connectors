"""Singularity Data Lake query client of the SentinelOne hunt connector."""

import threading
from collections.abc import Hashable, Sequence
from datetime import datetime, timezone
from typing import Any
from urllib.parse import quote

import requests
from connectors_sdk import ApiClientError
from connectors_sdk.connectors.internal_hunt import (
    HuntApiClient,
    HuntExecutionError,
    RunDeadline,
)

QUERIES_PATH = "/sdl/v2/api/queries"
"""Long Running Query API of the console, the PowerQuery path kept after 2027-02-15."""

FORWARD_TAG_HEADER = "X-Dataset-Query-Forward-Tag"
"""Header routing the status and cancellation calls to the node holding the query."""


def iso_time(value: datetime) -> str:
    """Format a datetime as an ISO 8601 UTC time."""
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class QueryResult:
    """Results of a PowerQuery.

    Attributes:
        rows: Rows of the query, as column name to value.
        match_count: Events matched by the initial filter of the query, when
            SentinelOne reports it.
    """

    def __init__(self, rows: list[dict[str, Any]], match_count: int | None) -> None:
        """Initialize the result.

        Args:
            rows: Rows of the query.
            match_count: Events matched by the initial filter.
        """
        self.rows = rows
        self.match_count = match_count


class SentinelOneClient(HuntApiClient):
    """Client of the Long Running Query API of the Singularity Data Lake.

    A PowerQuery is launched over the run window, polled until all its steps
    are done within the run deadline (SentinelOne drops a query not polled for
    30 seconds), then deleted, which also frees the concurrent query budget of
    the account. Only launches are throttled: a launch refused with HTTP 429 is
    retried with backoff within the run deadline.
    """

    def __init__(
        self,
        base_url: str,
        api_token: str,
        account_ids: Sequence[str],
        verify_ssl: bool,
        poll_interval: float,
        logger: Any,
    ) -> None:
        """Initialize the client.

        Args:
            base_url: URL of the management console of the tenant.
            api_token: API token of the service user.
            account_ids: Accounts searched, every reachable account when empty.
            verify_ssl: Whether to verify the TLS certificate.
            poll_interval: Seconds between two status checks of a query.
            logger: Connector logger.
        """
        super().__init__(base_url=base_url, ssl_verify=verify_ssl)
        self._api_token = api_token
        self._account_ids = list(account_ids)
        self._poll_interval = poll_interval
        self._logger = logger
        self._local = threading.local()
        self._queries_lock = threading.Lock()
        self._active_queries: dict[Hashable, tuple[str, str]] = {}

    @property
    def session_headers(self) -> dict[str, str]:
        """Return the authentication header of the service user."""
        return {"Authorization": f"Bearer {self._api_token}"}

    def _raw_request(self, method: str, path: str, **kwargs: Any) -> requests.Response:
        """Send a request and keep the forward tag of its answer for this thread."""
        response = super()._raw_request(method, path, **kwargs)
        self._local.forward_tag = response.headers.get(FORWARD_TAG_HEADER)
        return response

    def _retry_delay(self, method: str, attempt: int, error: Exception) -> float | None:
        """Retry a throttled launch: a launch refused with HTTP 429 started nothing."""
        if (
            method.upper() == "POST"
            and isinstance(error, ApiClientError)
            and error.status_code == 429
        ):
            return super()._retry_delay("GET", attempt, error)
        return super()._retry_delay(method, attempt, error)

    def query(
        self,
        query: str,
        start: datetime,
        end: datetime,
        deadline: RunDeadline,
        job_key: Hashable,
        edr_schema: bool = False,
    ) -> QueryResult:
        """Run a PowerQuery over a time window.

        Args:
            query: PowerQuery.
            start: Start of the time window.
            end: End of the time window.
            deadline: Run deadline.
            job_key: Key of the run, used to cancel its query.
            edr_schema: Whether SentinelOne checks the field names of the query
                against the EDR schema (an unknown field is then refused).

        Returns:
            The rows of the query.

        Raises:
            HuntExecutionError: If SentinelOne rejects the query.
            HuntTimeoutError: If the query does not complete before the deadline.
        """
        body: dict[str, Any] = {
            "queryType": "PQ",
            "startTime": iso_time(start),
            "endTime": iso_time(end),
            "queryPriority": "HIGH",
            "pq": {"query": query, "resultType": "TABLE"},
        }
        if self._account_ids:
            body["tenant"] = False
            body["accountIds"] = list(self._account_ids)
        else:
            body["tenant"] = True
        if edr_schema:
            body["scheme"] = "edr"
        self._local.forward_tag = None
        answer = self.hunt_request(
            "POST", QUERIES_PATH, deadline, "The PowerQuery launch", json=body
        )
        forward_tag = self._local.forward_tag
        query_id = answer.get("id") if isinstance(answer, dict) else None
        if not query_id:
            raise HuntExecutionError("SentinelOne did not return a query id.")
        path = f"{QUERIES_PATH}/{quote(str(query_id), safe='')}"
        if not forward_tag:
            raise HuntExecutionError(
                f"SentinelOne did not return the {FORWARD_TAG_HEADER} header of the query."
            )
        with self._queries_lock:
            self._active_queries[job_key] = (path, forward_tag)
        try:
            return self._wait_for_query(answer, path, forward_tag, deadline)
        finally:
            with self._queries_lock:
                owned = self._active_queries.pop(job_key, None) is not None
            if owned:
                self._delete_query(path, forward_tag)

    def cancel(self, job_key: Hashable) -> None:
        """Delete the running query of a run, if any.

        Args:
            job_key: Key of the run.
        """
        with self._queries_lock:
            active = self._active_queries.pop(job_key, None)
        if active is not None:
            self._delete_query(*active)

    def _wait_for_query(
        self, answer: Any, path: str, forward_tag: str, deadline: RunDeadline
    ) -> QueryResult:
        """Poll a query until all its steps are done (small queries end at launch)."""
        while True:
            if not isinstance(answer, dict):
                raise HuntExecutionError("SentinelOne returned an unexpected answer.")
            completed = _int(answer.get("stepsCompleted"))
            total = _int(answer.get("stepsTotal"))
            if total > 0 and completed >= total:
                return _query_result(answer)
            deadline.check("The PowerQuery")
            deadline.sleep(self._poll_interval)
            answer = self.hunt_request(
                "GET",
                path,
                deadline,
                "The PowerQuery status",
                params={"lastStepSeen": completed},
                headers={FORWARD_TAG_HEADER: forward_tag},
            )

    def _delete_query(self, path: str, forward_tag: str) -> None:
        """Delete a query (best effort, SentinelOne also drops unpolled queries)."""
        error = self.cleanup_request(
            "DELETE",
            path,
            "The PowerQuery deletion",
            headers={FORWARD_TAG_HEADER: forward_tag},
        )
        if error:
            self._logger.warning(error, {"query": path})


def _int(value: Any) -> int:
    """Return an integer step counter, 0 when missing or invalid."""
    if isinstance(value, bool):
        return 0
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _query_result(answer: dict[str, Any]) -> QueryResult:
    """Read the rows of a completed query (``data.columns`` and ``data.values``)."""
    data = answer.get("data")
    if not isinstance(data, dict):
        data = {}
    columns = [
        str(column.get("name") or "") if isinstance(column, dict) else str(column)
        for column in data.get("columns") or []
    ]
    rows = [
        dict(zip(columns, values))
        for values in data.get("values") or []
        if isinstance(values, list)
    ]
    match_count = data.get("matchCount", answer.get("matchCount"))
    return QueryResult(
        rows,
        (
            int(match_count)
            if isinstance(match_count, (int, float))
            and not isinstance(match_count, bool)
            else None
        ),
    )

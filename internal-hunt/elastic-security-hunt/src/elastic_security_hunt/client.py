"""Elasticsearch client running hunt queries in ES|QL, EQL and Lucene."""

import base64
import threading
from collections.abc import Hashable
from datetime import datetime, timezone
from typing import Any
from urllib.parse import quote

import requests
from connectors_sdk.connectors.internal_hunt import (
    HuntApiClient,
    HuntExecutionError,
    RunDeadline,
)

MAX_RESULT_WINDOW = 10000
"""Largest number of results Elasticsearch returns by default (``index.max_result_window``)."""

LONG_POLL_SECONDS = 30
"""Longest time an async search request waits for the search to complete."""

ASYNC_KEEP_ALIVE = "10m"
"""Lifetime of an async search kept on the cluster (cleaned up when the run ends)."""

COUNT_COLUMN = "opencti_hit_count"


def iso_time(value: datetime) -> str:
    """Format a datetime as an ISO 8601 UTC time with milliseconds."""
    utc = value.astimezone(timezone.utc)
    return utc.strftime("%Y-%m-%dT%H:%M:%S.") + f"{utc.microsecond // 1000:03d}Z"


class SearchResult:
    """Results of a hunt query.

    Attributes:
        rows: Matching documents (``_source``) or ES|QL rows.
        total: Total number of matches.
        partial: True when Elasticsearch flagged the results as partial.
    """

    def __init__(self, rows: list[dict[str, Any]], total: int, partial: bool) -> None:
        """Initialize the result.

        Args:
            rows: Matching documents or rows.
            total: Total number of matches.
            partial: Whether the results are partial.
        """
        self.rows = rows
        self.total = total
        self.partial = partial


class ElasticsearchClient(HuntApiClient):
    """Client of the Elasticsearch search APIs used by hunts.

    ES|QL and EQL queries run as async searches: they are long-polled within the
    run deadline and deleted from the cluster when the run ends or times out.
    Lucene queries run as plain searches.
    """

    def __init__(
        self,
        base_url: str,
        api_key: str | None,
        username: str | None,
        password: str | None,
        verify_ssl: bool,
        ca_cert: str | None,
        timestamp_field: str,
        logger: Any,
    ) -> None:
        """Initialize the client.

        Args:
            base_url: URL of the Elasticsearch cluster.
            api_key: Encoded API key (takes precedence).
            username: User name (basic authentication).
            password: Password (basic authentication).
            verify_ssl: Whether to verify the TLS certificate.
            ca_cert: Path to a CA bundle verifying the certificate.
            timestamp_field: Field holding the event time.
            logger: Connector logger.
        """
        super().__init__(base_url=base_url, ssl_verify=verify_ssl)
        self._api_key = api_key
        self._username = username
        self._password = password
        self._verify: bool | str = ca_cert if verify_ssl and ca_cert else verify_ssl
        self._timestamp_field = timestamp_field
        self._logger = logger
        self._lock = threading.Lock()
        self._active_searches: dict[Hashable, str] = {}

    @property
    def session_headers(self) -> dict[str, str]:
        """Return the authentication header (API key, or basic authentication)."""
        if self._api_key:
            return {"Authorization": f"ApiKey {self._api_key}"}
        credentials = f"{self._username}:{self._password}".encode()
        return {"Authorization": f"Basic {base64.b64encode(credentials).decode()}"}

    def _raw_request(self, method: str, path: str, **kwargs: Any) -> requests.Response:
        """Send a request verifying the certificate with the configured CA bundle."""
        kwargs.setdefault("verify", self._verify)
        return super()._raw_request(method, path, **kwargs)

    def time_filter(self, start: datetime, end: datetime) -> dict[str, Any]:
        """Return the query DSL filter restricting a search to a time window."""
        return {
            "range": {
                self._timestamp_field: {
                    "gte": iso_time(start),
                    "lte": iso_time(end),
                    "format": "strict_date_optional_time",
                }
            }
        }

    # ------------------------------------------------------------------
    # ES|QL
    # ------------------------------------------------------------------

    def esql(
        self,
        query: str,
        start: datetime,
        end: datetime,
        max_results: int,
        deadline: RunDeadline,
        job_key: Hashable,
    ) -> SearchResult:
        """Run an ES|QL query over a time window.

        Args:
            query: ES|QL query (starting with ``from``).
            start: Start of the time window.
            end: End of the time window.
            max_results: Maximum number of rows to fetch.
            deadline: Run deadline.
            job_key: Key of the run, used to cancel its search.

        Returns:
            The rows and the total number of matches.

        Raises:
            HuntExecutionError: If Elasticsearch rejects the query.
            HuntTimeoutError: If the query does not complete before the deadline.
        """
        cap = min(max_results, MAX_RESULT_WINDOW)
        answer = self._esql_rows(
            f"{query}\n| limit {cap}", start, end, deadline, job_key
        )
        rows = esql_rows(answer)
        total = len(rows)
        partial = bool(answer.get("is_partial"))
        if total >= cap:
            counted = self._esql_rows(
                f"{query}\n| stats {COUNT_COLUMN} = count(*)",
                start,
                end,
                deadline,
                job_key,
            )
            count_rows = esql_rows(counted)
            value = count_rows[0].get(COUNT_COLUMN) if count_rows else None
            partial = partial or bool(counted.get("is_partial"))
            if _usable_count(value, total):
                total = int(value)
            else:
                # A full page without a usable count (missing, not a number or
                # below the page size) cannot prove that every match was
                # returned: the page size is kept as a lower bound.
                partial = True
        return SearchResult(rows, total, partial)

    def _esql_rows(
        self,
        query: str,
        start: datetime,
        end: datetime,
        deadline: RunDeadline,
        job_key: Hashable,
    ) -> dict[str, Any]:
        """Run one ES|QL async query and return its completed answer."""
        return self._async_search(
            "/_query/async",
            "/_query/async",
            {"query": query, "filter": self.time_filter(start, end)},
            deadline,
            job_key,
            "The ES|QL query",
        )

    # ------------------------------------------------------------------
    # EQL
    # ------------------------------------------------------------------

    def eql(
        self,
        indices: list[str],
        query: str,
        start: datetime,
        end: datetime,
        max_results: int,
        deadline: RunDeadline,
        job_key: Hashable,
    ) -> SearchResult:
        """Run an EQL query over a time window.

        Args:
            indices: Index patterns to search.
            query: EQL query.
            start: Start of the time window.
            end: End of the time window.
            max_results: Maximum number of events or sequences to fetch.
            deadline: Run deadline.
            job_key: Key of the run, used to cancel its search.

        Returns:
            The matching events and the total number of matches.

        Raises:
            HuntExecutionError: If Elasticsearch rejects the query.
            HuntTimeoutError: If the query does not complete before the deadline.
        """
        cap = min(max_results, MAX_RESULT_WINDOW)
        answer = self._async_search(
            f"/{index_path(indices)}/_eql/search",
            "/_eql/search",
            {
                "query": query,
                "filter": self.time_filter(start, end),
                "size": cap,
                "timestamp_field": self._timestamp_field,
            },
            deadline,
            job_key,
            "The EQL query",
            params={"ignore_unavailable": "true", "allow_no_indices": "true"},
        )
        hits = answer.get("hits") or {}
        events = list(hits.get("events") or [])
        sequences = hits.get("sequences") or []
        for sequence in sequences:
            events.extend(sequence.get("events") or [])
        rows = [_source(event) for event in events]
        total, relation = _total(hits, len(sequences) or len(rows))
        if sequences:
            # hits.total counts sequences while the result reports their events: every fetched event is a hit
            total = max(total, len(rows))
        # Sequences can hold more events than the cap: the events cut here make the result partial
        partial = (
            bool(answer.get("is_partial"))
            or relation == "gte"
            or len(rows) > max_results
        )
        return SearchResult(rows[:max_results], total, partial)

    # ------------------------------------------------------------------
    # Lucene
    # ------------------------------------------------------------------

    def lucene(
        self,
        indices: list[str],
        query: str,
        start: datetime,
        end: datetime,
        max_results: int,
        deadline: RunDeadline,
    ) -> SearchResult:
        """Run a Lucene query string search over a time window.

        Args:
            indices: Index patterns to search.
            query: Lucene query string.
            start: Start of the time window.
            end: End of the time window.
            max_results: Maximum number of documents to fetch.
            deadline: Run deadline.

        Returns:
            The most recent matching documents and the total number of matches.

        Raises:
            HuntExecutionError: If Elasticsearch rejects the query.
            HuntTimeoutError: If the search does not complete before the deadline.
        """
        body = {
            "query": {
                "bool": {
                    "must": [{"query_string": {"query": query}}],
                    "filter": [self.time_filter(start, end)],
                }
            },
            "size": min(max_results, MAX_RESULT_WINDOW),
            "track_total_hits": True,
            "sort": [
                {
                    self._timestamp_field: {
                        "order": "desc",
                        "unmapped_type": "date",
                    }
                }
            ],
        }
        answer = self.hunt_request(
            "POST",
            f"/{index_path(indices)}/_search",
            deadline,
            "The Elasticsearch search",
            json=body,
            params={"ignore_unavailable": "true", "allow_no_indices": "true"},
        )
        if not isinstance(answer, dict):
            raise HuntExecutionError("Elasticsearch returned an unexpected answer.")
        hits = answer.get("hits") or {}
        rows = [_source(hit) for hit in hits.get("hits") or []]
        total, relation = _total(hits, len(rows))
        shards = answer.get("_shards") or {}
        partial = (
            bool(answer.get("timed_out"))
            or bool(shards.get("failed"))
            or relation == "gte"
        )
        return SearchResult(rows, total, partial)

    # ------------------------------------------------------------------
    # Async searches
    # ------------------------------------------------------------------

    def cancel(self, job_key: Hashable) -> None:
        """Delete the running async search of a run, if any.

        Args:
            job_key: Key of the run.
        """
        with self._lock:
            path = self._active_searches.pop(job_key, None)
        if path is not None:
            self._delete_search(path)

    def _async_search(
        self,
        submit_path: str,
        status_path: str,
        body: dict[str, Any],
        deadline: RunDeadline,
        job_key: Hashable,
        operation: str,
        params: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """Submit an async search, long-poll it until done, then delete it."""
        answer = self.hunt_request(
            "POST",
            submit_path,
            deadline,
            operation,
            max_timeout=LONG_POLL_SECONDS + 30,
            json={
                **body,
                "wait_for_completion_timeout": _wait(deadline),
                "keep_alive": ASYNC_KEEP_ALIVE,
            },
            params=params,
        )
        answer = _as_dict(answer)
        search_id = answer.get("id") if answer.get("is_running") else None
        if search_id is None:
            return answer
        path = f"{status_path}/{quote(str(search_id), safe='')}"
        with self._lock:
            self._active_searches[job_key] = path
        try:
            while answer.get("is_running"):
                answer = _as_dict(
                    self.hunt_request(
                        "GET",
                        path,
                        deadline,
                        operation,
                        max_timeout=LONG_POLL_SECONDS + 30,
                        params={"wait_for_completion_timeout": _wait(deadline)},
                    )
                )
            return answer
        finally:
            with self._lock:
                owned = self._active_searches.pop(job_key, None) is not None
            if owned:
                self._delete_search(path)

    def _delete_search(self, path: str) -> None:
        """Delete an async search (best effort, its keep-alive also cleans it)."""
        error = self.cleanup_request("DELETE", path, "The async search deletion")
        if error:
            self._logger.warning(error, {"search": path})


def index_path(indices: list[str]) -> str:
    """Return the URL path segment of a list of index patterns."""
    return quote(",".join(indices), safe=",*-_.:")


def esql_rows(answer: dict[str, Any]) -> list[dict[str, Any]]:
    """Turn the columns and values of an ES|QL answer into dictionaries."""
    names = [str(column.get("name")) for column in answer.get("columns") or []]
    return [
        dict(zip(names, values, strict=False)) for values in answer.get("values") or []
    ]


def _usable_count(value: Any, page_size: int) -> bool:
    """Tell whether a count answer can be the total of a full page of rows."""
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and value >= page_size
    )


def _source(hit: dict[str, Any]) -> dict[str, Any]:
    """Return the source document of a search hit or EQL event."""
    source = hit.get("_source")
    return dict(source) if isinstance(source, dict) else {}


def _total(hits: dict[str, Any], default: int) -> tuple[int, str]:
    """Return the total number of hits and its relation (``eq`` or ``gte``)."""
    total = hits.get("total")
    if isinstance(total, dict) and isinstance(total.get("value"), int):
        return max(total["value"], default), str(total.get("relation") or "eq")
    return default, "eq"


def _wait(deadline: RunDeadline) -> str:
    """Return the long-poll duration of an async search request."""
    return f"{max(1, min(LONG_POLL_SECONDS, int(deadline.remaining()) - 1))}s"


def _as_dict(answer: Any) -> dict[str, Any]:
    """Check that an answer is a JSON object."""
    if not isinstance(answer, dict):
        raise HuntExecutionError("Elasticsearch returned an unexpected answer.")
    return answer

"""OpenSearch client running hunt queries in PPL and Lucene."""

import base64
from datetime import datetime, timezone
from typing import Any
from urllib.parse import quote

import requests
from connectors_sdk.client.exceptions import ApiClientError
from connectors_sdk.connectors.internal_hunt import (
    HuntApiClient,
    HuntExecutionError,
    RunDeadline,
    api_error_message,
)

MAX_RESULTS = 10000
"""Largest number of results OpenSearch returns by default (``index.max_result_window``)."""

COUNT_COLUMN = "opencti_hit_count"

PPL_PATH = "/_plugins/_ppl"


def epoch_ms(value: datetime) -> int:
    """Return a datetime as milliseconds since the epoch."""
    return int(value.timestamp() * 1000)


def iso_time(value: datetime) -> str:
    """Format a datetime as an ISO 8601 UTC time with milliseconds."""
    utc = value.astimezone(timezone.utc)
    return utc.strftime("%Y-%m-%dT%H:%M:%S.") + f"{utc.microsecond // 1000:03d}Z"


class SearchResult:
    """Results of a hunt query.

    Attributes:
        rows: Matching documents (``_source``) or PPL rows.
        total: Total number of matches.
        partial: True when OpenSearch flagged the results as partial.
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


class OpenSearchClient(HuntApiClient):
    """Client of the OpenSearch search and PPL APIs used by hunts."""

    def __init__(
        self,
        base_url: str,
        username: str | None,
        password: str | None,
        verify_ssl: bool,
        ca_cert: str | None,
        timestamp_field: str,
        timestamp_format: str,
    ) -> None:
        """Initialize the client.

        Args:
            base_url: URL of the OpenSearch cluster.
            username: User name (basic authentication), or ``None``.
            password: Password (basic authentication), or ``None``.
            verify_ssl: Whether to verify the TLS certificate.
            ca_cert: Path to a CA bundle verifying the certificate.
            timestamp_field: Field holding the event time.
            timestamp_format: ``epoch_millis`` or ``date``.
        """
        super().__init__(base_url=base_url, ssl_verify=verify_ssl)
        self._username = username
        self._password = password
        self._verify: bool | str = ca_cert if verify_ssl and ca_cert else verify_ssl
        self._timestamp_field = timestamp_field
        self._epoch = timestamp_format == "epoch_millis"

    @property
    def session_headers(self) -> dict[str, str]:
        """Return the basic authentication header, when credentials are set."""
        if not self._username:
            return {}
        credentials = f"{self._username}:{self._password}".encode()
        return {"Authorization": f"Basic {base64.b64encode(credentials).decode()}"}

    def _raw_request(self, method: str, path: str, **kwargs: Any) -> requests.Response:
        """Send a request verifying the certificate with the configured CA bundle."""
        kwargs.setdefault("verify", self._verify)
        return super()._raw_request(method, path, **kwargs)

    # ------------------------------------------------------------------
    # PPL
    # ------------------------------------------------------------------

    def ppl_time_condition(self, start: datetime, end: datetime) -> str:
        """Return the PPL condition restricting a query to a time window."""
        field = f"`{self._timestamp_field}`"
        if self._epoch:
            low, high = str(epoch_ms(start)), str(epoch_ms(end))
        else:
            low = f"timestamp('{_ppl_time(start)}')"
            high = f"timestamp('{_ppl_time(end)}')"
        return f"{field} >= {low} and {field} <= {high}"

    def ppl(
        self,
        query: str,
        start: datetime,
        end: datetime,
        max_results: int,
        deadline: RunDeadline,
    ) -> SearchResult:
        """Run a PPL query over a time window.

        Args:
            query: PPL query (starting with ``source=``).
            start: Start of the time window.
            end: End of the time window.
            max_results: Maximum number of rows to fetch.
            deadline: Run deadline.

        Returns:
            The rows and the total number of matches.

        Raises:
            HuntExecutionError: If OpenSearch rejects the query.
            HuntTimeoutError: If the query does not complete before the deadline.
        """
        filtered = with_where(query, self.ppl_time_condition(start, end))
        cap = min(max_results, MAX_RESULTS)
        rows = ppl_rows(self._ppl(f"{filtered} | head {cap}", deadline))
        total = len(rows)
        if rows:
            counted = ppl_rows(
                self._ppl(f"{filtered} | stats count() as {COUNT_COLUMN}", deadline)
            )
            value = counted[0].get(COUNT_COLUMN) if counted else None
            if isinstance(value, (int, float)):
                total = max(total, int(value))
        return SearchResult(rows, total, False)

    def _ppl(self, query: str, deadline: RunDeadline) -> dict[str, Any]:
        """Run one PPL query and return its answer."""
        try:
            answer = self.hunt_request(
                "POST", PPL_PATH, deadline, "The PPL query", json={"query": query}
            )
        except HuntExecutionError as err:
            details = _ppl_error_details(err.__cause__)
            if details is None:
                raise
            raise HuntExecutionError(f"{err} - {details}") from err
        if not isinstance(answer, dict):
            raise HuntExecutionError("OpenSearch returned an unexpected answer.")
        return answer

    # ------------------------------------------------------------------
    # Lucene
    # ------------------------------------------------------------------

    def time_filter(self, start: datetime, end: datetime) -> dict[str, Any]:
        """Return the query DSL filter restricting a search to a time window."""
        if self._epoch:
            bounds: dict[str, Any] = {"gte": epoch_ms(start), "lte": epoch_ms(end)}
        else:
            bounds = {
                "gte": iso_time(start),
                "lte": iso_time(end),
                "format": "strict_date_optional_time",
            }
        return {"range": {self._timestamp_field: bounds}}

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
            HuntExecutionError: If OpenSearch rejects the query.
            HuntTimeoutError: If the search does not complete before the deadline.
        """
        body = {
            "query": {
                "bool": {
                    "must": [{"query_string": {"query": query}}],
                    "filter": [self.time_filter(start, end)],
                }
            },
            "size": min(max_results, MAX_RESULTS),
            "track_total_hits": True,
            "sort": [
                {
                    self._timestamp_field: {
                        "order": "desc",
                        "unmapped_type": "long" if self._epoch else "date",
                    }
                }
            ],
        }
        answer = self.hunt_request(
            "POST",
            f"/{index_path(indices)}/_search",
            deadline,
            "The OpenSearch search",
            json=body,
            params={"ignore_unavailable": "true", "allow_no_indices": "true"},
        )
        if not isinstance(answer, dict):
            raise HuntExecutionError("OpenSearch returned an unexpected answer.")
        hits = answer.get("hits") or {}
        rows = [_source(hit) for hit in hits.get("hits") or []]
        total = hits.get("total")
        count = total.get("value") if isinstance(total, dict) else None
        shards = answer.get("_shards") or {}
        partial = bool(answer.get("timed_out")) or bool(shards.get("failed"))
        return SearchResult(
            rows,
            max(count, len(rows)) if isinstance(count, int) else len(rows),
            partial,
        )


def with_where(query: str, condition: str) -> str:
    """Insert a ``where`` command right after the ``source`` command of a PPL query."""
    head, rest = _split_first_command(query.strip().rstrip(";").rstrip())
    return f"{head} | where {condition}" + (f" {rest}" if rest else "")


def _split_first_command(query: str) -> tuple[str, str]:
    """Split a PPL query at its first pipe outside quotes and backticks."""
    quote_char: str | None = None
    for index, char in enumerate(query):
        if quote_char:
            if char == quote_char:
                quote_char = None
        elif char in "'\"`":
            quote_char = char
        elif char == "|":
            return query[:index].rstrip(), query[index:]
    return query, ""


def ppl_rows(answer: dict[str, Any]) -> list[dict[str, Any]]:
    """Turn the schema and data rows of a PPL answer into dictionaries."""
    names = [str(column.get("name")) for column in answer.get("schema") or []]
    return [
        dict(zip(names, values, strict=False))
        for values in answer.get("datarows") or []
    ]


def index_path(indices: list[str]) -> str:
    """Return the URL path segment of a list of index patterns."""
    return quote(",".join(indices), safe=",*-_.:")


def _ppl_time(value: datetime) -> str:
    """Format a datetime as a PPL timestamp literal (UTC)."""
    return value.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def _ppl_error_details(cause: BaseException | None) -> str | None:
    """Return the details of a PPL error (the reason alone is often 'Invalid Query')."""
    if not isinstance(cause, ApiClientError) or not isinstance(
        cause.response_body, dict
    ):
        return None
    error = cause.response_body.get("error")
    details = error.get("details") if isinstance(error, dict) else None
    return api_error_message(details) if details else None


def _source(hit: dict[str, Any]) -> dict[str, Any]:
    """Return the source document of a search hit."""
    source = hit.get("_source")
    return dict(source) if isinstance(source, dict) else {}

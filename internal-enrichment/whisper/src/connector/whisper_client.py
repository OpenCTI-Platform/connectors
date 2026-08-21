import logging
from dataclasses import dataclass, field
from typing import Any

import requests
from connector.exceptions import (
    WhisperAuthError,
    WhisperQueryError,
    WhisperTransportError,
)
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 30.0
DEFAULT_MAX_RETRIES = 3
DEFAULT_BACKOFF = 0.5
CYPHER_PATH = "/api/query"


@dataclass(frozen=True)
class CypherResult:
    """One execution of a Cypher query against the Whisper graph.

    `columns` is the ordered list of RETURN aliases (e.g. ["n", "r", "m"]).
    The result parser needs this to pair edges with their surrounding nodes.
    """

    columns: list[str]
    rows: list[dict[str, Any]]
    statistics: dict[str, Any] = field(default_factory=dict)


class _RateLimitLoggingRetry(Retry):
    """``urllib3.Retry`` subclass that emits one info-level log per 429.

    urllib3 logs retries at WARN by default, which is too coarse for an
    enrichment connector — when Whisper rate-limits, ops want to see it
    at info so they can correlate spikes with quota windows without
    cranking urllib3's whole logger up. Only 429s log here; 5xx retries
    stay on urllib3's default channel.
    """

    def increment(  # type: ignore[override]
        self,
        method=None,
        url=None,
        response=None,
        error=None,
        _pool=None,
        _stacktrace=None,
    ) -> "_RateLimitLoggingRetry":
        if response is not None and getattr(response, "status", None) == 429:
            retry_after = None
            try:
                retry_after = response.headers.get("Retry-After")
            except AttributeError:
                pass
            # ``self.total`` is the retry budget on the current instance and is
            # decremented by ``super().increment()``; clamp so the log never
            # shows a negative count near exhaustion.
            remaining = max(0, self.total - 1) if isinstance(self.total, int) else "?"
            logger.info(
                "Whisper API rate-limited (HTTP 429); retrying "
                "(Retry-After=%s, retries_remaining=%s)",
                retry_after,
                remaining,
            )
        return super().increment(method, url, response, error, _pool, _stacktrace)


class WhisperClient:
    """HTTP client for the Whisper graph API.

    Executes Cypher queries with API-key authentication. Retries 5xx,
    429 (rate-limit, honouring ``Retry-After`` when present), and
    transport errors with exponential backoff. Never retries other 4xx.
    """

    def __init__(
        self,
        api_url: str,
        api_key: str,
        timeout: float = DEFAULT_TIMEOUT,
        verify_ssl: bool = True,
        max_retries: int = DEFAULT_MAX_RETRIES,
        backoff_factor: float = DEFAULT_BACKOFF,
    ) -> None:
        if not api_url:
            raise ValueError("api_url is required")
        if not api_key:
            raise ValueError("api_key is required")
        self.api_url = api_url.rstrip("/")
        self._api_key = api_key
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self._session = self._build_session(max_retries, backoff_factor)

    @staticmethod
    def _build_session(max_retries: int, backoff_factor: float) -> requests.Session:
        # ``respect_retry_after_header`` defaults to True, and 429 is in
        # ``Retry.RETRY_AFTER_STATUS_CODES`` by default, so Whisper's
        # ``Retry-After`` is honoured automatically when present. With no
        # header, urllib3 falls back to the exponential backoff configured
        # via ``backoff_factor``. ``total=max_retries`` (3 by default) caps
        # the worst-case hang at roughly 3 × max(backoff, Retry-After) —
        # for the common Whisper case of ``Retry-After: 60`` that's about
        # three minutes, which we judged the right ceiling for an
        # interactive enrichment work item (issue #30).
        retries = _RateLimitLoggingRetry(
            total=max_retries,
            backoff_factor=backoff_factor,
            status_forcelist=(429, 500, 502, 503, 504),
            allowed_methods=frozenset(["POST"]),
            raise_on_status=False,
        )
        adapter = HTTPAdapter(max_retries=retries)
        session = requests.Session()
        session.mount("https://", adapter)
        session.mount("http://", adapter)
        return session

    def _headers(self) -> dict[str, str]:
        return {
            "X-API-Key": self._api_key,
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    def execute_cypher(
        self,
        query: str,
        params: dict[str, Any] | None = None,
    ) -> CypherResult:
        """Execute a Cypher query and return the parsed result.

        Whisper returns a JSON body of shape
        ``{"success": bool, "columns": [...], "rows": [...], "statistics": {...}}``.
        Each row is a dict keyed by RETURN alias; cell values are either node
        objects (``{nodeId, label, name, ...}``) or edge objects (``{type, ...}``).
        """
        url = f"{self.api_url}{CYPHER_PATH}"
        payload: dict[str, Any] = {"query": query, "params": params or {}}
        logger.debug(
            "whisper request url=%s param_keys=%s", url, list(payload["params"].keys())
        )

        try:
            response = self._session.post(
                url,
                json=payload,
                headers=self._headers(),
                timeout=self.timeout,
                verify=self.verify_ssl,
            )
        except requests.RequestException as exc:
            raise WhisperTransportError(
                f"transport error contacting Whisper API: {exc}"
            ) from exc

        if response.status_code in (401, 403):
            raise WhisperAuthError(
                f"Whisper API rejected the API key (HTTP {response.status_code})"
            )
        if response.status_code == 429:
            # urllib3 already retried up to ``total`` times honouring
            # Retry-After. A 429 still landing here means Whisper is hard-
            # throttling us; raise transport (not query) so QA / the work
            # item triage treats it as a quota incident rather than a
            # malformed-Cypher bug. Issue #30.
            raise WhisperTransportError(
                "Whisper API rate-limited (HTTP 429) after retries"
            )
        if response.status_code >= 500:
            raise WhisperTransportError(
                f"Whisper API returned HTTP {response.status_code} after retries"
            )
        if response.status_code >= 400:
            body_snippet = response.text[:500]
            raise WhisperQueryError(
                f"Whisper API query error (HTTP {response.status_code}): {body_snippet}"
            )

        try:
            body = response.json()
        except ValueError as exc:
            raise WhisperQueryError(
                f"Whisper API returned non-JSON body: {exc}"
            ) from exc

        if body.get("success") is False:
            raise WhisperQueryError(
                f"Whisper API returned success=false: {body.get('error', body)!r}"
            )

        rows = body.get("rows", [])
        if not isinstance(rows, list):
            raise WhisperQueryError(
                f"Whisper API returned unexpected 'rows' shape: {type(rows).__name__}"
            )
        columns = body.get("columns") or []
        if not isinstance(columns, list):
            raise WhisperQueryError(
                f"Whisper API returned unexpected 'columns' shape: {type(columns).__name__}"
            )
        statistics = body.get("statistics") or {}
        if not isinstance(statistics, dict):
            statistics = {}
        return CypherResult(columns=columns, rows=rows, statistics=statistics)

    def close(self) -> None:
        self._session.close()

    def __enter__(self) -> "WhisperClient":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

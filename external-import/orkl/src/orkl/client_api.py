"""ORKL API client using the SDK BaseClientApi."""

from __future__ import annotations

from collections.abc import Generator
from typing import Any

from connectors_sdk import ApiClientError, BaseClientApi, ConnectorLogger

# ORKL (https://orkl.eu) publishes no documented request quota, so this
# client relies on a two-layer defensive strategy:
#
# - Throttling (RATE_LIMIT) is proactive, self-imposed pacing applied to
#   every outgoing request regardless of how the server responds, so we
#   never come close to triggering a limit in the first place.
# - Backoff (MAX_RETRIES / BACKOFF_FACTOR) is reactive: it only kicks in
#   after the server has already pushed back (408/429/5xx), applying an
#   exponential delay that honours any `Retry-After` header, capped at
#   MAX_RETRIES attempts before the run fails cleanly.
PAGE_SIZE = 100  # API-capped maximum
RATE_LIMIT = "1/second"  # proactive, self-imposed throttle
MAX_RETRIES = 5  # 408/429/5xx, honours Retry-After
BACKOFF_FACTOR = 2.0
TIMEOUT = 60
# ORKL holds ~29,500 library entries at the time of writing. At the
# API-capped PAGE_SIZE of 100, a full backfill is therefore ~295 pages.
# MAX_PAGES is set an order of magnitude above that so a legitimate full
# backfill can never come close to hitting it -- it exists purely as a
# last-line-of-defence circuit breaker against a misbehaving or
# static/cached server that keeps returning full pages forever (see
# `iter_library_entries`). If ORKL's corpus grows substantially, resize
# this constant accordingly.
MAX_PAGES = 1000
# https://orkl.eu/llms.txt asks clients to send a descriptive User-Agent so
# the ORKL maintainers can contact us if this client misbehaves. This is a
# stated requirement, not a nicety.
USER_AGENT = (
    "OpenCTI-ORKL-Connector/1.0 (+https://github.com/OpenCTI-Platform/connectors)"
)


class OrklClient(BaseClientApi):
    """HTTP client for the ORKL library API.

    ORKL (https://orkl.eu) is a free, public, unauthenticated CTI report
    library. No auth header is sent.

    Reference:
        https://orkl.eu/api/v1
    """

    def __init__(
        self, base_url: str, *, logger: ConnectorLogger | None = None, **kwargs: Any
    ) -> None:
        """Initialize the client, applying ORKL-specific defaults.

        The module-level constants are applied via ``setdefault`` so callers
        (and tests) can still override them explicitly.

        Args:
            base_url: ORKL API base URL.
            logger: Optional ``ConnectorLogger`` used for pagination warnings.
                When omitted the client stays silent. ``BaseClientApi`` accepts
                no ``logger`` kwarg, so it is consumed here and not forwarded.
        """
        self._logger = logger
        kwargs.setdefault("rate_limit", RATE_LIMIT)
        kwargs.setdefault("max_retries", MAX_RETRIES)
        kwargs.setdefault("backoff_factor", BACKOFF_FACTOR)
        kwargs.setdefault("timeout", TIMEOUT)
        # The SDK defaults `raise_on_limit_exceeded` to True, which treats our
        # own self-imposed rate limit as a tripwire: as soon as the window is
        # exceeded it raises `ApiRateLimitError` instead of pacing requests,
        # which would abort any backfill on page 2. Setting it to False makes
        # the adapter sleep until the window resets instead, which is the
        # throttling behaviour we actually want.
        kwargs.setdefault("raise_on_limit_exceeded", False)
        super().__init__(base_url, **kwargs)

    @property
    def session_headers(self) -> dict[str, str]:
        """Return the descriptive User-Agent header. No auth is required."""
        return {"User-Agent": USER_AGENT}

    def _warn(self, message: str, meta: dict[str, Any]) -> None:
        """Emit a warning only when a logger was supplied; stay silent otherwise."""
        if self._logger is not None:
            self._logger.warning(message, meta)

    def _parse_response(self, response: Any) -> Any:
        """Unwrap the ORKL ``{"data", "message", "status"}`` envelope.

        Delegates to the base class first (so Content-Type parsing still
        applies), then raises `ApiClientError` on a non-``success`` status and
        returns the ``data`` payload. Non-enveloped responses pass through.

        Note: ``data`` may legitimately be ``None`` (ORKL's empty-list sentinel
        for list endpoints); normalising that into ``[]`` is the caller's job.
        """
        result = super()._parse_response(response)

        if isinstance(result, dict):
            status = result.get("status")
            if status is not None and status != "success":
                raise ApiClientError(
                    result.get("message") or "ORKL API error",
                    status_code=response.status_code,
                    response_body=result,
                )
            if "data" in result:
                return result["data"]

        return result

    def iter_library_entries(
        self, *, page_size: int = PAGE_SIZE
    ) -> Generator[list[dict[str, Any]], None, None]:
        """Lazily paginate through ORKL library entries, newest-updated first.

        Lazy: no page is fetched until it is consumed, so a caller (e.g. the
        incremental-sync processor) that stops iterating once it passes its
        cutoff triggers no further requests.

        Args:
            page_size: Entries requested per page, clamped to 1..100.

        Yields:
            Lists of raw entry dicts, one per page, ordered newest-first.
        """
        page_size = max(1, min(page_size, PAGE_SIZE))
        offset = 0
        previous_ids: list[Any] | None = None

        # Termination is normally driven by a short final page. Because ORKL is
        # a third-party API we don't control, that signal alone is not trusted:
        # two guards defend against a misbehaving server (e.g. one that ignores
        # `offset` and serves a cached full page forever) -- a hard MAX_PAGES
        # cap, and stall detection on repeated ids. Either tripping logs a
        # warning and stops cleanly (never raises), so a partial run still
        # sends what it collected rather than being silently truncated.
        for page_number in range(1, MAX_PAGES + 1):
            params = {
                "limit": page_size,
                "offset": offset,
                "order_by": "updated_at",
                "order": "desc",
            }
            entries = self._get("/library/entries", params=params) or []

            if not entries:
                break

            current_ids = [entry.get("id") for entry in entries]
            if current_ids == previous_ids:
                self._warn(
                    "ORKL library entries stalled: server is not honouring "
                    "`offset` (same ids as previous page); stopping pagination "
                    "to avoid an unbounded request loop",
                    {"offset": offset, "pages_yielded": page_number - 1},
                )
                break
            previous_ids = current_ids

            yield entries

            if len(entries) < page_size:
                break

            offset += len(entries)
        else:
            self._warn(
                "ORKL library entries pagination hit the MAX_PAGES cap without "
                "a short final page; stopping to avoid an unbounded request "
                "loop (server may be misbehaving or the corpus may have grown "
                "beyond this connector's expectations)",
                {"max_pages": MAX_PAGES},
            )

    def get_library_entry(self, entry_id: str) -> dict[str, Any] | None:
        """Retrieve a single library entry by its UUID.

        Not used by the Phase 1 processor, since list payloads already
        include full entry content (`plain_text`, `threat_actors`,
        `files`, ...). Kept thin, for debugging and future processors.

        Args:
            entry_id: The ORKL library entry UUID.

        Returns:
            The entry dict, or `None` if not present.
        """
        return self._get(f"/library/entry/{entry_id}")

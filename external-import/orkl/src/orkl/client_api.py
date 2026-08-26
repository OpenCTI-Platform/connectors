"""ORKL API client using the SDK BaseClientApi."""

from __future__ import annotations

import logging
from collections.abc import Generator
from typing import Any

from connectors_sdk import BaseClientApi
from connectors_sdk.client.exceptions import ApiClientError

logger = logging.getLogger(__name__)

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

    def __init__(self, base_url: str, **kwargs: Any) -> None:
        """Initialize the client, applying ORKL-specific defaults.

        The module-level constants are applied via ``setdefault`` so callers
        (and tests) can still override them explicitly.
        """
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

    def _parse_response(self, response: Any) -> Any:
        """Unwrap the ORKL response envelope.

        ORKL wraps every response as ``{"data": ..., "message": ...,
        "status": ...}``. This method first delegates to the base class so
        Content-Type based parsing still applies, then:

        - raises `ApiClientError` (carrying the envelope's `message`) if
          `status` is present and is not `"success"`.
        - returns `result["data"]` when a `data` key is present. Note this
          may legitimately be `None` (ORKL's empty-list sentinel for list
          endpoints) -- normalising that `None` into `[]` is the caller's
          responsibility, not this method's.
        - returns the result unchanged otherwise, so non-enveloped or
          non-JSON responses still work.
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

        Entries are sorted by `updated_at` descending. This is a lazy
        generator: no page is fetched until it is consumed, so a caller
        (e.g. the incremental-sync processor) that stops iterating once it
        passes its cutoff will not trigger any further requests.

        Termination is normally driven by a short final page (`len(entries)
        < page_size`). Because the API exposes no total-count field, this
        means a corpus whose size is an exact multiple of `page_size` costs
        one extra, empty trailing request before the generator stops --
        that's an accepted, known trade-off of offset pagination without a
        count, not an oversight.

        Since ORKL is a third-party public API we do not control, that
        short-page signal alone is not trusted as the sole stop condition.
        Two additional guards defend against a misbehaving server (e.g. one
        that ignores/clamps `offset` and keeps serving a cached/static full
        page forever):

        - A hard cap of `MAX_PAGES` requests, sized far above a legitimate
          full backfill (see the constant's comment for the numbers).
        - Stall detection: if a page's entry `id`s are identical to the
          previous page's, `offset` is clearly not being honoured.

        Either guard tripping logs a warning (so the anomaly is
        diagnosable) and stops the generator cleanly -- it never raises --
        so a partial run still sends everything collected so far instead of
        being silently truncated with no trace.

        Args:
            page_size: Number of entries requested per page. Clamped into
                the API-supported range of 1..100.

        Yields:
            Lists of raw entry dicts, one per page, ordered newest-first.
        """
        page_size = max(1, min(page_size, PAGE_SIZE))
        offset = 0
        previous_ids: list[Any] | None = None

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
                logger.warning(
                    "ORKL library entries stalled: page at offset=%s returned "
                    "the same entry ids as the previous page, meaning the "
                    "server is not honouring `offset`. Stopping pagination "
                    "after %s page(s) to avoid an unbounded request loop.",
                    offset,
                    page_number - 1,
                )
                break
            previous_ids = current_ids

            yield entries

            if len(entries) < page_size:
                break

            offset += len(entries)
        else:
            logger.warning(
                "ORKL library entries pagination hit the MAX_PAGES cap "
                "(%s) without reaching a short final page. Stopping to "
                "avoid an unbounded request loop; the server may be "
                "misbehaving or the corpus may have grown beyond this "
                "connector's expectations.",
                MAX_PAGES,
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

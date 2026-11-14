"""Client for the PolySwarm live hunting results endpoint.

Endpoint: ``GET {api_url}/v3/hunt/live/list``.

Behaviour of the endpoint, as measured against the production API:

- Authentication is the raw API key in the ``Authorization`` header
  (no ``Bearer`` prefix). A missing key returns 401; a key that is not
  a 32 character alphanumeric string returns 400.
- ``since`` is a window in SECONDS (some client documentation says
  minutes, which is wrong). ``since=0`` or no ``since`` at all means no
  time filter, so this client never sends 0. Non-integer values return
  400; very large values (1e12) return 500.
- Results come newest first. Each response carries ``has_more`` and,
  when there is a next page, an opaque ``offset`` cursor that is passed
  back as the ``offset`` query parameter. ``limit`` defaults to 50 and
  the server rejects anything above 300.
- An empty window returns HTTP 204 with no body.
"""

from typing import Any, Generator

from connectors_sdk import (
    ApiClientError,
    ApiForbiddenError,
    ApiUnauthorizedError,
    BaseClientApi,
)

LIVE_HUNT_LIST_PATH = "/v3/hunt/live/list"
MAX_PAGE_SIZE = 300
# Hard stop so a misbehaving cursor can never loop forever.
DEFAULT_MAX_PAGES = 1000


class PolySwarmHuntingError(ApiClientError):
    """Raised when the live hunting endpoint returns an unusable response."""


class PolySwarmHuntingAuthError(PolySwarmHuntingError):
    """Raised when PolySwarm rejects the API key."""


def _server_message(body: Any) -> str:
    """Extract the human readable message PolySwarm puts in error bodies."""
    if isinstance(body, dict):
        message = body.get("result") or body.get("message") or body.get("errors")
        if message:
            return str(message)[:300]
    if isinstance(body, str) and body:
        return body[:300]
    return "no details returned"


class PolySwarmHuntingClient(BaseClientApi):
    """Read only client for PolySwarm live hunting results.

    Retries on 408, 429 and 5xx (honouring ``Retry-After``) are handled by
    the ``BaseClientApi`` session from connectors-sdk.
    """

    def __init__(
        self,
        api_url: str,
        api_key: str,
        *,
        timeout: int = 60,
        max_retries: int = 3,
        backoff_factor: float = 1.0,
        page_size: int = MAX_PAGE_SIZE,
        max_pages: int = DEFAULT_MAX_PAGES,
    ) -> None:
        super().__init__(
            api_url,
            timeout=timeout,
            max_retries=max_retries,
            backoff_factor=backoff_factor,
        )
        if not api_key:
            raise ValueError("A PolySwarm API key is required")
        if not 1 <= page_size <= MAX_PAGE_SIZE:
            raise ValueError(f"page_size must be between 1 and {MAX_PAGE_SIZE}")
        self._api_key = api_key
        self._page_size = page_size
        self._max_pages = max_pages

    @property
    def session_headers(self) -> dict[str, str]:
        return {"Authorization": self._api_key}

    def _get_page(self, params: dict[str, Any]) -> dict[str, Any] | None:
        try:
            body = self._get(LIVE_HUNT_LIST_PATH, params=params)
        except (ApiUnauthorizedError, ApiForbiddenError) as err:
            raise PolySwarmHuntingAuthError(
                "PolySwarm rejected the API key "
                f"(HTTP {err.status_code or ''}): {_server_message(err.response_body)}. "
                "Check POLYSWARM_API_KEY and that the account has live hunting.",
                status_code=err.status_code,
            ) from err
        except PolySwarmHuntingError:
            raise
        except ApiClientError as err:
            message = _server_message(err.response_body)
            if err.status_code == 400 and "api key" in message.lower():
                raise PolySwarmHuntingAuthError(
                    f"PolySwarm rejected the API key (HTTP 400): {message}. "
                    "Check POLYSWARM_API_KEY.",
                    status_code=400,
                ) from err
            raise PolySwarmHuntingError(
                f"PolySwarm live hunting request failed "
                f"(HTTP {err.status_code or 'unknown'}): {message}",
                status_code=err.status_code,
            ) from err

        if body is None:
            # HTTP 204: nothing in the window.
            return None
        if not isinstance(body, dict):
            raise PolySwarmHuntingError(
                "Unexpected live hunting response: expected a JSON object"
            )
        result = body.get("result")
        if result is None:
            body["result"] = []
        elif not isinstance(result, list):
            raise PolySwarmHuntingError(
                "Unexpected live hunting response: 'result' is not a list"
            )
        return body

    def read_live_hits(self, since_seconds: int) -> "LiveHitsReader":
        """A reader over the live hunting hits of the last ``since_seconds``.

        Iterate it to get the hits (newest first); afterwards its ``complete``
        attribute tells whether paging reached the end of the window.
        """
        return LiveHitsReader(self, since_seconds)

    def iter_live_hits(self, since_seconds: int) -> Generator[dict, None, None]:
        """Yield live hunting hits from the last ``since_seconds`` seconds.

        Hits are yielded in the order the API returns them (newest first).
        """
        yield from self.read_live_hits(since_seconds)

    def list_live_hits(self, since_seconds: int) -> list[dict]:
        """Return the live hunting hits from the last ``since_seconds`` seconds.

        Paging can stop early (missing or repeated cursor, page limit); use
        ``read_live_hits`` when the caller needs to know.
        """
        return list(self.iter_live_hits(since_seconds))


class LiveHitsReader:
    """Iterate the live hunting hits of one window, page by page.

    Pages are fetched lazily, so a caller that stops iterating fetches no
    more pages. After iteration, ``complete`` is True only when the API said
    there was nothing more; otherwise ``stop_reason`` says why paging stopped
    ("missing cursor", "repeated cursor", "page limit"), or is None when the
    caller stopped first. Hits not read are the oldest ones in the window.
    """

    def __init__(self, client: PolySwarmHuntingClient, since_seconds: int) -> None:
        if isinstance(since_seconds, bool) or not isinstance(since_seconds, int):
            raise ValueError("since_seconds must be an integer")
        if since_seconds < 1:
            # since=0 would disable the time filter and return everything.
            raise ValueError("since_seconds must be at least 1")
        self._client = client
        self._since_seconds = since_seconds
        self.complete = False
        self.stop_reason: str | None = None

    def __iter__(self) -> Generator[dict, None, None]:
        client = self._client
        params: dict[str, Any] = {
            "since": self._since_seconds,
            "limit": client._page_size,
        }
        seen_cursors: set[str] = set()
        for _ in range(client._max_pages):
            body = client._get_page(params)
            if body is None:
                self.complete = True
                return
            for hit in body["result"]:
                if isinstance(hit, dict):
                    yield hit
            if not body.get("has_more"):
                self.complete = True
                return
            cursor = body.get("offset")
            if not cursor or not isinstance(cursor, str):
                self._stop("missing cursor")
                return
            if cursor in seen_cursors:
                self._stop("repeated cursor")
                return
            seen_cursors.add(cursor)
            params = {**params, "offset": cursor}
        self._stop("page limit")

    def _stop(self, reason: str) -> None:
        self.stop_reason = reason
        self._client.logger.warning(
            "Live hunting paging stopped before the end of the window.",
            meta={"reason": reason, "max_pages": self._client._max_pages},
        )

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

    def iter_live_hits(self, since_seconds: int) -> Generator[dict, None, None]:
        """Yield live hunting hits from the last ``since_seconds`` seconds.

        Hits are yielded in the order the API returns them (newest first).
        """
        if isinstance(since_seconds, bool) or not isinstance(since_seconds, int):
            raise ValueError("since_seconds must be an integer")
        if since_seconds < 1:
            # since=0 would disable the time filter and return everything.
            raise ValueError("since_seconds must be at least 1")

        params: dict[str, Any] = {"since": since_seconds, "limit": self._page_size}
        seen_cursors: set[str] = set()
        for _ in range(self._max_pages):
            body = self._get_page(params)
            if body is None:
                return
            for hit in body["result"]:
                if isinstance(hit, dict):
                    yield hit
            if not body.get("has_more"):
                return
            cursor = body.get("offset")
            if not cursor or not isinstance(cursor, str) or cursor in seen_cursors:
                self.logger.warning(
                    "Live hunting response said has_more without a new cursor; "
                    "stopping paging."
                )
                return
            seen_cursors.add(cursor)
            params = {**params, "offset": cursor}
        self.logger.warning(
            "Live hunting paging stopped at the page limit.",
            meta={"max_pages": self._max_pages},
        )

    def list_live_hits(self, since_seconds: int) -> list[dict]:
        """Return every live hunting hit from the last ``since_seconds`` seconds."""
        return list(self.iter_live_hits(since_seconds))

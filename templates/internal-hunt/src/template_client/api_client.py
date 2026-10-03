"""EXAMPLE HTTP client of the platform search API.

.. important::
    `TemplateClient` and its `/search` endpoint are a **worked example**:
    they show how a hunt connector client is structured, but they do not
    correspond to a real API. Rewrite them to call the search API of your
    platform (a search job API, a query endpoint...).

What this example demonstrates:
    - All networking concerns (base URL, authentication, errors, timeouts)
      live in one place, built on `BaseClientApi` (from `connectors-sdk`),
      which already provides retries with backoff on 429/5xx and typed
      `ApiClientError` exceptions.
    - Every call is bounded by the run timeout so that a slow platform
      never blocks the connector beyond the hunt run limits.
    - The response is reduced to what the connector needs: the total
      number of hits and at most `max_results` events.

TODO:
    - [ ] Rename `TemplateClient` (and this `template_client` package).
    - [ ] Implement `session_headers` for the authentication scheme of your platform.
    - [ ] Implement `search` with the real search API (and job polling/cancellation
        when the platform runs searches asynchronously).
"""

from datetime import datetime
from typing import Any

from connectors_sdk import ApiClientError, BaseClientApi
from connectors_sdk.connectors.internal_hunt import HuntExecutionError


class TemplateClient(BaseClientApi):
    """EXAMPLE client of a platform search API -- rewrite it for your platform."""

    def __init__(self, base_url: str, api_key: str, verify_ssl: bool, logger: Any):
        """Initialize the client.

        Args:
            base_url: Base URL of the platform search API.
            api_key: API key used to authenticate.
            verify_ssl: Whether to verify the TLS certificate of the API.
            logger: The connector logger.
        """
        super().__init__(base_url=base_url, ssl_verify=verify_ssl)
        self._api_key = api_key
        self._logger = logger

    @property
    def session_headers(self) -> dict[str, str]:
        """Return the authentication headers sent with every request."""
        return {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self._api_key}",
        }

    def search(
        self,
        query: str,
        indices: list[str],
        start: datetime,
        end: datetime,
        max_results: int,
        timeout: int,
    ) -> dict[str, Any]:
        """Run a search over a time window.

        Args:
            query: Native query.
            indices: Indices (or tables) to search in.
            start: Start of the time window.
            end: End of the time window.
            max_results: Maximum number of events to return.
            timeout: Maximum duration of the call in seconds.

        Returns:
            The `total` number of hits and at most `max_results` `events`.

        Raises:
            HuntExecutionError: If the platform rejects the search.
        """
        body = {
            "query": query,
            "indices": indices,
            "from": start.isoformat(),
            "to": end.isoformat(),
            "size": max_results,
        }
        try:
            response = self._post("/search", json=body, timeout=timeout)
        except ApiClientError as err:
            self._logger.error(
                "[API] Search failed",
                {"status_code": err.status_code, "error": str(err)},
            )
            raise HuntExecutionError(f"The platform search failed: {err}") from err
        events = list(response.get("events") or [])
        return {"total": int(response.get("total", len(events))), "events": events}

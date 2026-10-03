"""EXAMPLE HTTP client of the platform search API.

.. important::
    `TemplateClient` and its `/search` endpoint are a **worked example**:
    they show how a hunt connector client is structured, but they do not
    correspond to a real API. Rewrite them to call the search API of your
    platform (a search job API, a query endpoint...).

What this example demonstrates:
    - All networking concerns (base URL, authentication, errors, timeouts)
      live in one place, built on `HuntApiClient` (from `connectors-sdk`),
      which provides retries with backoff on 429/5xx and turns HTTP and
      network failures into hunt errors carrying the platform message.
    - Every call is bounded by the run deadline (`RunDeadline`) so that a
      slow platform never blocks the connector beyond the hunt run limits.
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

from connectors_sdk.connectors.internal_hunt import HuntApiClient, RunDeadline


class TemplateClient(HuntApiClient):
    """EXAMPLE client of a platform search API -- rewrite it for your platform."""

    def __init__(self, base_url: str, api_key: str, verify_ssl: bool):
        """Initialize the client.

        Args:
            base_url: Base URL of the platform search API.
            api_key: API key used to authenticate.
            verify_ssl: Whether to verify the TLS certificate of the API.
        """
        super().__init__(base_url=base_url, ssl_verify=verify_ssl)
        self._api_key = api_key

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
        deadline: RunDeadline,
    ) -> dict[str, Any]:
        """Run a search over a time window.

        Args:
            query: Native query.
            indices: Indices (or tables) to search in.
            start: Start of the time window.
            end: End of the time window.
            max_results: Maximum number of events to return.
            deadline: Run deadline bounding the call.

        Returns:
            The `total` number of hits and at most `max_results` `events`.

        Raises:
            HuntExecutionError: If the platform rejects the search.
            HuntTimeoutError: If the search does not answer before the deadline.
        """
        body = {
            "query": query,
            "indices": indices,
            "from": start.isoformat(),
            "to": end.isoformat(),
            "size": max_results,
        }
        response = self.hunt_request(
            "POST", "/search", deadline, "The platform search", json=body
        )
        events = [event for event in response.get("events") or [] if event]
        return {"total": int(response.get("total", len(events))), "events": events}

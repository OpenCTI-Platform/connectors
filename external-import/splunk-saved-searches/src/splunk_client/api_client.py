"""Read-only client of the Splunk saved searches REST endpoint."""

from __future__ import annotations

from collections.abc import Callable, Generator
from typing import Any
from urllib.parse import quote, urlsplit

from connectors_sdk import ApiClientError, ConnectorLogger
from splunk_client.retrying_client import RetryingApiClient


class SplunkSavedSearchesClient(RetryingApiClient):
    """List the saved searches of a Splunk namespace.

    Only ``GET`` requests are sent: the connector never creates, modifies,
    enables or schedules a search.
    """

    def __init__(
        self,
        api_url: str,
        token: str,
        *,
        logger: ConnectorLogger,
        app: str = "-",
        owner: str = "-",
        web_url: str | None = None,
        page_size: int = 100,
        timeout: int = 60,
        ssl_verify: bool = True,
        max_retries: int = 5,
        sleep: Callable[[float], None] | None = None,
    ) -> None:
        super().__init__(
            api_url,
            logger=logger,
            timeout=timeout,
            ssl_verify=ssl_verify,
            max_retries=max_retries,
            sleep=sleep,
        )
        self._token = token
        self._app = app
        self._owner = owner
        self._web_url = web_url.rstrip("/") if web_url else None
        self._page_size = page_size

    @property
    def session_headers(self) -> dict[str, str]:
        """Authenticate with the Splunk authentication token."""
        return {"Authorization": f"Bearer {self._token}"}

    def iter_saved_searches(self) -> Generator[dict[str, Any], None, None]:
        """Yield every saved search entry of the namespace."""
        path = (
            f"/servicesNS/{quote(self._owner, safe='-')}"
            f"/{quote(self._app, safe='-')}/saved/searches"
        )
        offset = 0
        has_more = True
        while has_more:
            response = self._get(
                path,
                params={
                    "output_mode": "json",
                    "count": self._page_size,
                    "offset": offset,
                },
            )
            if not isinstance(response, dict) or not isinstance(
                response.get("entry"), list
            ):
                raise ApiClientError(
                    "Unexpected response of the Splunk saved/searches endpoint",
                    response_body=response,
                )
            entries = response["entry"]
            yield from entries
            offset += len(entries)
            total = int((response.get("paging") or {}).get("total") or 0)
            has_more = bool(entries) and offset < total

    def saved_search_url(self, entry: dict[str, Any]) -> str | None:
        """Return the Splunk Web link opening the saved search, if configured."""
        app = (entry.get("acl") or {}).get("app")
        rest_path = urlsplit(str(entry.get("id") or "")).path
        if not self._web_url or not app or not rest_path:
            return None
        return f"{self._web_url}/app/{quote(app, safe='')}/search?s={quote(rest_path, safe='')}"

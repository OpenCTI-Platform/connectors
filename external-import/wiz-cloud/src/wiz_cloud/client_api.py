"""Wiz GraphQL client on top of connectors_sdk BaseClientApi.

BaseClientApi provides the session, retry strategy (honouring Retry-After),
rate limiting and typed HTTP exceptions. Three Wiz-specific concerns are
added here:

1. OAuth2 client-credentials token with refresh. session_headers is applied
   once at session creation and never refreshed, so per the SDK docstring the
   Authorization header is injected per request by overriding _raw_request.
   Wiz tokens last 24 h; a long-lived connector must refresh.

2. GraphQL error handling. A failed query returns HTTP 200 with a populated
   errors array and data: null, which sails past _raise_for_status. execute()
   checks it explicitly.

3. Cursor pagination with the cursor in the request body (after /
   pageInfo.endCursor), which neither _paginate_offset nor the ZeroFox
   next-URL paginator covers.
"""

import time
from collections.abc import Iterator
from typing import Any

import requests
from connectors_sdk import ApiClientError, BaseClientApi


class WizGraphQLError(ApiClientError):
    """Raised on an HTTP 200 response carrying a populated GraphQL errors array."""


class WizApiClient(BaseClientApi):
    """Client for the Wiz tenant GraphQL API.

    Args:
        base_url: Tenant GraphQL endpoint.
        auth_url: OAuth2 token endpoint, on a different host than base_url.
        client_id: Wiz service account client id.
        client_secret: Wiz service account client secret.
        **kwargs: Forwarded to BaseClientApi (timeout, max_retries, ...).
    """

    def __init__(
        self,
        base_url: str,
        auth_url: str,
        client_id: str,
        client_secret: str,
        **kwargs: Any,
    ) -> None:
        super().__init__(base_url=base_url, **kwargs)
        self._auth_url = auth_url
        self._client_id = client_id
        self._client_secret = client_secret
        self._token: str | None = None
        self._token_expires_at: float = 0.0

    # -- OAuth2 -------------------------------------------------------------

    def _access_token(self) -> str:
        if self._token and time.time() < self._token_expires_at:
            return self._token

        # Different host than base_url, so this cannot go through self._post.
        response = requests.post(
            self._auth_url,
            data={
                "grant_type": "client_credentials",
                "client_id": self._client_id,
                "client_secret": self._client_secret,
                "audience": "wiz-api",
            },
            timeout=30,
        )
        response.raise_for_status()
        payload = response.json()
        self._token = payload["access_token"]
        # Refresh one minute before actual expiry (Wiz tokens last 24 h).
        self._token_expires_at = time.time() + payload["expires_in"] - 60
        return self._token

    def _raw_request(self, method: str, path: str, **kwargs: Any) -> Any:
        headers = dict(kwargs.pop("headers", None) or {})
        headers["Authorization"] = f"Bearer {self._access_token()}"
        return super()._raw_request(method, path, headers=headers, **kwargs)

    # -- GraphQL ------------------------------------------------------------

    def execute(self, query: str, variables: dict[str, Any]) -> dict[str, Any]:
        """Run a single GraphQL query.

        Args:
            query: GraphQL document to execute.
            variables: Variables bound to the query.

        Returns:
            The data object of the GraphQL response.

        Raises:
            WizGraphQLError: If the response carries GraphQL errors or no data.
                Wiz answers a failed query with HTTP 200, so this cannot be
                left to the SDK status handling.
        """
        payload = self._post("", json={"query": query, "variables": variables})
        if errors := payload.get("errors"):
            raise WizGraphQLError(f"Wiz GraphQL error: {errors}")
        data = payload.get("data")
        if data is None:
            raise WizGraphQLError("Wiz GraphQL response has no data")
        return data

    def paginate(
        self,
        query: str,
        variables: dict[str, Any],
        connection_key: str,
    ) -> Iterator[list[dict[str, Any]]]:
        """Paginate through a Wiz GraphQL connection using cursor-based pagination.

        Args:
            query: GraphQL document exposing an ``after`` variable.
            variables: Variables bound to the query. The ``after`` entry is
                overwritten on each iteration with the next cursor.
            connection_key: Key of the connection to walk in the response.

        Yields:
            Lists of node dicts, one per page.
        """
        variables = dict(variables)
        while True:
            connection = self.execute(query, variables)[connection_key]
            nodes = connection.get("nodes") or []
            if nodes:
                yield nodes
            page_info = connection.get("pageInfo") or {}
            if not page_info.get("hasNextPage"):
                return
            variables["after"] = page_info["endCursor"]

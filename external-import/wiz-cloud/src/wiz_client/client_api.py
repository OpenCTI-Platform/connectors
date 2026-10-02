"""Wiz GraphQL client on top of connectors_sdk BaseClientApi.

BaseClientApi provides the session, retry strategy (honouring Retry-After),
rate limiting and typed HTTP exceptions. This client adds four things for
Wiz:

1. OAuth2 client-credentials token with refresh. session_headers is applied
   once at session creation and never refreshed, so per the SDK docstring the
   Authorization header is injected per request by overriding _raw_request.
   Wiz tokens last 24 h; a long-lived connector must refresh.

2. GraphQL error handling. A failed query returns HTTP 200 with a populated
   errors array and data: null, which sails past _raise_for_status.
   _execute() checks it explicitly.

3. Cursor pagination with the cursor in the request body (after /
   pageInfo.endCursor), which neither _paginate_offset nor the ZeroFox
   next-URL paginator covers.

4. Parsed results. paginate_issues() and paginate_vulnerabilities_findings()
   read their GraphQL query from the wiz_client/queries folder, and convert
   each result into a pydantic model. If a result cannot be parsed, they
   raise pydantic.ValidationError. The result is not skipped.
"""

import time
from collections.abc import Iterator
from datetime import datetime, timezone
from importlib import resources
from typing import Any

import requests
from connectors_sdk import ApiClientError, BaseClientApi
from connectors_sdk.connectors.external_import.logger import ConnectorLogger
from wiz_client.models import WizIssue, WizVulnerabilityFinding


class WizGraphQLError(ApiClientError):
    """Raised on an HTTP 200 response carrying a populated GraphQL errors array."""


def _utc(dt: datetime) -> str:
    # Full precision matters: Wiz createdAt carries microseconds and the
    # filter is exclusive, so truncating to the second would re-select the
    # issue the cursor points at on every run.
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


class WizApiClient(BaseClientApi):
    """Client for the Wiz tenant GraphQL API.

    Args:
        base_url: Tenant GraphQL endpoint.
        auth_url: OAuth2 token endpoint, on a different host than base_url.
        client_id: Wiz service account client id.
        client_secret: Wiz service account client secret.
        logger: Connector logger, used to report truncated pagination.
        **kwargs: Forwarded to BaseClientApi (timeout, max_retries, ...).
    """

    def __init__(
        self,
        base_url: str,
        auth_url: str,
        client_id: str,
        client_secret: str,
        logger: ConnectorLogger,
        **kwargs: Any,
    ) -> None:
        super().__init__(base_url=base_url, **kwargs)
        self._auth_url = auth_url
        self._client_id = client_id
        self._client_secret = client_secret
        self._logger = logger
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

    def _execute(self, query: str, variables: dict[str, Any]) -> dict[str, Any]:
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
        if (data := payload.get("data")) is None:
            raise WizGraphQLError("Wiz GraphQL response has no data")
        return data

    def _paginate(
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

        Pagination stops when hasNextPage is false, when the cursor is empty,
        or when it repeats, so a misbehaving connection cannot loop forever.
        """
        variables = dict(variables)
        previous_cursor: str | None = None
        while True:
            connection = self._execute(query, variables)[connection_key]
            nodes = connection.get("nodes") or []
            if nodes:
                yield nodes
            page_info = connection.get("pageInfo") or {}
            if not page_info.get("hasNextPage"):
                return
            cursor = page_info.get("endCursor")
            # Wiz can answer hasNextPage: true with a null or repeated cursor.
            # Following it would re-request the same page forever, so stop and
            # keep what we already have rather than aborting the whole run.
            if not cursor or cursor == previous_cursor:
                self._logger.warning(
                    "[WIZ-CLOUD] Stopping pagination early on an unusable cursor, "
                    "results may be incomplete",
                    {
                        "connection": connection_key,
                        "cursor": cursor,
                        "reason": "missing" if not cursor else "repeated",
                    },
                )
                return
            previous_cursor = cursor
            variables["after"] = cursor

    def paginate_issues(
        self,
        first: int | None = None,
        after: str | None = None,
        type: list[str] | None = None,
        severity: list[str] | None = None,
        status: list[str] | None = None,
        created_after: datetime | None = None,
    ) -> Iterator[list[WizIssue]]:
        """Get Wiz issues, page by page, oldest first.

        With the oldest issues first, a run that stops in the middle has
        still imported all issues up to a given date, with no gap.
        Filters that are empty or None are not sent to Wiz.

        Args:
            first: Number of issues per page.
            after: Cursor of the page to start from. None for the first page.
            type: Issue types to get, e.g. ["THREAT_DETECTION"].
            severity: Issue severities to get.
            status: Issue statuses to get.
            created_after: Only issues created after this date are returned.
                The date is sent with microseconds.

        Yields:
            Lists of parsed issues, one list per page.

        Raises:
            pydantic.ValidationError: If an issue cannot be parsed as WizIssue.
            WizGraphQLError: If Wiz returns GraphQL errors.
        """
        issues_query = (
            resources.files("wiz_client.queries")
            .joinpath("issues.graphql")
            .read_text("utf-8")
        )

        filter_by = {}
        if type:
            filter_by["type"] = type
        if severity:
            filter_by["severity"] = severity
        if status:
            filter_by["status"] = status
        if created_after:
            filter_by["createdAt"] = {"after": _utc(created_after)}

        pages = self._paginate(
            query=issues_query,
            variables={
                "first": first,
                "after": after,
                "orderBy": {"field": "CREATED_AT", "direction": "ASC"},
                "filterBy": filter_by,
            },
            connection_key="issues",
        )

        for page in pages:
            yield [WizIssue.model_validate(raw) for raw in page]

    def paginate_vulnerabilities_findings(
        self,
        first: int | None = None,
        after: str | None = None,
        severity: list[str] | None = None,
        status: list[str] | None = None,
        has_exploit: bool | None = None,
        asset_id: str | None = None,
    ) -> Iterator[list[WizVulnerabilityFinding]]:
        """Get Wiz vulnerability findings, page by page, newest first.

        Filters that are empty or None are not sent to Wiz. has_exploit is
        sent when it is True or False. Be careful: False returns only the
        findings WITHOUT a known exploit.

        Args:
            first: Number of findings per page.
            after: Cursor of the page to start from. None for the first page.
            severity: Finding severities to get.
            status: Finding statuses to get.
            has_exploit: True to get only findings with a known exploit,
                False to get only findings without one, None for all.
            asset_id: Only get the findings of this asset.

        Yields:
            Lists of parsed findings, one list per page.

        Raises:
            pydantic.ValidationError: If a finding cannot be parsed as
                WizVulnerabilityFinding.
            WizGraphQLError: If Wiz returns GraphQL errors.
        """
        vulnerabilities_query = (
            resources.files("wiz_client.queries")
            .joinpath("vulnerability_findings.graphql")
            .read_text("utf-8")
        )

        filter_by = {}
        if asset_id:
            filter_by["assetIdV2"] = {"equals": [asset_id]}
        if severity:
            filter_by["severity"] = severity
        if status:
            filter_by["status"] = status
        if has_exploit is not None:
            filter_by["hasExploit"] = has_exploit

        pages = self._paginate(
            query=vulnerabilities_query,
            variables={
                "first": first,
                "after": after,
                "orderBy": {"field": "CREATED_AT", "direction": "DESC"},
                "filterBy": filter_by,
            },
            connection_key="vulnerabilityFindings",
        )

        for page in pages:
            yield [WizVulnerabilityFinding.model_validate(raw) for raw in page]

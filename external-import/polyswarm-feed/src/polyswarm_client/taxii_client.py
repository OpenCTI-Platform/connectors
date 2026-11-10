"""TAXII 2.1 client for the PolySwarm feed.

PolySwarm serves its feed over TAXII 2.1:

    - discovery: `<api_url>/v3/stix/taxii2/`
    - API roots: `<api_url>/v3/stix/<root>/` (trustgroup, ransomware, freemium),
      each with a single readable collection.
    - objects: `<api_url>/v3/stix/<root>/collections/<id>/objects/`, paged with
      `limit`, `added_after` and the `more`/`next` envelope fields. The
      `X-TAXII-Date-Added-First`/`-Last` headers describe the returned page.

Authentication is HTTP Basic (account number, API key). Retries with
backoff on 408/429/5xx are handled by `BaseClientApi` (`connectors-sdk`).
"""

from __future__ import annotations

import base64
from dataclasses import dataclass, field
from typing import Any

import requests
from connectors_sdk import (
    ApiClientError,
    ApiForbiddenError,
    ApiUnauthorizedError,
    BaseClientApi,
)

TAXII_MEDIA_TYPE = "application/taxii+json;version=2.1"


class TaxiiAuthenticationError(ApiUnauthorizedError):
    """The TAXII server rejected the credentials (HTTP 401)."""


class TaxiiPermissionError(ApiForbiddenError):
    """The account is not allowed to read the requested resource (HTTP 403)."""


class TaxiiResponseError(ApiClientError):
    """The TAXII server returned a body the client cannot use."""


@dataclass
class TaxiiPage:
    """One page of a TAXII `objects` response."""

    objects: list[Any] = field(default_factory=list)
    more: bool = False
    next: str | None = None
    date_added_first: str | None = None
    date_added_last: str | None = None


class PolySwarmTaxiiClient(BaseClientApi):
    """Read-only client for PolySwarm's TAXII 2.1 server."""

    def __init__(
        self,
        api_url: str,
        account_number: str,
        api_key: str,
        *,
        timeout: int = 60,
        max_retries: int = 3,
        backoff_factor: float = 2.0,
    ) -> None:
        """Initialize the client.

        Args:
            api_url: PolySwarm API base URL, e.g. `https://api.polyswarm.network`.
            account_number: PolySwarm account number (Basic auth username).
            api_key: PolySwarm API key (Basic auth password).
            timeout: Timeout of each HTTP request, in seconds.
            max_retries: Retries on 408/429/5xx responses and connection errors.
            backoff_factor: Exponential backoff factor between retries.
        """
        base_url = api_url.rstrip("/")
        if not base_url.endswith("/v3"):
            base_url = f"{base_url}/v3"
        super().__init__(
            base_url=f"{base_url}/stix",
            timeout=timeout,
            max_retries=max_retries,
            backoff_factor=backoff_factor,
        )
        self._account_number = account_number
        self._api_key = api_key
        self._collection_ids: dict[str, str] = {}

    @property
    def session_headers(self) -> dict[str, str]:
        """Headers sent with every request: TAXII media type and Basic auth."""
        credentials = f"{self._account_number}:{self._api_key}".encode()
        return {
            "Accept": TAXII_MEDIA_TYPE,
            "Authorization": "Basic " + base64.b64encode(credentials).decode(),
        }

    # ------------------------------------------------------------------
    # TAXII endpoints
    # ------------------------------------------------------------------

    def discovery(self) -> dict[str, Any]:
        """Return the TAXII discovery document."""
        body, _ = self._get_taxii("taxii2/")
        return body

    def list_collections(self, api_root: str) -> list[dict[str, Any]]:
        """Return the collections of an API root."""
        body, _ = self._get_taxii(f"{api_root}/collections/")
        collections = body.get("collections", [])
        if not isinstance(collections, list):
            raise TaxiiResponseError(
                f"Unexpected 'collections' value from API root '{api_root}'"
            )
        return collections

    def get_collection_id(self, api_root: str) -> str:
        """Return the id of the first readable collection of an API root.

        Each PolySwarm API root exposes a single collection. The id is cached
        for the lifetime of the client.
        """
        if api_root not in self._collection_ids:
            for collection in self.list_collections(api_root):
                if (
                    isinstance(collection, dict)
                    and collection.get("id")
                    and collection.get("can_read", True)
                ):
                    self._collection_ids[api_root] = collection["id"]
                    break
            else:
                raise TaxiiPermissionError(
                    f"No readable collection in PolySwarm API root '{api_root}'. "
                    "Check that the account has access to this feed."
                )
        return self._collection_ids[api_root]

    def get_objects(
        self,
        api_root: str,
        collection_id: str,
        *,
        added_after: str | None = None,
        next_token: str | None = None,
        limit: int | None = None,
    ) -> TaxiiPage:
        """Fetch one page of objects from a collection.

        Args:
            api_root: The API root name, e.g. `trustgroup`.
            collection_id: The collection id (see `get_collection_id`).
            added_after: Only return objects added after this timestamp.
            next_token: Opaque `next` value from the previous page.
            limit: Maximum number of items in the page.

        Returns:
            The page. An empty body (no `objects` key) is an empty page.
        """
        params: dict[str, Any] = {}
        if limit:
            params["limit"] = limit
        if added_after:
            params["added_after"] = added_after
        if next_token:
            params["next"] = next_token

        body, headers = self._get_taxii(
            f"{api_root}/collections/{collection_id}/objects/", params=params
        )
        objects = body.get("objects") or []
        if not isinstance(objects, list):
            raise TaxiiResponseError(
                f"Unexpected 'objects' value from API root '{api_root}'"
            )
        more = bool(body.get("more", False))
        return TaxiiPage(
            objects=objects,
            more=more,
            next=body.get("next") if more else None,
            date_added_first=headers.get("X-TAXII-Date-Added-First"),
            date_added_last=headers.get("X-TAXII-Date-Added-Last"),
        )

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _get_taxii(
        self, path: str, params: dict[str, Any] | None = None
    ) -> tuple[dict[str, Any], requests.structures.CaseInsensitiveDict]:
        """GET a TAXII resource and return (JSON body, response headers).

        Raises:
            TaxiiAuthenticationError: On 401 (wrong account number or API key).
            TaxiiPermissionError: On 403 (account not entitled to the resource).
            ApiClientError: On other HTTP errors (after retries for 429/5xx).
            TaxiiResponseError: When the body is not a JSON object.
        """
        response = self._raw_request("GET", path, params=params)

        if response.status_code == 204:
            return {}, response.headers

        if response.status_code == 401:
            raise TaxiiAuthenticationError(
                "PolySwarm TAXII authentication failed (HTTP 401). "
                "Check POLYSWARM_ACCOUNT_NUMBER and POLYSWARM_API_KEY.",
                response_body=self._safe_response_body(response),
            )
        if response.status_code == 403:
            raise TaxiiPermissionError(
                f"PolySwarm TAXII access denied (HTTP 403) on '{path}'. "
                "Check that the account has access to this feed.",
                response_body=self._safe_response_body(response),
            )
        if not response.ok:
            self._raise_for_status(response, "GET", path)

        try:
            body = response.json() if response.content else {}
        except (ValueError, requests.exceptions.JSONDecodeError) as err:
            raise TaxiiResponseError(
                f"PolySwarm TAXII response on '{path}' is not valid JSON"
            ) from err
        if not isinstance(body, dict):
            raise TaxiiResponseError(
                f"PolySwarm TAXII response on '{path}' is not a JSON object"
            )
        return body, response.headers

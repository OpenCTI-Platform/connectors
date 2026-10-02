"""HTTP client for the AbuseIPDB TAXII 2.1 API root."""

import base64
from collections.abc import Mapping
from datetime import datetime, timezone
from typing import Any
from urllib.parse import quote

import requests
from abuseipdb_taxii_client.models import TaxiiPage
from connectors_sdk import (
    BaseClientApi,
    ConfigurationInvalidError,
    ProviderApiAuthenticationError,
    ProviderApiAuthorizationError,
    ProviderApiConnectionError,
    ProviderApiInvalidResponseError,
    ProviderApiNotFoundError,
    ProviderApiRateLimitError,
    ProviderApiServerError,
    ProviderApiTimeoutError,
    ProviderApiUnknownError,
)
from urllib3.exceptions import ReadTimeoutError

TAXII_ACCEPT = "application/taxii+json;version=2.1"
TAXII_MEDIA_TYPE = "application/taxii+json"
DATE_ADDED_LAST_HEADER = "X-TAXII-Date-Added-Last"
MAX_RETRIES = 5


class TaxiiBadRequestError(ProviderApiUnknownError):
    """The TAXII server rejected the request parameters (HTTP 400)."""


def _normalize_date_added(value: str | None) -> str | None:
    """Return a TAXII timestamp as ``YYYY-MM-DDTHH:MM:SS.ffffffZ``, or ``None``.

    ``None`` is returned for a missing or empty value, a value that is not an
    ISO 8601 timestamp, and a timestamp without a timezone.
    """
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


class AbuseIPDBTaxiiClient(BaseClientApi):
    """Read the account's AbuseIPDB TAXII feed.

    Retries, backoff and ``Retry-After`` handling come from ``BaseClientApi``.
    Every error raised here carries a static message: none includes a URL,
    collection ID, cursor, header value, or response body.
    """

    def __init__(
        self,
        api_root: str,
        username: str,
        password: str,
        *,
        timeout: float,
        ssl_verify: bool,
    ) -> None:
        super().__init__(
            base_url=api_root,
            timeout=timeout,
            ssl_verify=ssl_verify,
            max_retries=MAX_RETRIES,
        )
        self._username = username
        self._password = password

    @property
    def session_headers(self) -> dict[str, str]:
        """TAXII ``Accept`` header and HTTP Basic credentials (email and API key)."""
        credentials = f"{self._username}:{self._password}".encode("utf-8")
        return {
            "Accept": TAXII_ACCEPT,
            "Authorization": "Basic " + base64.b64encode(credentials).decode("ascii"),
        }

    def _parse_response(self, response: requests.Response) -> dict[str, Any]:
        content_type = response.headers.get("Content-Type", "").lower()
        if not content_type.startswith(TAXII_MEDIA_TYPE):
            raise ProviderApiInvalidResponseError(
                "AbuseIPDB TAXII response has an unexpected content type"
            ) from None
        try:
            payload = response.json()
        except ValueError:
            raise ProviderApiInvalidResponseError(
                "AbuseIPDB TAXII response is not valid JSON"
            ) from None
        if not isinstance(payload, dict):
            raise ProviderApiInvalidResponseError(
                "AbuseIPDB TAXII response is not a JSON object"
            ) from None
        return payload

    def _get_taxii(
        self, path: str, params: dict[str, Any] | None = None
    ) -> tuple[dict[str, Any], Mapping[str, str]]:
        try:
            response = self._raw_request("GET", path, params=params)
        except requests.exceptions.Timeout:
            raise ProviderApiTimeoutError("AbuseIPDB TAXII request timed out") from None
        except requests.exceptions.RequestException as err:
            # A read timeout arrives as a ConnectionError: wrapping urllib3's
            # MaxRetryError when it outlasted the retries, or the ReadTimeoutError
            # itself when the body stalled.
            cause = err.args[0] if err.args else None
            if isinstance(cause, ReadTimeoutError) or isinstance(
                getattr(cause, "reason", None), ReadTimeoutError
            ):
                raise ProviderApiTimeoutError(
                    "AbuseIPDB TAXII request timed out"
                ) from None
            raise ProviderApiConnectionError(
                "AbuseIPDB TAXII request failed before a response was received"
            ) from None

        status = response.status_code
        if status != 200:
            if status == 400:
                raise TaxiiBadRequestError(
                    "AbuseIPDB TAXII rejected the request parameters (HTTP 400)"
                )
            if status == 401:
                raise ProviderApiAuthenticationError(
                    "AbuseIPDB TAXII rejected the credentials (HTTP 401)"
                )
            if status == 403:
                raise ProviderApiAuthorizationError(
                    "AbuseIPDB TAXII denied access (HTTP 403)"
                )
            if status == 404:
                raise ProviderApiNotFoundError(
                    "AbuseIPDB TAXII resource was not found (HTTP 404)"
                )
            if status == 429:
                raise ProviderApiRateLimitError(
                    "AbuseIPDB TAXII rate limit still exceeded after retries (HTTP 429)"
                )
            if status >= 500:
                raise ProviderApiServerError(
                    f"AbuseIPDB TAXII server error after retries (HTTP {status})"
                )
            raise ProviderApiUnknownError(
                f"AbuseIPDB TAXII returned an unexpected status (HTTP {status})"
            )

        # The case-insensitive header mapping is returned as is: the server's
        # header casing is not guaranteed.
        return self._parse_response(response), response.headers

    def discover_collection_id(self, configured_id: str | None) -> str:
        """Return the ID of the readable TAXII collection to pull.

        That is the readable collection whose ID matches ``configured_id`` in any
        letter case, returned as the server lists it, or the account's single
        readable collection when no ID is configured.
        """
        payload, _ = self._get_taxii("collections/")
        collections = payload.get("collections")
        if not isinstance(collections, list):
            raise ProviderApiInvalidResponseError(
                "AbuseIPDB TAXII discovery returned invalid collection metadata"
            )
        readable = [
            item
            for item in collections
            if isinstance(item, dict) and item.get("can_read", True) is not False
        ]
        if configured_id is not None:
            for item in readable:
                listed_id = item.get("id")
                if (
                    isinstance(listed_id, str)
                    and listed_id.lower() == configured_id.lower()
                ):
                    return listed_id
            raise ConfigurationInvalidError(
                "The configured ABUSEIPDB_TAXII_COLLECTION_ID is not one of the "
                "AbuseIPDB account's readable TAXII feeds"
            )
        if not readable:
            raise ConfigurationInvalidError(
                "The AbuseIPDB account has no readable TAXII feed"
            )
        if len(readable) > 1:
            raise ConfigurationInvalidError(
                "The AbuseIPDB account has several readable TAXII feeds; set "
                "ABUSEIPDB_TAXII_COLLECTION_ID to choose one"
            )
        collection_id = readable[0].get("id")
        if not isinstance(collection_id, str) or not collection_id:
            raise ProviderApiInvalidResponseError(
                "AbuseIPDB TAXII discovery returned invalid collection metadata"
            )
        return collection_id

    def get_objects_page(
        self,
        collection_id: str,
        *,
        added_after: str | None,
        next_cursor: str | None,
        limit: int,
    ) -> TaxiiPage:
        """Fetch one page of the collection's objects.

        ``next_cursor`` takes precedence: when it is set, ``added_after`` is not
        sent.
        """
        params: dict[str, Any] = {"limit": limit}
        if next_cursor:
            params["next"] = next_cursor
        elif added_after:
            params["added_after"] = added_after

        payload, headers = self._get_taxii(
            f"collections/{quote(collection_id, safe='')}/objects/", params
        )
        objects = payload.get("objects", [])
        more = payload.get("more", False)
        next_value = payload.get("next")

        if not isinstance(objects, list) or not all(
            isinstance(item, dict)
            and isinstance(item.get("type"), str)
            and isinstance(item.get("id"), str)
            for item in objects
        ):
            raise ProviderApiInvalidResponseError(
                "AbuseIPDB TAXII response contains invalid STIX objects"
            )
        if not isinstance(more, bool):
            raise ProviderApiInvalidResponseError(
                "AbuseIPDB TAXII response has an invalid more flag"
            )
        if more and (not isinstance(next_value, str) or not next_value):
            raise ProviderApiInvalidResponseError(
                "AbuseIPDB TAXII response is missing its continuation cursor"
            )

        return TaxiiPage(
            objects=objects,
            more=more,
            next_cursor=next_value if isinstance(next_value, str) else None,
            added_last=_normalize_date_added(headers.get(DATE_ADDED_LAST_HEADER)),
        )

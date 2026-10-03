"""
Client module for the SentinelOne services API
"""

from __future__ import annotations

import re
import time
from collections.abc import Iterator
from typing import TYPE_CHECKING, Any

import requests

if TYPE_CHECKING:
    from pycti.connector.opencti_connector_helper import OpenCTIConnectorHelper
    from sentinelone_connector.settings import ConnectorSettings

# The suffix to be appended to a base URL for a POST request of IOCs to S1
IOC_ENDPOINT_URL = "/web/api/v2.1/threat-intelligence/iocs/stix"
# The suffix of the IOCs endpoint (list and delete), used by the deployment write-back
IOCS_ENDPOINT_URL = "/web/api/v2.1/threat-intelligence/iocs"
# IOCs per page of the read-back, and maximum number of pages read
PAGE_SIZE = 1000
MAX_PAGES = 1000
# Maximum length of the SentinelOne response body kept in an error message
MAX_ERROR_DETAIL_LENGTH = 500


# SentinelOne can only accept Patterns with single elements of the types:
#   - File hashes (MD5, SHA-1, SHA-256)
#   - Domain names
#   - URLs
#   - IPv4 addresses
#
# Such regex patterns allow the connector to thus filter for valid Indicators.
# More details can be found in the connector's documentation.
#
# The file-hash pattern accepts every shape OpenCTI is known to emit
# for file-hash indicators (issue #5428):
#   - the STIX 2.1 canonical form  ``[file:hashes.SHA-256 = '...']``;
#   - the single-quoted algorithm  ``[file:hashes.'SHA-256' = '...']``
#     that OpenCTI uses when the algorithm key is not a valid
#     ``hash-algorithm-ov`` literal;
#   - lowercase variants           ``[file:hashes.sha-256 = '...']``;
#   - the legacy non-hyphenated form ``[file:hashes.SHA256 = '...']``.
# The ``('?)`` capture group holds an optional opening quote and the
# ``\1`` backreference requires the closing quote to match it, so
# unbalanced shapes such as ``[file:hashes.'SHA-256 = ...]`` or
# ``[file:hashes.SHA-256' = ...]`` are rejected (would otherwise be
# matched by the previous independent-``'?`` form). ``SHA-?1`` /
# ``SHA-?256`` make the hyphen optional, and the inline ``(?i:...)``
# local flag makes only the algorithm token case-insensitive — the
# surrounding ``[file:hashes...]`` object key stays case-sensitive
# because STIX object types are lower-case-only per spec.

SUPPORTED_STIX_PATTERNS = [
    re.compile(
        r"^\s*\[file:hashes\.(?i:('?)(?:MD5|SHA-?1|SHA-?256)\1)"
        r"\s*=\s*\'[^\']+\'\s*\]\s*$"
    ),
    re.compile(r"^\s*\[domain-name:value\s*=\s*\'[^\']+\'\s*\]\s*$"),
    re.compile(r"^\s*\[url:value\s*=\s*\'[^\']+\'\s*\]\s*$"),
    re.compile(r"^\s*\[ipv4-addr:value\s*=\s*\'[^\']+\'\s*\]\s*$"),
]


class SentinelOneApiError(Exception):
    """Error raised when SentinelOne rejects a request or cannot be reached."""


def describe_response(response: requests.Response) -> str:
    """Describe a failed SentinelOne response: HTTP status and response body excerpt."""
    detail = (response.text or "").strip()
    message = f"HTTP {response.status_code}"
    if detail:
        message = f"{message} - {detail[:MAX_ERROR_DETAIL_LENGTH]}"
    return message


class SentinelOneClient:
    """
    Client class for the SentinelOne API
    """

    def __init__(
        self, config: ConnectorSettings, helper: OpenCTIConnectorHelper
    ) -> None:
        """
        Initialize the SentinelOne client

        :param config: Connector settings
        :param helper: OpenCTI connector helper
        """
        self.config = config.sentinelone_intel
        self.helper = helper

        self.session = requests.Session()
        headers = {
            "Authorization": f"APIToken {self.config.api_key.get_secret_value()}",
            "Content-Type": "application/json",
        }
        self.session.headers.update(headers)

    def create_indicator(self, indicator_msg: dict) -> list[str] | None:
        """
        Create an indicator in SentinelOne from a STIX indicator object

        :param indicator_msg: STIX indicator dictionary containing pattern and metadata
        :return: The `uuid`s of the created IOCs returned by SentinelOne (possibly empty),
            or None when the pattern is not supported (nothing was sent)
        :raises SentinelOneApiError: When SentinelOne rejects the indicator
        """

        # If the Indicator's pattern will not be accepted by the SentinelOne API
        if not self._is_valid_pattern(indicator_msg["pattern"]):
            self.helper.connector_logger.info(
                "[API] Skipping indicator with unsupported pattern"
            )
            return None

        # For a valid pattern, generate and push an Indicator payload
        payload = self._generate_indicator_payload(indicator_msg)
        response = self._push_indicator_payload(payload)
        data = response.get("data") if isinstance(response, dict) else None
        if not isinstance(data, list):
            return []
        return [
            str(item["uuid"])
            for item in data
            if isinstance(item, dict) and item.get("uuid") is not None
        ]

    def _is_valid_pattern(self, pattern: str) -> bool:
        """
        Check if a STIX pattern is in a format that is supported
        by SentinelOne (see README for more information)

        :param pattern: STIX pattern string to validate
        :return: True if pattern is supported, False otherwise
        """
        for valid_pattern in SUPPORTED_STIX_PATTERNS:
            if valid_pattern.match(pattern):
                return True
        return False

    def scope_filter(self) -> dict[str, list[int]]:
        """
        Return the scope (account, site and group ids) the connector pushes the IOCs to,
        as the `filter` keys of the SentinelOne API.
        """
        scope: dict[str, list[int]] = {}
        if (account_id := self.config.account_id) is not None:
            scope["accountIds"] = [account_id]
        if (group_id := self.config.group_id) is not None:
            scope["groupIds"] = [group_id]
        if (site_id := self.config.site_id) is not None:
            scope["siteIds"] = [site_id]
        return scope

    def _scope_params(self) -> dict[str, str]:
        """Return the scope of the connector as query parameters (comma-separated ids)."""
        return {
            key: ",".join(str(value) for value in values)
            for key, values in self.scope_filter().items()
        }

    def _generate_indicator_payload(self, indicator: dict) -> dict:
        """
        Generate the API payload for creating an indicator in SentinelOne

        :param indicator: STIX indicator dictionary
        :return: Formatted payload dictionary for SentinelOne API
        """
        return {
            "bundle": {"objects": [indicator]},
            "filter": {"tenant": "false", **self.scope_filter()},
        }

    def _push_indicator_payload(self, payload: dict) -> Any:
        """
        Send an Indicator payload to SentinelOne API, with relevant
        retry logic to handle retries / back-offs from the SentinelOne
        API.

        :param payload: Formatted payload dictionary for SentinelOne API
        :return: The JSON response of SentinelOne
        :raises SentinelOneApiError: When the request did not succeed
        """
        response = self._request("POST", IOC_ENDPOINT_URL, json=payload)
        self.helper.connector_logger.debug("[API] Indicator payload successfully sent")
        # Rate limiting prevention
        time.sleep(0.2)
        return response

    def iter_iocs(self, max_pages: int = MAX_PAGES) -> Iterator[dict[str, Any]]:
        """
        Iterate over the IOCs of the scope of the connector, paginated with `cursor`.

        Used by the deployment reconciliation to read the pushed IOCs back.

        :raises SentinelOneApiError: On any API error, an unexpected payload, a cursor
            repeating the previous one or when `max_pages` is reached: a partial listing
            is never returned silently.
        """
        yield from self._iter_pages(self._scope_params(), max_pages)

    def find_iocs_by_external_id(
        self, external_id: str, max_pages: int = MAX_PAGES
    ) -> list[dict[str, Any]]:
        """
        List every IOC of the scope of the connector carrying an external id.

        :param external_id: The external id (the STIX id of the pushed indicator).
        :raises SentinelOneApiError: On any API error, an unexpected payload, a cursor
            repeating the previous one or when `max_pages` is reached.
        """
        params = self._scope_params()
        params["externalId"] = external_id
        return list(self._iter_pages(params, max_pages))

    def _iter_pages(
        self, params: dict[str, str], max_pages: int
    ) -> Iterator[dict[str, Any]]:
        """Iterate over the IOCs matching the query parameters, to cursor exhaustion."""
        params = {**params, "limit": str(PAGE_SIZE)}
        cursor: str | None = None
        for _ in range(max_pages):
            page_params = {**params, "cursor": cursor} if cursor else params
            data, next_cursor = self._list_page(page_params)
            yield from data
            if not next_cursor:
                return
            if next_cursor == cursor:
                raise SentinelOneApiError(
                    "SentinelOne returned the same IOC cursor twice, "
                    "the read-back pagination is not honored"
                )
            cursor = next_cursor
        raise SentinelOneApiError(
            f"IOC read-back stopped after {max_pages} pages of {PAGE_SIZE} IOCs"
        )

    def delete_iocs(self, uuids: list[str]) -> None:
        """
        Delete IOCs of the scope of the connector.

        :param uuids: The `uuid`s of the IOCs.
        :raises SentinelOneApiError: When SentinelOne refuses the deletion.
        """
        self._request(
            "DELETE",
            IOCS_ENDPOINT_URL,
            json={"filter": {"uuids": uuids, **self.scope_filter()}},
        )

    def _list_page(
        self, params: dict[str, str]
    ) -> tuple[list[dict[str, Any]], str | None]:
        """Read one page of IOCs: the IOCs and the next cursor."""
        response = self._request("GET", IOCS_ENDPOINT_URL, params=params)
        data = response.get("data") if isinstance(response, dict) else None
        if not isinstance(data, list):
            raise SentinelOneApiError(
                "Unexpected IOC listing response: 'data' is not a list"
            )
        pagination = response.get("pagination") or {}
        next_cursor = (
            pagination.get("nextCursor") if isinstance(pagination, dict) else None
        )
        return [item for item in data if isinstance(item, dict)], next_cursor or None

    def _request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, str] | None = None,
        json: dict[str, Any] | None = None,
    ) -> Any:
        """
        Send a request to the SentinelOne API, retrying throttled requests (HTTP 429)
        with an exponential back-off.

        :return: The JSON response (an empty dictionary when the body is empty)
        :raises SentinelOneApiError: When the request did not succeed, with the HTTP
            status and the SentinelOne response
        """
        timeout = 10
        request_attempts = 3
        backoff_factor = 5

        url = f"{str(self.config.api_url).rstrip('/')}{path}"

        attempt = 0
        while True:
            attempt += 1
            try:
                response = self.session.request(
                    method, url, params=params, json=json, timeout=timeout
                )
            except requests.RequestException as e:
                self.helper.connector_logger.warning(
                    f"[API] Request failed with exception: {e}"
                )
                raise SentinelOneApiError(f"SentinelOne request failed: {e}") from e

            if response.status_code == 429 and attempt < request_attempts:
                delay = self.backoff_delay(backoff_factor, attempt)
                self.helper.connector_logger.debug(
                    f"[API] Rate limited, retrying in {delay} seconds"
                )
                time.sleep(delay)
                continue

            if response.status_code != 200:
                if response.status_code == 429:
                    self.helper.connector_logger.warning(
                        "[API] Rate limited - exhausted all retry attempts"
                    )
                raise SentinelOneApiError(
                    f"SentinelOne request rejected: {describe_response(response)}"
                )
            if not response.content:
                return {}
            try:
                return response.json()
            except ValueError as e:
                raise SentinelOneApiError(
                    "Unexpected SentinelOne response: the body is not JSON"
                ) from e

    @staticmethod
    def backoff_delay(backoff_factor: int, attempts: int) -> float:
        delay = backoff_factor * (2 ** (attempts - 1))
        return delay

"""Read-only client of the Kibana detection engine API."""

from __future__ import annotations

from collections.abc import Callable, Generator
from typing import Any

from connectors_sdk import ApiClientError, ConnectorLogger
from elastic_client.retrying_client import RetryingApiClient

# Versioned Kibana APIs (required on Elastic Cloud Serverless, accepted on 8.x).
_API_VERSION = "2023-10-31"


class ElasticDetectionRulesClient(RetryingApiClient):
    """List the detection rules of a Kibana space.

    Only ``GET`` requests are sent: the connector never creates, modifies
    or enables a rule.
    """

    def __init__(
        self,
        kibana_url: str,
        api_key: str,
        *,
        logger: ConnectorLogger,
        space_id: str | None = None,
        page_size: int = 100,
        timeout: int = 60,
        ssl_verify: bool = True,
        max_retries: int = 5,
        sleep: Callable[[float], None] | None = None,
    ) -> None:
        super().__init__(
            kibana_url,
            logger=logger,
            timeout=timeout,
            ssl_verify=ssl_verify,
            max_retries=max_retries,
            sleep=sleep,
        )
        self._api_key = api_key
        self._space_id = space_id.strip() if space_id else None
        self._page_size = page_size

    @property
    def session_headers(self) -> dict[str, str]:
        """Authenticate with the API key and target the versioned API."""
        return {
            "Authorization": f"ApiKey {self._api_key}",
            "elastic-api-version": _API_VERSION,
            "kbn-xsrf": "true",
        }

    @property
    def space_prefix(self) -> str:
        """URL prefix of the configured Kibana space (empty for the default one)."""
        if not self._space_id or self._space_id == "default":
            return ""
        return f"/s/{self._space_id}"

    def rule_url(self, saved_object_id: str) -> str:
        """Return the URL of a rule in the Kibana Security app."""
        return f"{self._base_url}{self.space_prefix}/app/security/rules/id/{saved_object_id}"

    def iter_rules(
        self, rule_filter: str | None = None
    ) -> Generator[dict[str, Any], None, None]:
        """Yield every detection rule of the space, oldest first."""
        page = 1
        seen = 0
        has_more = True
        while has_more:
            params: dict[str, Any] = {
                "page": page,
                "per_page": self._page_size,
                "sort_field": "created_at",
                "sort_order": "asc",
            }
            if rule_filter:
                params["filter"] = rule_filter
            response = self._get(
                f"{self.space_prefix}/api/detection_engine/rules/_find", params=params
            )
            if not isinstance(response, dict) or not isinstance(
                response.get("data"), list
            ):
                raise ApiClientError(
                    "Unexpected response of the detection engine _find API",
                    response_body=response,
                )
            data = response["data"]
            yield from data
            seen += len(data)
            has_more = bool(data) and seen < int(response.get("total") or 0)
            page += 1

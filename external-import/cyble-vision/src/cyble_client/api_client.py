"""HTTP client for the Cyble Vision Alerts Management API v2."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Generator

from connectors_sdk import ApiClientError, BaseClientApi

ALERTS_PATH = "/ar-apollo-v2/api/v2/y/alerts"
SERVICES_PATH = "/ar-apollo-v2/api/v2/y/services"


def to_vision_timestamp(value: datetime) -> str:
    """Format a datetime the way the Alerts API expects: milliseconds + Z."""
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    value = value.astimezone(timezone.utc)
    return value.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


class CybleVisionClient(BaseClientApi):
    """Thin wrapper around GET /y/services and POST /y/alerts."""

    def __init__(
        self,
        *,
        base_url: str,
        api_token: str,
        page_size: int,
        logger,
    ) -> None:
        super().__init__(base_url=base_url.rstrip("/"))
        self._api_token = api_token
        self._page_size = page_size
        self._logger = logger

    @property
    def session_headers(self) -> dict[str, str]:
        return {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self._api_token}",
        }

    def list_services(self) -> list[str]:
        """Return entitled service names from GET /y/services."""
        try:
            response = self._get(SERVICES_PATH)
        except ApiClientError as err:
            self._logger.error(
                "Failed to list Cyble Vision services",
                {"error": str(err)},
            )
            raise

        rows = response.get("data") if isinstance(response, dict) else response
        names = [row["name"] for row in (rows or []) if row.get("name")]
        self._logger.info(
            "Fetched Cyble Vision services",
            {"count": len(names), "services": names},
        )
        return names

    def iter_alerts(
        self,
        *,
        service: str,
        since: datetime,
        until: datetime,
        exclude_statuses: list[str] | None = None,
    ) -> Generator[list[dict[str, Any]], None, None]:
        """Yield pages of alerts for exactly one service.

        The Alerts API only applies service-specific filters when
        ``filters.service`` contains a single name, so callers must loop
        services themselves.
        """
        skip = 0
        take = self._page_size
        has_more = True

        while has_more:
            body: dict[str, Any] = {
                "orderBy": [{"created_at": "asc"}],
                "filters": {
                    "service": [service],
                    "created_at": {
                        "gte": to_vision_timestamp(since),
                        "lte": to_vision_timestamp(until),
                    },
                },
                "skip": skip,
                "take": take,
                "withDataMessage": True,
            }
            if exclude_statuses:
                body["excludes"] = {"status": exclude_statuses}

            try:
                response = self._post(ALERTS_PATH, json=body)
            except ApiClientError as err:
                self._logger.error(
                    "Failed to fetch Cyble Vision alerts",
                    {"service": service, "skip": skip, "error": str(err)},
                )
                raise

            page = (response.get("data") or {}).get(service) or []
            if not isinstance(page, list):
                page = []

            self._logger.info(
                "Fetched Cyble Vision alerts page",
                {"service": service, "skip": skip, "count": len(page)},
            )

            if page:
                yield page

            has_more = len(page) >= take
            skip += take

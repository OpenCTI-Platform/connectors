"""HTTP client for the Cyble Vision Alerts Management API v2 (write side)."""

from __future__ import annotations

from typing import Any

from connectors_sdk import ApiClientError, BaseClientApi

ALERTS_PATH = "/ar-apollo-v2/api/v2/y/alerts"
MAX_BATCH_SIZE = 100


class CybleVisionClient(BaseClientApi):
    """Thin wrapper around PUT /y/alerts."""

    def __init__(self, *, base_url: str, api_token: str, logger) -> None:
        super().__init__(base_url=base_url.rstrip("/"))
        self._api_token = api_token
        self._logger = logger

    @property
    def session_headers(self) -> dict[str, str]:
        return {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self._api_token}",
        }

    def update_alerts(self, updates: list[dict[str, Any]]) -> Any:
        """Write status and/or user_severity back to Vision.

        Each item needs ``id`` and ``service``. Optional ``status`` and
        ``user_severity``. Batches larger than 100 are split.
        """
        if not updates:
            return {"success": True, "data": []}

        results = []
        for start in range(0, len(updates), MAX_BATCH_SIZE):
            batch = []
            for item in updates[start : start + MAX_BATCH_SIZE]:
                if not item.get("id") or not item.get("service"):
                    raise ApiClientError(
                        "Vision alert update requires both id and service"
                    )
                entry = {"id": item["id"], "service": item["service"]}
                if item.get("status"):
                    entry["status"] = item["status"]
                if item.get("user_severity"):
                    entry["user_severity"] = item["user_severity"]
                batch.append(entry)

            try:
                response = self._put(ALERTS_PATH, json={"alerts": batch})
            except ApiClientError as err:
                self._logger.error(
                    "Failed to update Cyble Vision alerts",
                    {"count": len(batch), "error": str(err)},
                )
                raise
            self._logger.info(
                "Updated Cyble Vision alerts",
                {"count": len(batch)},
            )
            results.append(response)

        if len(results) == 1:
            return results[0]
        return {"success": True, "batches": results}

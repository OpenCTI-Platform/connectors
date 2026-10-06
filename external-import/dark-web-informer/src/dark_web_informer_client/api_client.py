"""Dark Web Informer API client (passthrough mode).

Handles X-API-Key + single-use X-Nonce authentication and 429 backoff, and
fetches the prebuilt STIX 2.1 bundles that DWI publishes. No STIX conversion
is performed here: DWI's native bundles are returned as-is to the connector.
"""

from __future__ import annotations

import secrets
import time
from typing import Any

import requests

__all__ = ["DarkWebInformerClient"]

_DEFAULT_BACKOFF_SECONDS = 60  # DWI returns Retry-After: 60 on every 429
_MAX_RETRIES = 5

# Bulk prebuilt bundle endpoints, per source.
_BULK_ENDPOINT = {
    "all": "/api/stix/export.json",
    "feed": "/api/stix/export_feed.json",
    "ransomware": "/api/stix/export_ransomware.json",
    "iocs": "/api/stix/export_iocs.json",
}


class DarkWebInformerClient:
    """HTTP client returning DWI's native STIX 2.1 bundles."""

    def __init__(
        self,
        helper: Any,
        base_url: str,
        api_key: str,
        timeout: int = 300,
    ) -> None:
        self.helper = helper
        self.base_url = str(base_url).rstrip("/")
        self.api_key = api_key
        self.timeout = timeout
        self.session = requests.Session()

    @staticmethod
    def _build_nonce() -> str:
        """Build an X-Nonce: ``<10-digit epoch>:<>=6 chars [A-Za-z0-9_-]>``."""
        return f"{int(time.time())}:{secrets.token_urlsafe(8)}"

    def _headers(self) -> dict[str, str]:
        return {
            "Accept": "application/json",
            "X-API-Key": self.api_key,
            "X-Nonce": self._build_nonce(),
        }

    def _get(
        self,
        path: str,
        params: dict[str, Any] | None = None,
        _retries: int = _MAX_RETRIES,
    ) -> Any:
        url = f"{self.base_url}/{path.lstrip('/')}"
        response = self.session.get(
            url, headers=self._headers(), params=params or {}, timeout=self.timeout
        )
        if response.status_code == 429 and _retries > 0:
            wait = response.headers.get("Retry-After") or response.headers.get(
                "RateLimit-Reset"
            )
            wait_seconds = (
                int(wait) if wait and str(wait).isdigit() else _DEFAULT_BACKOFF_SECONDS
            )
            self.helper.connector_logger.warning(
                "Rate limited, backing off",
                {"path": path, "wait_seconds": wait_seconds},
            )
            time.sleep(wait_seconds + 1)
            return self._get(path, params, _retries - 1)
        response.raise_for_status()
        return response.json()

    def get_stix_bundle(self, source: str) -> dict:
        """Return DWI's prebuilt STIX 2.1 bundle for a source.

        ``source`` is one of: all, feed, ransomware, iocs.
        """
        endpoint = _BULK_ENDPOINT[source]
        return self._get(endpoint)

    def get_stix_preview(self, source: str = "all", limit: int = 5000) -> dict:
        """Return an on-demand STIX 2.1 bundle (smaller, for testing).

        Uses /api/stix.json?source=...&limit=...
        """
        return self._get("/api/stix.json", {"source": source, "limit": limit})

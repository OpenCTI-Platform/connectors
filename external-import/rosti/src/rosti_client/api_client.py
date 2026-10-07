"""HTTP client for the Rösti API v2.

Retries come from the connectors-sdk client: server errors and 429 responses
with a ``Retry-After`` (the API only sends up to 60 seconds) are retried. When
the API key's quota is used up, the API answers 429 with a "quota exceeded"
problem (RFC 9457) and no ``Retry-After``; after the retries the client raises
``ApiRateLimitError`` and the processor ends the run, keeping its checkpoint.
"""

from __future__ import annotations

import datetime as dt
from collections.abc import Generator
from typing import Any

from connectors_sdk.client.base_client_api import BaseClientApi
from connectors_sdk.client.exceptions import ApiRateLimitError
from rosti_client.models import IOC, Report, Yara, group_iocs

CONNECTOR_VERSION = "0.1.0"
USER_AGENT = f"opencti-connector-rosti/{CONNECTOR_VERSION}"

# Largest page size the API accepts (`limit` maximum in the OpenAPI spec).
MAX_PAGE_SIZE = 1000

# Problem type of a 429 when the quota of the API key is used up.
QUOTA_EXCEEDED_TYPE = "https://iana.org/assignments/http-problem-types#quota-exceeded"


def quota_exceeded(error: BaseException) -> dict[str, Any] | None:
    """The problem details if ``error`` is a "quota exceeded" 429, else None."""
    if not isinstance(error, ApiRateLimitError):
        return None
    body = error.response_body
    if isinstance(body, dict) and str(body.get("type", "")).endswith("#quota-exceeded"):
        return body
    return None


class RostiClient(BaseClientApi):
    """Typed access to the Rösti API endpoints the connector needs."""

    def __init__(  # pylint: disable=too-many-arguments
        self,
        api_key: str,
        base_url: str = "https://api.rosti.dev/v2",
        timeout: int = 60,
        *,
        max_retries: int = 5,
        backoff_factor: float = 2.0,
    ) -> None:
        super().__init__(
            base_url,
            timeout=timeout,
            max_retries=max_retries,
            backoff_factor=backoff_factor,
        )
        self._api_key = api_key

    @property
    def session_headers(self) -> dict[str, str]:
        return {"X-API-Key": self._api_key, "User-Agent": USER_AGENT}

    # ------------------------------------------------------------------
    # Pagination
    # ------------------------------------------------------------------

    def _paginate_cursor(
        self, path: str, params: dict[str, Any] | None = None
    ) -> Generator[list[dict[str, Any]], None, None]:
        """Yield the ``data`` list of every page of a cursor-paginated endpoint."""
        page_params = dict(params or {})
        while True:
            body = self._get(path, params=page_params)
            yield body.get("data") or []
            meta = body.get("meta") or {}
            next_cursor = meta.get("next_cursor")
            if not meta.get("has_more") or not next_cursor:
                return
            page_params["cursor"] = next_cursor

    # ------------------------------------------------------------------
    # Endpoints
    # ------------------------------------------------------------------

    def iter_updated_reports(
        self, since: dt.datetime, page_size: int = 100
    ) -> Generator[list[Report], None, None]:
        """Reports created or updated after ``since``, oldest change first.

        ``GET /reports?timestamp=…&sort=last_updated``
        """
        params = {
            "timestamp": since.astimezone(dt.timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            ),
            "sort": "last_updated",
            "limit": page_size,
        }
        for page in self._paginate_cursor("/reports", params):
            yield [Report.model_validate(item) for item in page]

    def get_report(self, report_id: str) -> Report:
        """Report metadata with MITRE IDs, CVEs and notes.

        ``GET /reports/{id}?mitre_ids=true&cve=true&notes=true``
        """
        body = self._get(
            f"/reports/{report_id}",
            params={"mitre_ids": "true", "cve": "true", "notes": "true"},
        )
        return Report.model_validate(body)

    def iter_report_ioc_groups(
        self, report_id: str, page_size: int = MAX_PAGE_SIZE
    ) -> Generator[list[IOC], None, None]:
        """IOCs of a report, grouped by ``entity_ref``. ``GET /reports/{id}/iocs``

        Pages are loaded one at a time. A group that ends a page is held back
        until the next page has been loaded, so every yielded group is complete.
        """

        def iocs() -> Generator[IOC, None, None]:
            for page in self._paginate_cursor(
                f"/reports/{report_id}/iocs", {"limit": page_size}
            ):
                for item in page:
                    yield IOC.model_validate(item)

        yield from group_iocs(iocs())

    def get_report_ioc_groups(self, report_id: str) -> list[list[IOC]]:
        """All IOC groups of a report (see ``iter_report_ioc_groups``)."""
        return list(self.iter_report_ioc_groups(report_id))

    def get_report_iocs(self, report_id: str) -> list[IOC]:
        """All IOCs of a report, in API order."""
        return [
            ioc for group in self.iter_report_ioc_groups(report_id) for ioc in group
        ]

    def get_report_yara_rules(self, report_id: str) -> list[Yara]:
        """YARA rules of a report. ``GET /reports/{id}/yara-rules``"""
        body = self._get(f"/reports/{report_id}/yara-rules")
        return [Yara.model_validate(item) for item in body.get("data") or []]

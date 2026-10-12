from __future__ import annotations

import hashlib
import secrets
import string
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

from connectors_sdk import ApiClientError, BaseClientApi
from cortex_xdr_client.types import IocFilter, IocPayload

if TYPE_CHECKING:
    from collections.abc import Iterator

    from pydantic import HttpUrl

PAGE_SIZE = 100
"""Records per call (`search_to - search_from`) of the IOCs and alerts read-back."""

IOC_ALERT_SOURCE = "XDR IOC"
"""`alert_source` of the alerts raised when an IOC matches."""


class CortexXdrApiError(Exception):
    """Exception raised when the Cortex XDR API returns an error."""

    pass


class CortexXdrRejectedIocsError(CortexXdrApiError):
    """Raised when Cortex XDR answers an upsert with IOCs it did not take.

    The HTTP status is a success, but the reply lists `errors`: none or only some of
    the IOCs of the indicator were inserted or updated.
    """

    def __init__(self, message: str, errors: list[Any]) -> None:
        super().__init__(message)
        self.errors = errors


def _reply_errors(response: Any) -> list[Any]:
    """Return the `errors` of a response, unwrapping the optional `reply` envelope."""
    reply = response.get("reply", response) if isinstance(response, dict) else None
    errors = reply.get("errors") if isinstance(reply, dict) else None
    if not errors:
        return []
    return errors if isinstance(errors, list) else [errors]


def _reply_list(response: Any, key: str, endpoint: str) -> list[dict[str, Any]]:
    """Return the `key` list of a response, unwrapping the optional `reply` envelope.

    Raises:
        CortexXdrApiError: When the list is missing or holds a row that is not an
            object, so that a read-back is never mistaken for an empty or shorter
            listing.
    """
    reply = response.get("reply", response) if isinstance(response, dict) else None
    items = reply.get(key) if isinstance(reply, dict) else None
    if not isinstance(items, list):
        raise CortexXdrApiError(
            f"Unexpected response format of {endpoint}: missing '{key}' list"
        )
    if not all(isinstance(item, dict) for item in items):
        raise CortexXdrApiError(
            f"Unexpected response format of {endpoint}: a '{key}' row is not an object"
        )
    return items


class CortexXdrClient(BaseClientApi):
    """
    Client for the Palo Alto Cortex XDR "Insert or update IOCs", "Get
    Indicators (IOCs)" and "Delete Indicators/IOCs" APIs.

    Reference:
        https://cortex-docs.paloaltonetworks.com/xdr-5-api/cortex-platform/iocs
    """

    def __init__(self, api_base_url: HttpUrl, api_key_id: str, api_key: str) -> None:
        super().__init__(str(api_base_url))
        self._api_key_id = api_key_id
        self._api_key = api_key

    @property
    def session_headers(self) -> dict[str, str]:
        """Static headers applied once when the session is created."""
        return {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    def _build_auth_headers(self) -> dict[str, str]:
        """Build fresh Advanced API key authentication headers.

        A new nonce and timestamp are generated for every call, as required by
        Cortex XDR's Advanced API key auth to prevent replay attacks: static,
        session-level headers would reuse the same nonce/timestamp/hash across
        requests and defeat that protection.

        Reference:
            https://cortex-docs.paloaltonetworks.com/xdr-5-api/make-your-first-api-call
        """
        # 64-char random alphanumeric string, single-use ("number used once").
        nonce = "".join(
            secrets.choice(string.ascii_letters + string.digits) for _ in range(64)
        )
        # Current UTC time in milliseconds.
        timestamp = int(datetime.now(timezone.utc).timestamp() * 1000)
        auth_key = f"{self._api_key}{nonce}{timestamp}".encode("utf-8")
        api_key_hash = hashlib.sha256(auth_key).hexdigest()

        return {
            "x-xdr-timestamp": str(timestamp),
            "x-xdr-nonce": nonce,
            "x-xdr-auth-id": str(self._api_key_id),
            "Authorization": api_key_hash,
        }

    def get_iocs(self, filters: list[IocFilter]) -> dict:
        """Fetch existing IOCs matching any of the given indicator values
        (single batched request), primarily to read back their `rule_id`.

        Reference:
            https://cortex-docs.paloaltonetworks.com/xdr-5-api/cortex-platform/iocs#post-public_api-v1-indicators-get
        """
        request_filters = [
            {
                "field": filter_.get("field", "indicator"),
                "operator": filter_.get("operator"),
                "value": filter_.get("value"),
            }
            for filter_ in filters  # 'filter_' prevents shadowing the built-in `filter` function
        ]

        try:
            return self._post(
                "/public_api/v1/indicators/get",
                headers=self._build_auth_headers(),
                json={
                    "request_data": {
                        "filters": request_filters,
                    }
                },
            )
        except ApiClientError as err:
            raise CortexXdrApiError("Error while fetching Cortex XDR API") from err

    def insert_iocs(self, iocs: list[IocPayload]) -> dict:
        """Insert new IOCs or update existing ones (single batched request).

        Optional fields omitted by the caller default to `None`, and
        `default_expiration_enabled` is derived from `expiration_date`,
        since the Cortex XDR API requires every field to be present in the
        request body. `rule_id` is the exception: it is only included when
        the caller provides one (Cortex XDR only accepts a numeric value or
        no key at all for it), and is what makes Cortex XDR *overwrite* an
        already existing IOC instead of failing with a 400 "IOC indicator
        exists" (see `get_iocs`).

        Reference:
            https://cortex-docs.paloaltonetworks.com/xdr-5-api/cortex-platform/iocs#post-public_api-v1-indicators-insert

        Raises:
            CortexXdrRejectedIocsError: When the reply lists `errors`, even with a
                success status and some IOCs inserted.
            CortexXdrApiError: When the request fails.
        """
        request_data = [
            {
                "indicator": ioc.get("indicator"),
                "type": ioc.get("type"),
                "severity": ioc.get("severity"),
                "expiration_date": ioc.get("expiration_date"),
                "default_expiration_enabled": ioc.get("expiration_date") is None,
                "comment": ioc.get("comment"),
                "reputation": ioc.get("reputation"),
                "reliability": ioc.get("reliability"),
                **(
                    {"rule_id": ioc.get("rule_id")}
                    if ioc.get("rule_id") is not None
                    else {}
                ),
            }
            for ioc in iocs
        ]
        try:
            response = self._post(
                "/public_api/v1/indicators/insert",
                headers=self._build_auth_headers(),
                json={"request_data": request_data},
            )
        except ApiClientError as err:
            raise CortexXdrApiError("Error while fetching Cortex XDR API") from err
        errors = _reply_errors(response)
        if errors:
            raise CortexXdrRejectedIocsError(
                f"Cortex XDR rejected {len(errors)} of the {len(iocs)} IOC(s) sent",
                errors,
            )
        return response

    def delete_iocs(self, filters: list[IocFilter]) -> dict:
        """Delete IOCs selected by the given filters (single batched request).

        `field` and `operator` default to "indicator" and "EQ" respectively
        when omitted by the caller.

        Reference:
            https://cortex-docs.paloaltonetworks.com/xdr-5-api/cortex-platform/iocs#post-public_api-v1-indicators-delete
        """
        request_filters = [
            {
                "field": filter_.get("field", "indicator"),
                "operator": filter_.get("operator"),
                "value": filter_["value"],  # required
            }
            for filter_ in filters  # 'filter_' prevents shadowing the built-in `filter` function
        ]

        try:
            return self._post(
                "/public_api/v1/indicators/delete",
                headers=self._build_auth_headers(),
                json={"request_data": {"filters": request_filters}},
            )
        except ApiClientError as err:
            raise CortexXdrApiError("Error while fetching Cortex XDR API") from err

    def iter_iocs(
        self, page_size: int = PAGE_SIZE, max_pages: int = 10_000
    ) -> Iterator[dict[str, Any]]:
        """Iterate over every IOC of the tenant, paginated with `search_from` / `search_to`.

        Used by the deployment reconciliation to read the pushed IOCs back.

        Raises:
            CortexXdrApiError: On any API error, an unexpected payload, a page
                repeating the previous one (pagination not honored) or when
                `max_pages` is reached: a partial listing is never returned silently.

        Reference:
            https://cortex-docs.paloaltonetworks.com/xdr-5-api/cortex-platform/iocs#post-public_api-v1-indicators-get
        """
        previous_first: Any = None
        for page in range(max_pages):
            search_from = page * page_size
            try:
                response = self._post(
                    "/public_api/v1/indicators/get",
                    headers=self._build_auth_headers(),
                    json={
                        "request_data": {
                            "filters": [],
                            "search_from": search_from,
                            "search_to": search_from + page_size,
                        }
                    },
                )
            except ApiClientError as err:
                raise CortexXdrApiError("Error while fetching Cortex XDR API") from err
            objects = _reply_list(response, "objects", "indicators/get")
            if objects:
                first = (objects[0].get("rule_id"), objects[0].get("indicator"))
                if page > 0 and first == previous_first:
                    raise CortexXdrApiError(
                        "Cortex XDR returned the same IOC page twice, "
                        "the read-back pagination is not honored"
                    )
                previous_first = first
            yield from objects
            if len(objects) < page_size:
                return
        raise CortexXdrApiError(
            f"IOC read-back stopped after {max_pages} pages of {page_size} IOCs"
        )

    def get_ioc_alerts(
        self, since: datetime, max_alerts: int = 10_000, offset: int = 0
    ) -> list[dict[str, Any]]:
        """List the IOC alerts (`alert_source` "XDR IOC") created since a date, with their events.

        Alerts are read oldest first: when `max_alerts` alerts are returned, the read
        is complete until the newest alert returned.

        Args:
            since: Only list the alerts created at or after this date.
            max_alerts: Maximum number of alerts returned.
            offset: Number of the oldest matching alerts to skip (continuation of a
                read capped by alerts sharing its start instant).

        Raises:
            CortexXdrApiError: On any API error, an unexpected payload or a page
                repeating the previous one (pagination not honored): the same alerts
                are never returned twice.

        Reference:
            https://cortex-docs.paloaltonetworks.com/xdr-5-api/cortex-xdr-api/get-alerts-multi-events
        """
        since_ms = int(since.timestamp() * 1000)
        alerts: list[dict[str, Any]] = []
        previous_first: Any = None
        while len(alerts) < max_alerts:
            size = min(PAGE_SIZE, max_alerts - len(alerts))
            try:
                response = self._post(
                    "/public_api/v1/alerts/get_alerts_multi_events",
                    headers=self._build_auth_headers(),
                    json={
                        "request_data": {
                            "filters": [
                                {
                                    "field": "creation_time",
                                    "operator": "gte",
                                    "value": since_ms,
                                },
                                {
                                    "field": "alert_source",
                                    "operator": "in",
                                    "value": [IOC_ALERT_SOURCE],
                                },
                            ],
                            "search_from": offset + len(alerts),
                            "search_to": offset + len(alerts) + size,
                            "sort": {"field": "creation_time", "keyword": "asc"},
                        }
                    },
                )
            except ApiClientError as err:
                raise CortexXdrApiError("Error while fetching Cortex XDR API") from err
            page = _reply_list(response, "alerts", "alerts/get_alerts_multi_events")
            if page:
                first = (
                    page[0].get("alert_id"),
                    page[0].get("local_insert_ts"),
                    page[0].get("detection_timestamp"),
                )
                if alerts and first == previous_first:
                    raise CortexXdrApiError(
                        "Cortex XDR returned the same alert page twice, "
                        "the alert pagination is not honored"
                    )
                previous_first = first
            alerts.extend(page[:size])
            if len(page) < size:
                break
        return alerts

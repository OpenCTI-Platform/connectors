from __future__ import annotations

import hashlib
import secrets
import string
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from connectors_sdk import ApiClientError, BaseClientApi
from cortex_xdr_client.types import IocFilter, IocPayload

if TYPE_CHECKING:
    from pydantic import HttpUrl


class CortexXdrApiError(Exception):
    """Exception raised when the Cortex XDR API returns an error."""

    pass


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
            return self._post(
                "/public_api/v1/indicators/insert",
                headers=self._build_auth_headers(),
                json={"request_data": request_data},
            )
        except ApiClientError as err:
            raise CortexXdrApiError("Error while fetching Cortex XDR API") from err

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

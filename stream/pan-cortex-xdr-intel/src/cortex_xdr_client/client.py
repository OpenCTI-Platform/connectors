from __future__ import annotations

import hashlib
import secrets
import string
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Literal

from connectors_sdk import ApiClientError, BaseClientApi
from cortex_xdr_client.exceptions import CortexXdrApiError, CortexXdrRequestBodyError
from cortex_xdr_client.models import IndicatorData, IndicatorFilters
from cortex_xdr_client.utils import datetime_to_utc
from pydantic import ValidationError

if TYPE_CHECKING:
    from pydantic import HttpUrl


class CortexXdrClient(BaseClientApi):
    """
    Client for the Palo Alto Cortex XDR "Insert or update IOCs" and "Delete
    Indicators/IOCs" APIs.

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
        timestamp = int(datetime.now(timezone.utc).timestamp()) * 1000

        auth_key = f"{self._api_key}{nonce}{timestamp}".encode("utf-8")
        api_key_hash = hashlib.sha256(auth_key).hexdigest()

        return {
            "x-xdr-timestamp": str(timestamp),
            "x-xdr-nonce": nonce,
            "x-xdr-auth-id": str(self._api_key_id),
            "Authorization": api_key_hash,
        }

    def upsert_indicator(
        self,
        value: str,
        type: Literal["HASH", "IP", "PATH", "DOMAIN_NAME", "FILENAME", "MIXED"],
        severity: (
            Literal["SEV_010_INFO", "SEV_020_LOW", "SEV_030_MEDIUM", "SEV_040_HIGH"]
            | None
        ) = None,
        expiration: datetime | None = None,
        comment: str | None = None,
        reputation: (
            Literal["GOOD", "BAD", "SUSPICIOUS", "UNKNOWN", "NO_REPUTATION"] | None
        ) = None,
        reliability: Literal["A", "B", "C", "D"] | None = None,
    ) -> dict:
        """Insert new indicator or update existing one.

        Reference:
            POST /public_api/v1/indicators/insert
        """
        try:
            # Validate and serialize data before sending the request to fail fast if the data is invalid.
            indicator_data = IndicatorData(
                indicator=value,
                type=type,
                severity=severity,
                expiration_date=datetime_to_utc(expiration) if expiration else None,
                comment=comment,
                reputation=reputation,
                reliability=reliability,
            )
            # Important: do not exclude `None` values, as the API requires all fields to be present.
            indicator_dict = indicator_data.model_dump(mode="json", exclude_none=False)
        except ValidationError as err:
            raise CortexXdrRequestBodyError("Invalid request's body") from err

        try:
            return self._post(
                "/public_api/v1/indicators/insert",
                headers=self._build_auth_headers(),
                json={"request_data": [indicator_dict]},
            )
        except ApiClientError as err:
            raise CortexXdrApiError("Error while fetching Cortex XDR API") from err

    def delete_indicator(self, value: str) -> dict:
        """Delete indicator selected by filter.

        Reference:
            POST /public_api/v1/indicators/delete
        """
        try:
            # Validate and serialize filters before sending the request to fail fast if the filters are invalid.
            indicator_filters = IndicatorFilters(value=value).model_dump(
                mode="json", exclude_none=True
            )
        except ValidationError as err:
            raise CortexXdrRequestBodyError("Invalid request's body") from err

        try:
            return self._post(
                "/public_api/v1/indicators/delete",
                headers=self._build_auth_headers(),
                json={
                    "request_data": {
                        "filters": [indicator_filters],
                    }
                },
            )
        except ApiClientError as err:
            raise CortexXdrApiError("Error while fetching Cortex XDR API") from err

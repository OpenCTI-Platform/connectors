"""Read-only client of the CrowdStrike Falcon custom IOA API."""

from __future__ import annotations

import time
from collections.abc import Callable, Generator
from typing import Any

import requests
from connectors_sdk import ApiClientError, ApiUnauthorizedError, ConnectorLogger
from crowdstrike_client.retrying_client import RetryingApiClient

# Refresh the access token this many seconds before it expires.
_TOKEN_EXPIRY_MARGIN = 120
# Rule group ids per entities request.
_ENTITIES_BATCH_SIZE = 100
# Prevention policies per page (the API accepts up to 5000).
_POLICIES_PAGE_SIZE = 500


def _pagination_total(response: dict[str, Any]) -> int:
    """Return the total the API reports in ``meta.pagination``."""
    pagination = (response.get("meta") or {}).get("pagination") or {}
    return int(pagination.get("total") or 0)


def _incomplete_listing(
    what: str, offset: int, total: int, response: dict[str, Any]
) -> ApiClientError:
    """Build the error raised when a listing ends before its reported total."""
    return ApiClientError(
        f"The CrowdStrike API returned an empty page of {what} at offset "
        f"{offset} of {total}: the listing is incomplete",
        response_body=response,
    )


class CrowdStrikeIoaClient(RetryingApiClient):
    """List the custom IOA rule groups of a CrowdStrike Falcon CID.

    Authenticates with the OAuth 2.0 client credentials flow. Only ``GET``
    requests are sent to the custom IOA and prevention policy APIs: the
    connector never creates, modifies or enables a rule, a rule group or a
    policy.
    """

    def __init__(
        self,
        base_url: str,
        client_id: str,
        client_secret: str,
        *,
        logger: ConnectorLogger,
        member_cid: str | None = None,
        page_size: int = 100,
        timeout: int = 60,
        max_retries: int = 5,
        sleep: Callable[[float], None] | None = None,
    ) -> None:
        super().__init__(
            base_url,
            logger=logger,
            timeout=timeout,
            max_retries=max_retries,
            sleep=sleep,
        )
        self._client_id = client_id
        self._client_secret = client_secret
        self._member_cid = member_cid
        self._page_size = page_size
        self._token: str | None = None
        self._token_expires_at = 0.0

    def retry_after(self, response: requests.Response) -> float | None:
        """Honor ``Retry-After``, else ``X-RateLimit-RetryAfter`` (epoch seconds)."""
        delay = super().retry_after(response)
        if delay is not None:
            return delay
        retry_at = response.headers.get("X-RateLimit-RetryAfter")
        try:
            return max(float(retry_at) - time.time(), 0.0) if retry_at else None
        except ValueError:
            return None

    # -- authentication ---------------------------------------------------
    def _access_token(self) -> str:
        if self._token is None or time.monotonic() >= self._token_expires_at:
            data = {"client_id": self._client_id, "client_secret": self._client_secret}
            if self._member_cid:
                data["member_cid"] = self._member_cid
            response = self._post("/oauth2/token", data=data)
            if not isinstance(response, dict) or not response.get("access_token"):
                raise ApiUnauthorizedError("CrowdStrike returned no access token")
            self._token = str(response["access_token"])
            lifetime = float(response.get("expires_in") or 1799)
            self._token_expires_at = time.monotonic() + max(
                lifetime - _TOKEN_EXPIRY_MARGIN, 0.0
            )
        return self._token

    def _authorized_get(self, path: str, params: dict[str, Any]) -> dict[str, Any]:
        try:
            response = self._get(
                path,
                params=params,
                headers={"Authorization": f"Bearer {self._access_token()}"},
            )
        except ApiUnauthorizedError:
            # The token may have been revoked: ask for a new one once.
            self._token = None
            response = self._get(
                path,
                params=params,
                headers={"Authorization": f"Bearer {self._access_token()}"},
            )
        if not isinstance(response, dict) or not isinstance(
            response.get("resources", []), list
        ):
            raise ApiClientError(
                f"Unexpected response of the CrowdStrike API on {path}",
                response_body=response,
            )
        errors = response.get("errors") or []
        if errors:
            raise ApiClientError(
                f"CrowdStrike API errors on {path}: {errors}", response_body=response
            )
        return response

    # -- custom IOA rule groups ------------------------------------------
    def iter_rule_group_ids(
        self, rule_group_filter: str | None = None
    ) -> Generator[str, None, None]:
        """Yield the id of every rule group matching the filter.

        Raises:
            ApiClientError: When a page is empty before the reported total is
                reached, so an incomplete listing is never taken for the full
                set of rule groups.
        """
        offset = 0
        has_more = True
        while has_more:
            params: dict[str, Any] = {"offset": str(offset), "limit": self._page_size}
            if rule_group_filter:
                params["filter"] = rule_group_filter
            response = self._authorized_get("/ioarules/queries/rule-groups/v1", params)
            ids = [
                str(rule_group_id) for rule_group_id in response.get("resources") or []
            ]
            total = _pagination_total(response)
            if not ids and offset < total:
                raise _incomplete_listing("rule groups", offset, total, response)
            yield from ids
            offset += len(ids)
            has_more = bool(ids) and offset < total

    def iter_rule_groups(
        self, rule_group_filter: str | None = None
    ) -> Generator[dict[str, Any], None, None]:
        """Yield every rule group matching the filter, with its rules."""
        ids = list(self.iter_rule_group_ids(rule_group_filter))
        for start in range(0, len(ids), _ENTITIES_BATCH_SIZE):
            response = self._authorized_get(
                "/ioarules/entities/rule-groups/v1",
                {"ids": ids[start : start + _ENTITIES_BATCH_SIZE]},
            )
            yield from response.get("resources") or []

    # -- prevention policies ----------------------------------------------
    def iter_prevention_policies(self) -> Generator[dict[str, Any], None, None]:
        """Yield every prevention policy, with its assigned custom IOA rule groups.

        Raises:
            ApiClientError: When a page is empty before the reported total is
                reached, so an incomplete listing never hides an enforcing
                policy.
        """
        offset = 0
        has_more = True
        while has_more:
            response = self._authorized_get(
                "/policy/combined/prevention/v1",
                {"offset": offset, "limit": _POLICIES_PAGE_SIZE},
            )
            resources = response.get("resources") or []
            total = _pagination_total(response)
            if not resources and offset < total:
                raise _incomplete_listing(
                    "prevention policies", offset, total, response
                )
            yield from (policy for policy in resources if isinstance(policy, dict))
            offset += len(resources)
            has_more = bool(resources) and offset < total

    def enforced_rule_group_ids(self) -> set[str]:
        """Return the rule groups assigned to at least one enabled prevention policy.

        A custom IOA rule group only runs on the hosts of the prevention
        policies it is assigned to.
        """
        return {
            str(rule_group["id"])
            for policy in self.iter_prevention_policies()
            if policy.get("enabled")
            for rule_group in policy.get("ioa_rule_groups") or []
            if isinstance(rule_group, dict) and rule_group.get("id")
        }

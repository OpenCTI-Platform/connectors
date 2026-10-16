"""Read-only client of the Microsoft Sentinel alert rules (Azure Resource Manager)."""

from __future__ import annotations

import time
from collections.abc import Callable, Generator
from typing import Any
from urllib.parse import quote, urlsplit

from connectors_sdk import ApiClientError, ApiUnauthorizedError, ConnectorLogger
from sentinel_client.retrying_client import RetryingApiClient

# Refresh the access token this many seconds before it expires.
_TOKEN_EXPIRY_MARGIN = 120


class SentinelAlertRulesClient(RetryingApiClient):
    """List the analytics (alert) rules of a Microsoft Sentinel workspace.

    Authenticates with the OAuth 2.0 client credentials flow of Microsoft
    Entra ID. Only ``GET`` requests are sent to Azure Resource Manager: the
    connector never creates, modifies or enables a rule.
    """

    def __init__(
        self,
        *,
        tenant_id: str,
        client_id: str,
        client_secret: str,
        subscription_id: str,
        resource_group: str,
        workspace_name: str,
        api_version: str,
        logger: ConnectorLogger,
        management_url: str = "https://management.azure.com",
        login_url: str = "https://login.microsoftonline.com",
        timeout: int = 60,
        max_retries: int = 5,
        sleep: Callable[[float], None] | None = None,
    ) -> None:
        super().__init__(
            management_url,
            logger=logger,
            timeout=timeout,
            max_retries=max_retries,
            sleep=sleep,
        )
        self._tenant_id = tenant_id
        self._client_id = client_id
        self._client_secret = client_secret
        self._login_url = login_url.rstrip("/")
        self._api_version = api_version
        self._rules_path = (
            f"/subscriptions/{quote(subscription_id, safe='')}"
            f"/resourceGroups/{quote(resource_group, safe='')}"
            "/providers/Microsoft.OperationalInsights"
            f"/workspaces/{quote(workspace_name, safe='')}"
            "/providers/Microsoft.SecurityInsights/alertRules"
        )
        self._token: str | None = None
        self._token_expires_at = 0.0

    # -- authentication ---------------------------------------------------
    def _access_token(self) -> str:
        if self._token is None or time.monotonic() >= self._token_expires_at:
            response = self._post(
                f"{self._login_url}/{quote(self._tenant_id, safe='')}/oauth2/v2.0/token",
                data={
                    "grant_type": "client_credentials",
                    "client_id": self._client_id,
                    "client_secret": self._client_secret,
                    "scope": f"{self._base_url}/.default",
                },
            )
            if not isinstance(response, dict) or not response.get("access_token"):
                raise ApiUnauthorizedError(
                    "Microsoft Entra ID returned no access token"
                )
            self._token = str(response["access_token"])
            lifetime = float(response.get("expires_in") or 3600)
            self._token_expires_at = time.monotonic() + max(
                lifetime - _TOKEN_EXPIRY_MARGIN, 0.0
            )
        return self._token

    def _authorized_get(self, url: str, params: dict[str, Any] | None) -> Any:
        try:
            return self._get(
                url,
                params=params,
                headers={"Authorization": f"Bearer {self._access_token()}"},
            )
        except ApiUnauthorizedError:
            # The token may have been revoked or rotated: ask for a new one once.
            self._token = None
            return self._get(
                url,
                params=params,
                headers={"Authorization": f"Bearer {self._access_token()}"},
            )

    # -- alert rules ------------------------------------------------------
    def iter_alert_rules(self) -> Generator[dict[str, Any], None, None]:
        """Yield every alert rule of the workspace, following ``nextLink``."""
        url: str | None = self._rules_path
        params: dict[str, Any] | None = {"api-version": self._api_version}
        while url:
            response = self._authorized_get(url, params)
            if not isinstance(response, dict) or not isinstance(
                response.get("value"), list
            ):
                raise ApiClientError(
                    "Unexpected response of the Microsoft Sentinel alertRules API",
                    response_body=response,
                )
            yield from response["value"]
            url = response.get("nextLink") or None
            # ``nextLink`` carries the api-version and the continuation token.
            params = None
            if url is not None:
                self._check_same_host(url)

    def _check_same_host(self, url: str) -> None:
        """Never send the access token outside Azure Resource Manager."""
        expected = urlsplit(self._base_url)
        actual = urlsplit(url)
        if (actual.scheme, actual.netloc) != (expected.scheme, expected.netloc):
            raise ApiClientError(
                f"Refusing to follow a nextLink outside {expected.netloc}: {actual.netloc}"
            )

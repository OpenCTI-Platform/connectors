"""Read-only client of the Google SecOps detection rules (Chronicle API)."""

from __future__ import annotations

import re
from collections.abc import Callable, Generator
from typing import Any, Protocol
from urllib.parse import quote, urlsplit, urlunsplit

from connectors_sdk import ApiClientError, ApiUnauthorizedError, ConnectorLogger
from google.auth.exceptions import GoogleAuthError, RefreshError
from google.auth.transport.requests import Request
from google.oauth2 import service_account
from secops_client.retrying_client import RetryingApiClient

SCOPES = ["https://www.googleapis.com/auth/cloud-platform"]
# ``.../rules/ru_<uuid>`` or ``.../rules/ru_<uuid>/deployment``, with an
# optional ``@<revision>`` suffix on the rule id.
_RULE_ID_RE = re.compile(r"/rules/([^/@]+)")


class Credentials(Protocol):
    """The part of ``google.auth.credentials.Credentials`` the client uses."""

    token: str | None

    @property
    def valid(self) -> bool:
        """Tell whether ``token`` is set and not expired."""

    def refresh(self, request: Any) -> None:
        """Get a new access token into ``token``."""


def service_account_credentials(
    *,
    client_email: str,
    private_key: str,
    token_uri: str,
    private_key_id: str | None = None,
    project_id: str | None = None,
) -> service_account.Credentials:
    """Build service account credentials scoped to the Chronicle API.

    Raises ``ValueError`` when the private key cannot be read.
    """
    info: dict[str, str] = {
        "type": "service_account",
        "client_email": client_email,
        "private_key": private_key,
        "token_uri": token_uri,
    }
    if private_key_id:
        info["private_key_id"] = private_key_id
    if project_id:
        info["project_id"] = project_id
    return service_account.Credentials.from_service_account_info(info, scopes=SCOPES)


def regional_url(base_url: str, region: str) -> str:
    """Prefix the host of ``base_url`` with the region (``us-chronicle...``)."""
    parts = urlsplit(base_url.rstrip("/"))
    return urlunsplit(
        (parts.scheme, f"{region}-{parts.netloc}", parts.path, "", "")
    ).rstrip("/")


def rule_id_from_name(name: object) -> str | None:
    """Return the rule id (``ru_<uuid>``) of a rule or rule deployment name."""
    match = _RULE_ID_RE.search(str(name or ""))
    return match.group(1) if match else None


class GoogleSecOpsRulesClient(RetryingApiClient):
    """List the detection rules of a Google SecOps instance and their deployment.

    Authenticates as a service account (OAuth 2.0 JWT bearer flow of the
    Google auth library). Only ``GET`` requests are sent to the Chronicle
    API: the connector never creates, modifies, enables or archives a rule.
    """

    def __init__(
        self,
        *,
        base_url: str,
        region: str,
        project_id: str,
        instance_id: str,
        api_version: str,
        credentials: Credentials,
        logger: ConnectorLogger,
        page_size: int = 1000,
        timeout: int = 60,
        max_retries: int = 5,
        sleep: Callable[[float], None] | None = None,
        auth_request: Callable[[], Any] = Request,
    ) -> None:
        super().__init__(
            regional_url(base_url, region),
            logger=logger,
            timeout=timeout,
            max_retries=max_retries,
            sleep=sleep,
        )
        self._credentials = credentials
        self._auth_request = auth_request
        self._page_size = page_size
        self._instance_path = (
            f"/{quote(api_version, safe='')}"
            f"/projects/{quote(project_id, safe='')}"
            f"/locations/{quote(region, safe='')}"
            f"/instances/{quote(instance_id, safe='')}"
        )

    # -- authentication ---------------------------------------------------
    def _refresh_token(self) -> None:
        try:
            self._credentials.refresh(self._auth_request())
        except RefreshError as err:
            raise ApiUnauthorizedError(
                f"Google rejected the service account credentials: {err}"
            ) from err
        except GoogleAuthError as err:
            raise ApiClientError(
                f"Could not get an access token from Google: {err}"
            ) from err

    def _access_token(self) -> str:
        if not self._credentials.valid:
            self._refresh_token()
        if not self._credentials.token:
            raise ApiUnauthorizedError("Google returned no access token")
        return str(self._credentials.token)

    def _authorized_get(self, path: str, params: dict[str, Any]) -> dict[str, Any]:
        try:
            response = self._get(
                path,
                params=params,
                headers={"Authorization": f"Bearer {self._access_token()}"},
            )
        except ApiUnauthorizedError:
            # The token may have been revoked: ask for a new one once.
            self._refresh_token()
            response = self._get(
                path,
                params=params,
                headers={"Authorization": f"Bearer {self._access_token()}"},
            )
        if response is None:
            return {}
        if not isinstance(response, dict):
            raise ApiClientError(
                f"Unexpected response of the Chronicle API on {path}",
                response_body=response,
            )
        return response

    def _paginate(
        self, path: str, items_key: str, params: dict[str, Any] | None = None
    ) -> Generator[dict[str, Any], None, None]:
        """Yield the items of every page, following ``nextPageToken``."""
        page_token: str | None = None
        seen_tokens: set[str] = set()
        has_more = True
        while has_more:
            query: dict[str, Any] = {**(params or {}), "pageSize": self._page_size}
            if page_token:
                query["pageToken"] = page_token
            response = self._authorized_get(self._instance_path + path, query)
            items = response.get(items_key) or []
            if not isinstance(items, list):
                raise ApiClientError(
                    f"Unexpected response of the Chronicle API on {path}",
                    response_body=response,
                )
            yield from (item for item in items if isinstance(item, dict))
            page_token = response.get("nextPageToken") or None
            if page_token in seen_tokens:
                raise ApiClientError(
                    f"The Chronicle API returned the same page token twice on {path}"
                )
            if page_token:
                seen_tokens.add(page_token)
            has_more = page_token is not None

    # -- rules ------------------------------------------------------------
    def iter_rules(self) -> Generator[dict[str, Any], None, None]:
        """Yield every rule of the instance, with its YARA-L text and metadata."""
        yield from self._paginate("/rules", "rules", {"view": "FULL"})

    def iter_rule_deployments(self) -> Generator[dict[str, Any], None, None]:
        """Yield the deployment (live, alerting, archived) of every rule."""
        yield from self._paginate("/rules/-/deployments", "ruleDeployments")

    def rule_deployments(self) -> dict[str, dict[str, Any]]:
        """Return the deployment of every rule, keyed by rule id."""
        deployments: dict[str, dict[str, Any]] = {}
        for deployment in self.iter_rule_deployments():
            rule_id = rule_id_from_name(deployment.get("name"))
            if rule_id:
                deployments[rule_id] = deployment
        return deployments

"""Google SecOps API client with Google OAuth2 service-account auth."""

import asyncio
from collections.abc import AsyncIterator
from typing import Any

from google.auth.transport.requests import Request
from google.oauth2.service_account import Credentials
from google_secops_siem_incidents.models.instance_info_response import (
    InstanceInfoResponse,
)
from google_secops_siem_incidents.models.rule_alert_response import RuleAlertResponse
from google_secops_siem_incidents.settings import GoogleSecOpsConfig
from google_secops_siem_incidents.utils.api_engine import ApiClient
from google_secops_siem_incidents.utils.api_engine.aio_http_client import AioHttpClient
from google_secops_siem_incidents.utils.api_engine.circuit_breaker import CircuitBreaker
from google_secops_siem_incidents.utils.api_engine.interfaces.base_request_hook import (
    BaseRequestHook,
)
from google_secops_siem_incidents.utils.api_engine.interfaces.base_request_model import (
    BaseRequestModel,
)
from google_secops_siem_incidents.utils.api_engine.retry_request_strategy import (
    RetryRequestStrategy,
)
from google_secops_siem_incidents.utils.timestamps import parse_ts


class GoogleAuthHook(BaseRequestHook):
    """Request hook that injects a Google OAuth2 Bearer token."""

    def __init__(self, credentials: Credentials) -> None:
        """Initialise with a Google OAuth2 service-account credentials object.

        Args:
            credentials: Google service-account credentials to inject as Bearer token.
        """
        self._credentials = credentials

    async def before(self, request: BaseRequestModel) -> None:
        """Refresh the OAuth2 token if needed and inject it as an Authorization header.

        Args:
            request: The outgoing request model to mutate.
        """
        if not self._credentials.valid:
            # ``Credentials.refresh`` is a blocking (requests-based) network
            # call; run it in a worker thread so it does not block the event
            # loop (and stall other async work) during a token refresh.
            await asyncio.to_thread(self._credentials.refresh, Request())
        if request.headers is None:
            request.headers = {}
        request.headers["Authorization"] = f"Bearer {self._credentials.token}"

    async def after(self, request: BaseRequestModel, response: Any) -> None:
        """No-op post-request hook.

        Args:
            request: The request model that was sent.
            response: The raw response received.
        """
        pass


class GoogleSecOpsApiClient:
    """API client for fetching rule alerts via Legacy Search endpoint."""

    _SCOPES = ["https://www.googleapis.com/auth/cloud-platform"]
    _API_VERSION = "v1alpha"
    _ALERTS_ENDPOINT = "legacy:legacySearchRulesAlerts"

    def __init__(self, config: GoogleSecOpsConfig) -> None:
        """Initialise the client from the given connector configuration.

        Args:
            config: Google SecOps connector configuration.
        """
        service_account_info = self._build_service_account_info(config)
        credentials = Credentials.from_service_account_info(
            service_account_info, scopes=self._SCOPES
        )
        self._config = config
        self._auth_hook = GoogleAuthHook(credentials)
        self._api_client = ApiClient(
            strategy=RetryRequestStrategy(
                http_client=AioHttpClient(),
                circuit_breaker=CircuitBreaker(),
                hooks=[self._auth_hook],
            ),
        )

    @staticmethod
    def _build_service_account_info(config: GoogleSecOpsConfig) -> dict[str, str]:
        """Map GoogleSecOpsConfig fields to the service-account info dict expected by google-auth.

        Args:
            config: Connector configuration with credentials.

        Returns:
            Dict suitable for ``Credentials.from_service_account_info``.
        """
        return {
            "type": "service_account",
            "project_id": config.project_id,
            "private_key": config.private_key,
            "private_key_id": config.private_key_id,
            "client_email": config.client_email,
            "client_id": config.client_id,
            "auth_uri": config.auth_uri,
            "token_uri": config.token_uri,
            "auth_provider_x509_cert_url": config.auth_provider_cert,
            "client_x509_cert_url": config.client_cert_url,
        }

    def _regionalized_url(self) -> str:
        """Build the API base URL with the region prefix.

        Returns:
            Regionalized base URL string.
        """
        base = str(self._config.base_url).rstrip("/")
        host = base.replace("https://", "")
        region = self._config.project_region
        return f"https://{region}-{host}"

    def _instance_path(self) -> str:
        """Build the resource instance path.

        Returns:
            Resource path string for the configured project/region/instance.
        """
        return (
            f"projects/{self._config.project_id}"
            f"/locations/{self._config.project_region}"
            f"/instances/{self._config.project_instance}"
        )

    def _alerts_url(self) -> str:
        """Build the full Legacy Search Rules Alerts endpoint URL.

        Returns:
            Fully qualified endpoint URL string.
        """
        return (
            f"{self._regionalized_url()}"
            f"/{self._API_VERSION}/{self._instance_path()}"
            f"/{self._ALERTS_ENDPOINT}"
        )

    def _instance_url(self) -> str:
        """Build the full Instance Info endpoint URL.

        Returns:
            Fully qualified URL for GET /v1alpha/{instance_path}.
        """
        return (
            f"{self._regionalized_url()}"
            f"/{self._API_VERSION}/{self._instance_path()}"
        )

    @staticmethod
    def compute_pagination_pivot(response: RuleAlertResponse) -> str | None:
        """Return the minimum detection_timestamp across all alerts, used as the next exclusive endTime.

        Args:
            response: The rule alert response to inspect.

        Returns:
            ISO-8601 timestamp string of the earliest alert, or None if no alerts.
        """
        all_alerts = [
            alert for rule_alert in response.rule_alerts for alert in rule_alert.alerts
        ]
        if not all_alerts:
            return None

        earliest = min(all_alerts, key=lambda a: parse_ts(a.detection_timestamp))
        return earliest.detection_timestamp

    async def close(self) -> None:
        """Close the underlying HTTP session."""
        await self._api_client.close()

    async def fetch_instance_info(self) -> InstanceInfoResponse:
        """Fetch instance information including SecOps UI URLs.

        Returns:
            InstanceInfoResponse with secops_urls and other instance metadata.
        """
        return await self._api_client.call_api(
            url=self._instance_url(),
            method="GET",
            response_model=InstanceInfoResponse,
        )

    async def fetch_rule_alerts(
        self,
        start_time: str,
        end_time: str,
        max_alerts: int = 1000,
    ) -> AsyncIterator[RuleAlertResponse]:
        """Fetch rule alerts from using backward-sliding pagination.

        Args:
            start_time: ISO-8601 start of the query window.
            end_time: ISO-8601 end of the query window.
            max_alerts: Maximum alerts per page request.

        Returns:
            Async iterator of RuleAlertResponse pages.
        """
        current_end = end_time
        start_dt = parse_ts(start_time)

        while True:
            response: RuleAlertResponse = await self._api_client.call_api(
                url=self._alerts_url(),
                method="GET",
                params={
                    "timeRange.startTime": start_time,
                    "timeRange.endTime": current_end,
                    "maxNumAlertsToReturn": max_alerts,
                },
                response_model=RuleAlertResponse,
            )
            yield response

            if not response.too_many_alerts:
                break

            pivot = self.compute_pagination_pivot(response)
            if pivot is None:
                break

            pivot_dt = parse_ts(pivot)
            current_end_dt = parse_ts(current_end)

            if pivot_dt <= start_dt or pivot_dt >= current_end_dt:
                break

            current_end = pivot

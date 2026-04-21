import time

import requests
from pycti import OpenCTIConnectorHelper


class BitSightClient:
    """API client for the Cybersixgill / BitSight API."""

    BASE_URL = "https://api.cybersixgill.com"

    def __init__(
        self,
        helper: OpenCTIConnectorHelper,
        client_id: str,
        client_secret: str,
    ):
        self.helper = helper
        self.client_id = client_id
        self.client_secret = client_secret

        self.session = requests.Session()
        self.session.headers.update(
            {
                "Content-Type": "application/json",
                "Cache-Control": "no-cache",
            }
        )

        self._access_token: str | None = None
        self._token_expiry: float = 0

    def _authenticate(self) -> None:
        """Obtain or refresh the bearer token (valid 30 min)."""
        url = f"{self.BASE_URL}/auth/token"
        response = requests.post(
            url,
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Cache-Control": "no-cache",
            },
            data={
                "grant_type": "client_credentials",
                "client_id": self.client_id,
                "client_secret": self.client_secret,
            },
        )
        response.raise_for_status()
        data = response.json()

        self._access_token = data["access_token"]
        # Refresh a bit before actual expiry to avoid race conditions
        self._token_expiry = time.time() + data.get("expires_in", 1800) - 60

        self.session.headers.update(
            {"Authorization": f"Bearer {self._access_token}"}
        )
        self.helper.connector_logger.info("[API] Successfully authenticated.")

    def _ensure_authenticated(self) -> None:
        """Re-authenticate when the token is missing or expired."""
        if self._access_token is None or time.time() >= self._token_expiry:
            self._authenticate()

    # ------------------------------------------------------------------
    # Generic request helper
    # ------------------------------------------------------------------

    def _request(self, method: str, path: str, params: str | None = None, **kwargs):
        """
        Execute an authenticated request against the API.

        :param method: HTTP method (GET, POST, …)
        :param path: URL path (appended to BASE_URL)
        :param org_id: Optional organisation ID for multi-tenant mode
        :return: parsed JSON response or None on error
        """
        self._ensure_authenticated()

        url = f"{self.BASE_URL}{path}"
        headers: dict[str, str] = {}

        try:
            response = self.session.request(method, url, headers=headers, params=params, **kwargs)
            self.helper.connector_logger.info(
                "[API] HTTP request", {"method": method, "url": url}
            )
            response.raise_for_status()
            return response.json()
        except requests.RequestException as err:
            self.helper.connector_logger.error(
                "[API] Error while fetching data",
                {"url": url, "error": str(err)},
            )
            return None

    def get_organizations(self) -> list[dict] | None:
        """Retrieve the list of monitored organisations."""
        return self._request("GET", "/multi-tenant/organization")

    def get_alerts(self, org_id: str | None = None) -> list[dict] | None:
        """
        Retrieve recent actionable alerts.

        :param org_id: Optional org ID for multi-tenant mode
        """
        if org_id:
            params = {"organization_id": org_id}
            return self._request("GET", "/alerts/actionable-alert",params=params)
        else:
            return self._request("GET", "/alerts/actionable_alerts")

    def get_alert_detail(
        self, alert_id: str, org_id: str | None = None
    ) -> dict | None:
        """
        Retrieve the full detail of a specific alert.

        :param alert_id: The alert ID
        :param org_id: Optional org ID for multi-tenant mode
        """
        if org_id:
            params = {"organization_id": org_id}
            return self._request(
                "GET", f"/alerts/actionable_alert/{alert_id}", params=params
            )
        else:
            return self._request("GET", f"/alerts/actionable_alerts/{alert_id}")

    def get_alert_content(
        self, alert_id: str, org_id: str | None = None
    ) -> dict | None:
        """
        Retrieve supplementary content for an alert.

        :param alert_id: The alert ID
        :param org_id: Optional org ID for multi-tenant mode
        """
        if org_id:
            params = {"organization_id": org_id}
            return self._request(
                "GET", f"/actionable_alert_content/{alert_id}", params=params
            )
        else:
            return self._request("GET", f"/actionable_alert_content/{alert_id}")


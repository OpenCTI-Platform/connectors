from typing import TYPE_CHECKING

import requests

if TYPE_CHECKING:
    from external_import_connector import ConnectorSettings
    from pycti import OpenCTIConnectorHelper


class FlowtriqClient:
    """
    HTTP client for the Flowtriq REST API v1.

    Authenticates via Bearer token and fetches DDoS incident data.
    """

    def __init__(self, helper: "OpenCTIConnectorHelper", config: "ConnectorSettings"):
        self.helper = helper
        self.config = config

        self.base_url = self.config.flowtriq.api_url.rstrip("/")
        self.session = requests.Session()
        self.session.headers.update(
            {
                "Authorization": f"Bearer {self.config.flowtriq.api_key.get_secret_value()}",
                "Accept": "application/json",
            }
        )

    def get_incidents(self, limit: int = 50, offset: int = 0) -> dict | None:
        """
        Fetch incidents from the Flowtriq API.

        GET /api/v1/incidents?limit=N&offset=N&status=...&severity=...
        Returns the full JSON response dict or None on error.
        """
        url = f"{self.base_url}/api/v1/incidents"
        params: dict[str, str | int] = {
            "limit": min(limit, 100),
            "offset": offset,
        }

        if self.config.flowtriq.incident_status:
            params["status"] = self.config.flowtriq.incident_status

        if self.config.flowtriq.incident_severity:
            # API accepts a single severity filter; if multiple are configured,
            # we make separate calls per severity in the connector layer.
            # Here we pass the first one if set.
            params["severity"] = self.config.flowtriq.incident_severity[0]

        try:
            self.helper.connector_logger.info(
                "[API] Fetching incidents from Flowtriq",
                {"url": url, "params": str(params)},
            )
            response = self.session.get(url, params=params, timeout=30)
            response.raise_for_status()
            return response.json()

        except requests.RequestException as err:
            self.helper.connector_logger.error(
                "[API] Error fetching incidents from Flowtriq",
                {"url": url, "error": str(err)},
            )
            return None

    def get_incident_detail(self, incident_uuid: str) -> dict | None:
        """
        Fetch a single incident with extended data (source IP count, geo breakdown).

        GET /api/v1/incidents/{uuid}
        """
        url = f"{self.base_url}/api/v1/incidents/{incident_uuid}"

        try:
            response = self.session.get(url, timeout=30)
            response.raise_for_status()
            data = response.json()
            return data.get("incident")

        except requests.RequestException as err:
            self.helper.connector_logger.error(
                "[API] Error fetching incident detail",
                {"uuid": incident_uuid, "error": str(err)},
            )
            return None

    def get_all_incidents(self, max_total: int = 100) -> list[dict]:
        """
        Paginate through incidents up to max_total.
        Returns a flat list of incident dicts.
        """
        all_incidents: list[dict] = []
        offset = 0
        page_size = min(max_total, 100)

        while offset < max_total:
            data = self.get_incidents(limit=page_size, offset=offset)
            if not data or "incidents" not in data:
                break

            incidents = data["incidents"]
            if not incidents:
                break

            all_incidents.extend(incidents)
            offset += len(incidents)

            # Stop if we got fewer than requested (last page)
            if len(incidents) < page_size:
                break

        return all_incidents[:max_total]

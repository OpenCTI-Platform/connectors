import time
from urllib.parse import quote

import requests
from pycti import OpenCTIConnectorHelper


class CTM360CbsAPIError(Exception):
    def __init__(self, message: str, status_code: int = None):
        self.status_code = status_code
        super().__init__(message)


class CTM360CbsClient:
    def __init__(self, helper: OpenCTIConnectorHelper, base_url: str, api_key: str):
        self.helper = helper
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()
        self.session.headers.update({"api-key": api_key})
        self.session.verify = True
        self._max_retries = 3
        self._retry_delay = 5

    def _request(self, method: str, path: str, params: dict = None) -> dict:
        """Make a single API request and return the raw JSON response dict."""
        url = f"{self.base_url}{path}"
        for attempt in range(self._max_retries):
            try:
                self.helper.connector_logger.debug(
                    "[API] Request",
                    {"method": method, "url": url, "params": params},
                )
                response = self.session.request(method, url, params=params, timeout=60)
                if response.status_code == 204:
                    return {"incident_list": [], "count": 0}
                if response.status_code == 429:
                    retry_after = int(
                        response.headers.get(
                            "Retry-After", self._retry_delay * (attempt + 1)
                        )
                    )
                    self.helper.connector_logger.warning(
                        "[API] Rate limited, waiting",
                        {"retry_after": retry_after},
                    )
                    time.sleep(retry_after)
                    continue
                response.raise_for_status()
                data = response.json()
                return data if isinstance(data, dict) else {"data": data}
            except requests.exceptions.HTTPError as e:
                status = e.response.status_code if e.response is not None else 0
                if status in (500, 502, 503) and attempt < self._max_retries - 1:
                    time.sleep(self._retry_delay * (attempt + 1))
                    continue
                raise CTM360CbsAPIError(
                    f"HTTP {status}: {str(e)}", status_code=status
                ) from e
            except requests.exceptions.ConnectionError as e:
                if attempt < self._max_retries - 1:
                    time.sleep(self._retry_delay * (attempt + 1))
                    continue
                raise CTM360CbsAPIError(f"Connection error: {str(e)}") from e
            except requests.exceptions.Timeout as e:
                if attempt < self._max_retries - 1:
                    time.sleep(self._retry_delay * (attempt + 1))
                    continue
                raise CTM360CbsAPIError(f"Request timeout: {str(e)}") from e
        raise CTM360CbsAPIError("Max retries exceeded")

    def _extract_items(self, data: dict) -> list:
        """Extract the list of items from a CBS API response.

        CBS uses different keys per endpoint:
        - /incidents -> "incident_list"
        - /leaks/* -> "data"
        - /domain_protection -> "data"
        """
        if "incident_list" in data:
            return data["incident_list"]
        if "data" in data and isinstance(data["data"], list):
            return data["data"]
        return []

    def _paginated_request(
        self, method: str, path: str, params: dict = None, page_size: int = 200
    ) -> list:
        """Fetch all pages from a paginated CBS endpoint."""
        params = dict(params or {})
        params["size"] = page_size
        page = 1
        all_items = []

        while True:
            params["page"] = page
            data = self._request(method, path, params=params)
            items = self._extract_items(data)
            all_items.extend(items)

            total = data.get("count", 0)
            self.helper.connector_logger.debug(
                "[API] Page fetched",
                {"path": path, "page": page, "items": len(items), "total": total},
            )

            if len(items) < page_size or len(all_items) >= total:
                break
            page += 1

        return all_items

    def ping(self):
        self._request("GET", "/api/v2/incidents", params={"size": 1})

    def get_incidents(self, date_from: str = None, date_to: str = None) -> list:
        """Fetch all CBS incidents (paginated)."""
        params = {}
        if date_from:
            params["date_field"] = "updated"
            params["date_from"] = date_from
        if date_to:
            params["date_to"] = date_to
        return self._paginated_request("GET", "/api/v2/incidents", params=params)

    def get_malware_logs(self, date_from: str = None, date_to: str = None) -> list:
        """Fetch all malware logs (paginated)."""
        params = {}
        if date_from:
            params["date_from"] = date_from
        if date_to:
            params["date_to"] = date_to
        return self._paginated_request(
            "GET", "/api/v2/leaks/malware_logs", params=params, page_size=5000
        )

    def get_breached_credentials(
        self, date_from: str = None, date_to: str = None
    ) -> list:
        """Fetch all breached credentials (paginated)."""
        params = {}
        if date_from:
            params["date_from"] = date_from
        if date_to:
            params["date_to"] = date_to
        return self._paginated_request(
            "GET", "/api/v2/leaks/breached_credentials", params=params, page_size=5000
        )

    def get_card_leaks(self, date_from: str = None, date_to: str = None) -> list:
        """Fetch all card leaks (paginated)."""
        params = {}
        if date_from:
            params["date_from"] = date_from
        if date_to:
            params["date_to"] = date_to
        return self._paginated_request(
            "GET", "/api/v2/leaks/card_leaks", params=params, page_size=5000
        )

    def get_domain_protection(self, date_from: str = None, date_to: str = None) -> list:
        """Fetch all domain protection findings (paginated)."""
        params = {}
        if date_from:
            params["date_from"] = date_from
        if date_to:
            params["date_to"] = date_to
        return self._paginated_request(
            "GET", "/api/v2/domain_protection", params=params
        )

    def get_incident(self, ticket_id: str) -> dict:
        """Fetch a single incident by ticket ID."""

        safe_id = quote(str(ticket_id), safe="")
        result = self._request("GET", f"/api/v2/incidents/{safe_id}")
        # Extract incident from response wrapper
        if "incident" in result and isinstance(result["incident"], dict):
            return result["incident"]
        if "incident_list" in result and isinstance(result["incident_list"], list):
            items = result["incident_list"]
            return items[0] if items else {}
        if "id" in result and "status" in result:
            return result
        return result

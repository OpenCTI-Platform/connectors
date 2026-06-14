import time
from urllib.parse import quote

import requests
from pycti import OpenCTIConnectorHelper


class CTM360HvAPIError(Exception):
    def __init__(self, message: str, status_code: int = None):
        self.status_code = status_code
        super().__init__(message)


class CTM360HvClient:
    def __init__(self, helper: OpenCTIConnectorHelper, base_url: str, api_key: str):
        self.helper = helper
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()
        self.session.headers.update({"api-key": api_key})
        self.session.verify = True
        self._max_retries = 3
        self._retry_delay = 5

    def _parse_retry_after(self, value, default: int) -> int:
        """Parse a ``Retry-After`` header into a delay in seconds.

        Per RFC 9110 the value may be a non-negative integer (seconds) or an
        HTTP-date. A float-like string is also tolerated. Anything we cannot
        interpret as a number of seconds falls back to the configured backoff
        instead of raising ``ValueError`` and aborting the request loop.
        """
        if value is None:
            return default
        try:
            return max(0, int(float(value)))
        except (TypeError, ValueError):
            return default

    def _request(self, method: str, path: str, params: dict = None) -> dict:
        """Make a single API request and return the raw JSON response dict/list."""
        url = f"{self.base_url}{path}"
        for attempt in range(self._max_retries):
            try:
                self.helper.connector_logger.debug(
                    "[API] Request",
                    {"method": method, "url": url, "params": params},
                )
                response = self.session.request(method, url, params=params, timeout=60)
                if response.status_code == 204:
                    return {"issues": [], "count": 0}
                if response.status_code == 429:
                    retry_after = self._parse_retry_after(
                        response.headers.get("Retry-After"),
                        self._retry_delay * (attempt + 1),
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
                # Retry the whole 5xx range (e.g. 500/502/503/504) — these are
                # transient server-side failures.
                if status >= 500 and attempt < self._max_retries - 1:
                    time.sleep(self._retry_delay * (attempt + 1))
                    continue
                raise CTM360HvAPIError(
                    f"HTTP {status}: {str(e)}", status_code=status
                ) from e
            except requests.exceptions.ConnectionError as e:
                if attempt < self._max_retries - 1:
                    time.sleep(self._retry_delay * (attempt + 1))
                    continue
                raise CTM360HvAPIError(f"Connection error: {str(e)}") from e
            except requests.exceptions.Timeout as e:
                if attempt < self._max_retries - 1:
                    time.sleep(self._retry_delay * (attempt + 1))
                    continue
                raise CTM360HvAPIError(f"Request timeout: {str(e)}") from e
        raise CTM360HvAPIError("Max retries exceeded")

    def _extract_items(self, data: dict) -> list:
        """Extract the list of items from an API response dict."""
        if "issues" in data and isinstance(data["issues"], list):
            return data["issues"]
        if "data" in data and isinstance(data["data"], list):
            return data["data"]
        return []

    def _paginated_request(
        self, method: str, path: str, params: dict = None, page_size: int = 100
    ) -> list:
        """Fetch all pages from a paginated HackerView endpoint.

        Uses size/page params. Stops when returned items < page_size
        or total count is reached.
        """
        params = dict(params or {})
        params["size"] = page_size
        page = 1
        all_items = []

        while True:
            params["page"] = page
            data = self._request(method, path, params=params)
            items = self._extract_items(data)
            all_items.extend(items)

            total = data.get("count")
            self.helper.connector_logger.debug(
                "[API] Page fetched",
                {"path": path, "page": page, "items": len(items), "total": total},
            )

            # Stop on a short page; only use the `count`/`total` stop condition
            # when the API actually reports a positive count. Otherwise a
            # missing/zero `count` (e.g. a bare-list response wrapped as
            # {"data": [...]}) would falsely stop pagination after the first
            # full page and silently truncate the import.
            if len(items) < page_size:
                break
            if total and len(all_items) >= total:
                break
            page += 1

        return all_items

    def ping(self):
        """Validate API connectivity with a minimal request."""
        self._request("GET", "/api/v2/issues", params={"size": "1"})

    def get_issues(self, first_seen: str = None) -> list:
        """Fetch all security issues from the attack surface (paginated).

        Args:
            first_seen: ISO timestamp filter for issues first seen after this date.
        """
        params = {}
        if first_seen:
            params["first_seen"] = first_seen
        return self._paginated_request("GET", "/api/v2/issues", params=params)

    def get_resolved_issues(self, from_date: str = None, to_date: str = None) -> list:
        """Fetch all resolved issues (paginated).

        Args:
            from_date: Start date filter.
            to_date: End date filter.
        """
        params = {}
        if from_date:
            params["from_date"] = from_date
        if to_date:
            params["to_date"] = to_date
        return self._paginated_request("GET", "/api/v2/resolved_issues", params=params)

    def get_domain_assets(self) -> list:
        """Fetch genuine domain assets (paginated)."""
        return self._paginated_request("GET", "/api/v2/assets/domain")

    def get_host_assets(self) -> list:
        """Fetch genuine hostname assets (paginated)."""
        return self._paginated_request("GET", "/api/v2/assets/host")

    def get_ip_assets(self) -> list:
        """Fetch associated IP address assets (paginated)."""
        return self._paginated_request("GET", "/api/v2/assets/ip_address")

    def get_issue(self, ticket_id: str) -> dict:
        """Fetch a single issue by ticket ID."""

        safe_id = quote(str(ticket_id), safe="")
        result = self._request("GET", f"/api/v2/issues/{safe_id}")
        if "issues" in result and isinstance(result["issues"], list):
            items = result["issues"]
            return items[0] if items else {}
        if "data" in result and isinstance(result["data"], dict):
            return result["data"]
        if "id" in result or "ticket_id" in result:
            return result
        return result

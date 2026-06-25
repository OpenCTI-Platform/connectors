from typing import Any, Dict, Optional

import requests
from pycti import OpenCTIConnectorHelper
from pydantic import HttpUrl


class VisionHeightClient:
    """
    HTTP client for the VisionHeight intelligence API.

    Wraps the two endpoints used by the enrichment connector:
      - GET /ip/{ip}      → full IPv4 profile
      - GET /domain/{name} → full domain profile

    Authentication uses the `x-api-key` header.
    """

    def __init__(
        self,
        helper: OpenCTIConnectorHelper,
        base_url: HttpUrl,
        api_key: str,
    ):
        """
        Initialize the VisionHeight API client.

        Args:
            helper: The connector helper, used for structured logging.
            base_url: Base URL of the VisionHeight API (e.g. https://api.visionheight.com).
            api_key: The API key, sent as the `x-api-key` header on every request.
        """
        self.helper = helper

        # Pydantic's HttpUrl serializes with a trailing slash; strip it so
        # f"{base_url}{path}" composes cleanly.
        self.base_url = str(base_url).rstrip("/")

        headers = {
            "x-api-key": api_key,
            "Accept": "application/json",
        }
        self.session = requests.Session()
        self.session.headers.update(headers)

    def _request_data(
        self,
        path: str,
        params: Optional[Dict[str, Any]] = None,
    ) -> Optional[Dict[str, Any]]:
        """
        Internal GET helper. Returns the parsed JSON response, or None on error.

        VisionHeight returns 200 with whatever data it has for any valid (non-bogon)
        IP/domain. Errors come back as:
          - 400 for invalid input (bogon IPs, malformed domains)
          - 401 for missing/invalid API key
          - 500 for server errors

        All errors are logged and swallowed; the caller gets None.

        Args:
            path: Endpoint path beginning with `/` (e.g. `/ip/1.2.3.4`).
            params: Optional query-string parameters.
        """
        url = f"{self.base_url}{path}"
        self.helper.connector_logger.info("[API] GET request", {"url_path": url})
        try:
            response = self.session.get(url, params=params, timeout=30)
            response.raise_for_status()
            return response.json()
        except requests.RequestException as err:
            status_code = err.response.status_code if err.response is not None else None
            body_snippet = err.response.text[:500] if err.response is not None else None
            self.helper.connector_logger.error(
                "[API] Error while fetching data",
                {
                    "url_path": url,
                    "error": str(err),
                    "status_code": status_code,
                    "response_body": body_snippet,
                },
            )
            return None

    def get_ip(self, ip: str) -> Optional[Dict[str, Any]]:
        """
        Fetch the comprehensive intelligence profile for an IPv4 address.

        Returns whatever VisionHeight has on the IP — may be sparse for IPs with
        little known activity, but always returns 200 for valid (non-bogon) IPs.
        Bogon IPs and malformed input are rejected by the server with 400.

        Args:
            ip: The IPv4 address to look up.

        Returns:
            The parsed JSON profile, or None on error (bogon, auth, server error).
        """
        return self._request_data(f"/ip/{ip}")

    def get_domain(self, domain: str) -> Optional[Dict[str, Any]]:
        """
        Fetch the comprehensive intelligence profile for a domain.

        Returns whatever VisionHeight has on the domain — may be sparse for
        domains with little known activity.

        Args:
            domain: The domain name to look up.

        Returns:
            The parsed JSON profile, or None on error (malformed domain, auth, server error).
        """
        return self._request_data(f"/domain/{domain}")

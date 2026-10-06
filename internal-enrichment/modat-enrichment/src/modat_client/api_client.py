import ipaddress

import requests
from pycti import OpenCTIConnectorHelper


class ModatClient:
    def __init__(self, helper: OpenCTIConnectorHelper, base_url: str, api_key: str):
        self.helper = helper
        self.base_url = base_url.rstrip("/")
        self._auth_header = (
            api_key if api_key.lower().startswith("bearer ") else f"Bearer {api_key}"
        )
        self.session = requests.Session()
        # Note: Authorization is sent per-request rather than via session.headers so
        # that requests automatically strips it on cross-origin redirects.
        self.session.headers.update({"Accept": "application/json"})

    @staticmethod
    def _validate_ipv4(ip: str) -> str:
        """Defense-in-depth: ensure the value going into the URL is a literal IPv4
        address, not a crafted string that could escape the path or change the
        endpoint."""
        try:
            parsed = ipaddress.IPv4Address(ip)
        except (ipaddress.AddressValueError, ValueError, TypeError) as err:
            raise ValueError(
                f"Refusing Modat lookup for non-IPv4 value: {ip!r}"
            ) from err
        return str(parsed)

    def get_host_details(self, ip: str) -> dict:
        safe_ip = self._validate_ipv4(ip)
        api_url = f"{self.base_url}/host/{safe_ip}/v1"
        self.helper.connector_logger.info(
            "[MODAT] GET request sent", {"endpoint": api_url}
        )
        response = self.session.get(
            api_url,
            headers={"Authorization": self._auth_header},
            timeout=60,
        )
        response.raise_for_status()
        return response.json()

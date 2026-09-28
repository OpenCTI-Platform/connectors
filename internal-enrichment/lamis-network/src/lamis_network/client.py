# -*- coding: utf-8 -*-
"""Lamis Network API client."""

import logging
from typing import Any, Dict, Optional

import requests

logger = logging.getLogger(__name__)


class LamisNetworkClient:
    """Client for interacting with Lamis Network IP intelligence API."""

    def __init__(
        self,
        api_key: str,
        base_url: str = "https://api.lamisnetwork.com",
        timeout: int = 10,
    ) -> None:
        """Initialize the client.

        :param api_key: Lamis Network API key
        :param base_url: API base URL (default: https://api.lamisnetwork.com)
        :param timeout: Request timeout in seconds
        """
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update(
            {
                "Authorization": f"Bearer {self.api_key}",
                "Accept": "application/json",
                "User-Agent": "OpenCTI-Connector-LamisNetwork/1.0.0",
            }
        )

    def get_ip_reputation(self, ip_address: str) -> Optional[Dict[str, Any]]:
        """Fetch IP reputation, ASN, geo, and fraud scoring from Lamis Network.

        :param ip_address: IPv4 or IPv6 address string
        :return: Dict with response data or None on failure
        """
        url = f"{self.base_url}/v1/ip/{ip_address}"
        try:
            response = self.session.get(url, timeout=self.timeout)
            if response.status_code == 200:
                return self._parse_response(response, ip_address)

            if response.status_code == 404:
                # Fallback to query parameter endpoint if path routing isn't available
                alt_url = f"{self.base_url}/v1/score"
                alt_resp = self.session.get(
                    alt_url, params={"ip": ip_address}, timeout=self.timeout
                )
                if alt_resp.status_code == 200:
                    return self._parse_response(alt_resp, ip_address)
                logger.warning(
                    "Lamis Network: fallback request for IP %s failed (HTTP %s)",
                    ip_address,
                    alt_resp.status_code,
                )
                return None

            if response.status_code in (401, 403):
                logger.error(
                    "Lamis Network API authentication failed (HTTP %s): "
                    "check LAMIS_NETWORK_API_KEY",
                    response.status_code,
                )
                return None

            if response.status_code == 429:
                retry_after = response.headers.get("Retry-After", "unknown")
                logger.warning(
                    "Lamis Network API rate limit exceeded (HTTP 429). Retry-After: %s",
                    retry_after,
                )
                return None

            logger.error(
                "Lamis Network API error for IP %s: HTTP %s (%s)",
                ip_address,
                response.status_code,
                response.text[:200],
            )
            return None

        except requests.exceptions.Timeout:
            logger.error(
                "Lamis Network API request timed out for IP %s (timeout=%ss)",
                ip_address,
                self.timeout,
            )
            return None
        except requests.exceptions.RequestException as exc:
            logger.error(
                "Lamis Network API request failed for IP %s: %s",
                ip_address,
                exc,
            )
            return None

    @staticmethod
    def _parse_response(
        response: requests.Response, ip_address: str
    ) -> Optional[Dict[str, Any]]:
        """Reject malformed JSON before it reaches the enrichment pipeline."""
        try:
            payload = response.json()
        except ValueError:
            logger.error(
                "Lamis Network API returned invalid JSON for IP %s", ip_address
            )
            return None
        if not isinstance(payload, dict):
            logger.error(
                "Lamis Network API returned a non-object for IP %s", ip_address
            )
            return None
        return payload

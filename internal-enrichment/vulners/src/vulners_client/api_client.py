"""Thin wrapper around the Vulners SDK STIX API.

The Vulners backend builds the full STIX bundle server-side
(`GET /api/v4/stix/bundle`). This client only fetches that ready-made bundle
and parses it into a dict; it does not construct any STIX objects itself.
"""

import json
from typing import Any

from vulners import VulnersApi


class VulnersClient:
    """Minimal client that retrieves prebuilt STIX bundles from Vulners."""

    def __init__(self, api_key: str, base_url: str = "https://vulners.com") -> None:
        """
        Initialize the Vulners client.

        :param api_key: Vulners API key (sent as the ``X-Api-Key`` header).
        :param base_url: Vulners server URL.
        """
        self._api = VulnersApi(api_key, server_url=base_url)

    def get_bundle(
        self, bulletin_id: str, opencti_id: str | None = None
    ) -> dict[str, Any]:
        """
        Fetch the ready-made STIX bundle for a given bulletin/CVE id.

        :param bulletin_id: The bulletin id (e.g. a CVE id) to enrich.
        :param opencti_id: The existing OpenCTI object id, if any.
        :return: The parsed STIX bundle as a dict.
        """
        data: str = self._api.stix.make_bundle_by_id(
            id=bulletin_id, opencti_id=opencti_id
        )
        return json.loads(data)

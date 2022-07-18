"""OpenCTI AlienVault client module."""
from __future__ import annotations

from datetime import datetime
from typing import List

import pydantic
from alienvault.models import Pulse
from OTXv2 import OTXv2

__all__ = [
    "AlienVaultClient",
]


class AlienVaultClient:
    """AlienVault client."""

    def __init__(self, base_url: str, api_key: str) -> None:
        """
        Initializer.
        :param base_url: Base API url.
        :param api_key: API key.
        """
        server = base_url if not base_url.endswith("/") else base_url[:-1]

        self.otx = OTXv2(api_key, server=server)

    def get_pulses_subscribed(
        self,
        modified_since: datetime,
        limit: int = 20,
    ) -> List[Pulse]:
        """
        Get any subscribed pulses.
        :param modified_since: Filter by results modified since this date.
        :param limit: Return limit.
        :return: A list of pulses.
        """
        pulse_data = self.otx.getsince(timestamp=modified_since, limit=limit)
        pulses = pydantic.parse_obj_as(List[Pulse], pulse_data)

        return pulses

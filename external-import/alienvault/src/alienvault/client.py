"""OpenCTI AlienVault client module."""

from __future__ import annotations

from datetime import datetime
from typing import List

from alienvault.models import Pulse
from OTXv2 import OTXv2
from pydantic.v1 import HttpUrl, parse_obj_as

__all__ = [
    "AlienVaultClient",
]


class AlienVaultClient:
    """AlienVault client."""

    def __init__(self, base_url: HttpUrl, api_key: str) -> None:
        """
        Initializer.
        :param base_url: Base API url.
        :param api_key: API key.
        """
        server = str(base_url).strip("/")

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
        pulses = parse_obj_as(List[Pulse], pulse_data)

        return pulses

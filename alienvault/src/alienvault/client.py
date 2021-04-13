# -*- coding: utf-8 -*-
"""OpenCTI AlienVault client module."""

from datetime import datetime
from typing import List

from OTXv2 import OTXv2  # type: ignore

from pydantic import parse_obj_as

from alienvault.models import Pulse


class AlienVaultClient:
    """AlienVault client."""

    def __init__(self, base_url: str, api_key: str) -> None:
        """Initialize AlienVault client."""
        server = base_url if not base_url.endswith("/") else base_url[:-1]

        self.otx = OTXv2(api_key, server=server)

    def get_pulses_subscribed(
        self, modified_since: datetime, limit: int = 20
    ) -> List[Pulse]:
        """Return subscribed pulses."""
        pulse_data = self.otx.getsince(modified_since, limit=limit)

        # with open("pulses.json", "w") as f:
        #     f.write(json.dumps(pulse_data))

        pulses = parse_obj_as(List[Pulse], pulse_data)
        return pulses

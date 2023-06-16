"""OpenCTI AlienVault client module."""
from __future__ import annotations

from datetime import datetime
from typing import List

import pydantic
from alienvault.models import Pulse
from OTXv2 import OTXv2,RetryError

__all__ = [
    "AlienVaultClient",
]

class OTXv2Fixed(OTXv2):
    
    def walkapi_iter(self, url, max_page=None, max_items=None, method='GET', body=None):
        next_page_url = url
        count = 0
        item_count = 0
        while next_page_url:
            count += 1
            if max_page and count > max_page:
                break
            
            if method == 'GET':
                try:
                    data = self.get(next_page_url)
                except RetryError:
                    pass
            elif method == 'POST':
                data = self.post(next_page_url, body=body)
            else:
                raise Exception("Unsupported method type: {}".format(method))

            for el in data['results']:
                item_count += 1
                if max_items and item_count > max_items:
                    break

                yield el

            next_page_url = data["next"]


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

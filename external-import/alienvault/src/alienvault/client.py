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
        Get any subscribed pulses using activity endpoint (PATCHED).
        :param modified_since: Filter by results modified since this date.
        :param limit: Return limit.
        :return: A list of pulses.
        """
        # PATCH: Use activity endpoint instead of subscribed (which times out)
        # Original: pulse_data = self.otx.getsince(timestamp=modified_since, limit=limit)
        
        # Get from activity endpoint
        activity_url = f"/api/v1/pulses/activity?limit={limit}"
        response = self.otx.get(activity_url)
        
        # Extract results and filter by modified_since
        if response and isinstance(response, dict) and 'results' in response:
            all_pulses = response['results']
            # Filter pulses by modified date AND add missing TLP field
            filtered_pulses = []
            for pulse in all_pulses:
                # Add default TLP if missing
                if 'tlp' not in pulse:
                    pulse['tlp'] = 'white'  # Default TLP value
                
                if 'modified' in pulse:
                    # Parse pulse modified time
                    pulse_modified_str = pulse['modified'].replace('Z', '+00:00')
                    try:
                        pulse_modified = datetime.fromisoformat(pulse_modified_str)
                        if pulse_modified >= modified_since:
                            filtered_pulses.append(pulse)
                    except:
                        # If parsing fails, include the pulse
                        filtered_pulses.append(pulse)
                else:
                    # If no modified field, include the pulse
                    filtered_pulses.append(pulse)
            
            pulses = parse_obj_as(List[Pulse], filtered_pulses)
        else:
            pulses = []
        
        return pulses

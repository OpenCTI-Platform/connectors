from typing import Any

from pycti import OpenCTIApiClient


class ThreatsGuesser:
    """Provide Intrusion Set, Malware, Tool, or Attack Pattern data from OpenCTI platform."""

    def __init__(self, api_client: OpenCTIApiClient):
        """Initialize the Geocoding Adapter."""
        self._api_client = api_client

    def search_by_name_or_id(self, value: str) -> list[dict[str, Any]]:
        threats = self._api_client.stix_domain_object.list(
            types=["Intrusion-Set", "Malware", "Tool", "Attack-Pattern"],
            filters={
                "mode": "and",
                "filters": [
                    {
                        "key": [
                            "name",
                            "x_mitre_id",
                            "aliases",
                            "x_opencti_aliases",
                        ],
                        "values": [value],
                    }
                ],
                "filterGroups": [],
            },
        )
        return threats

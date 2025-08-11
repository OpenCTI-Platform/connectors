from typing import List, Dict, Any

# from .splunk_bundle import full_bundle


class OpenCTIIndicatorFetcher:
    def __init__(self, opencti_client):
        """
        :param opencti_client: An instance of the OpenCTI API client.
        :param predefined_stix_indicators: Dict mapping observable types to lists of STIX Indicator dicts.
        """
        self.opencti_client = opencti_client
        self.predefined_stix_indicators = full_bundle

    def fetch_indicators(
        self, observable_type: str, observable_value: str
    ) -> List[Dict[str, Any]]:
        """
        Query OpenCTI for indicators related to the observable.
        If none are found, return predefined STIX Indicator objects.
        """
        indicators = self._query_opencti(observable_type, observable_value)
        if indicators:
            return indicators
        return self.predefined_stix_indicators

    def _query_opencti(self, observable_type: str) -> List[Dict[str, Any]]:
        """
        Internal method to query OpenCTI API.
        """
        splunk_label = self.opencti_client

        query_filters = {
            "mode": "and",
            "filters": [
                {
                    "key": "entity_type",
                    "values": ["Indicator"],
                    "operator": "eq",
                    "mode": "or",
                }
            ],
            "filterGroups": [
                {
                    "mode": "and",
                    "filters": [
                        {
                            "key": "pattern_type",
                            "operator": "eq",
                            "values": ["splunk"],
                            "mode": "or",
                        },
                        {
                            "key": "objectLabel",
                            "operator": "eq",
                            "values": ["01bc68e6-5c38-427d-97c3-8b2f4072ff7e"],
                            "mode": "or",
                        },
                    ],
                    "filterGroups": [],
                }
            ],
        }
        # Example API call, adjust to your OpenCTI client
        try:
            result = self.opencti_client.indicator.read(filters=query_filters)
            return result or []
        except Exception as e:
            # Log error if needed
            return []

    def get_patterns_and_types(
        self, observable_type: str, observable_value: str
    ) -> List[Dict[str, str]]:
        """
        Returns a list of dicts with 'observable_type' and 'pattern' from OpenCTI or predefined bundle.
        """
        indicators = self._query_opencti_graphql(observable_type, observable_value)
        if indicators:
            return [
                {
                    "observable_type": i.get("x_opencti_main_observable_type")
                    or i.get("main_observable_type"),
                    "pattern": i.get("pattern"),
                }
                for i in indicators
                if i.get("pattern")
            ]
        # fallback to predefined bundle
        return [
            {
                "observable_type": i.get("x_opencti_main_observable_type")
                or i.get("main_observable_type"),
                "pattern": i.get("pattern"),
            }
            for i in self.predefined_stix_indicators.get(observable_type, [])
            if i.get("pattern")
        ]

    def get_full_bundle(
        self, observable_type: str, observable_value: str
    ) -> List[Dict[str, Any]]:
        """
        Returns the full indicator bundle from OpenCTI or predefined bundle.
        """
        indicators = self._query_opencti(observable_type, observable_value)
        if indicators:
            return indicators
        return self.predefined_stix_indicators.get(observable_type, [])


# Example usage:
# opencti_client = ... # Your OpenCTI API client instance
# predefined_stix_indicators = {
#     "ipv4-addr": [{"type": "indicator", "pattern": "[ipv4-addr:value = '1.2.3.4']"}],
#     "domain-name": [{"type": "indicator", "pattern": "[domain-name:value = 'example.com']"}],
# }
# fetcher = OpenCTIIndicatorFetcher(opencti_client, predefined_stix_indicators)
# indicators = fetcher.fetch_indicators("ipv4-addr", "8.8.8.8")

"""Client for Recorded Future API
############################## TERMS OF USE ####################################
# The following code is provided for demonstration purposes only, and should   #
# not be used without independent verification. Recorded Future makes no       #
# representations or warranties, express, implied, statutory, or otherwise,    #
# regarding this code, and provides it strictly "as-is".                       #
# Recorded Future shall not be liable for, and you assume all risk of          #
# using the foregoing.                                                         #
################################################################################
"""

import urllib.parse

import requests

from .rf_utils import extract_and_combine_links

API_BASE = "https://api.recordedfuture.com"
API_BASE_V2 = urllib.parse.urljoin(API_BASE, "/v2")


class RFClientError(Exception):
    """Wrapper of errors raised in RFClient"""


class RFClient:
    """class for talking to the RF API, specifically for enriching indicators"""

    def __init__(self, token, header="OpenCTI-Enrichment/2.0"):
        """Initialize the RFClient with API token and session settings."""
        self.session = requests.Session()
        self.session.headers.update(
            {
                "X-RFToken": token,
                "User-Agent": header,
            }
        )

    def _get_observable_enrichment(self, type_: str, value: str):
        """Enrich entity and get its risk score."""

        enrichment_fields = ["entity", "risk"]
        if type_.lower() == "hash":
            enrichment_fields.append("hashAlgorithm")

        url = f"{API_BASE_V2}/{type_}/{urllib.parse.quote(value, safe='')}"
        query_params = {"fields": ",".join(enrichment_fields)}

        response = self.session.get(url, params=query_params)
        response.raise_for_status()

        response_json = response.json()
        data = response_json.get("data")
        if not data:
            raise RFClientError("RecordedFuture API response does not include data")

        return data

    def _get_observable_links(self, rfid: str) -> list:
        """Retrieve links for a given entity ID."""

        url = urllib.parse.urljoin(API_BASE, "/links/search")
        body = {
            "entities": [rfid],
            "limits": {"search_scope": "medium", "per_entity_type": 100},
        }

        response = self.session.post(url, json=body)
        response.raise_for_status()

        response_json = response.json()
        data = response_json.get("data")
        if not data:
            raise RFClientError("RecordedFuture API response does not include data")

        return extract_and_combine_links(data)

    def get_observable_enrichment(self, type_: str, value: str) -> dict:
        """Enrich an individual IOC with additional links."""
        try:
            enrichment_data = self._get_observable_enrichment(type_, value)
            links = self._get_observable_links(enrichment_data["entity"]["id"])

            enrichment_data["links"] = links or None

            return enrichment_data
        except requests.exceptions.HTTPError as err:
            raise RFClientError("An HTTP error occurred") from err
        except requests.exceptions.RequestException as err:
            raise RFClientError(
                "Unexpected error while fetching RecordedFuture API"
            ) from err

    def get_vulnerability_enrichment(self, name: str) -> dict:
        enrichment_fields = [
            "commonNames",
            "cvss",
            "cvssv3",
            "cvssv4",
            "intelCard",
            "lifecycleStage",
        ]

        url = f"{API_BASE_V2}/vulnerability/{urllib.parse.quote(name, safe='')}"
        query_params = {"fields": ",".join(enrichment_fields)}

        try:
            response = self.session.get(url, params=query_params)
            response.raise_for_status()

            response_json = response.json()
            warnings = response_json.get("warnings")
            if warnings:
                raise RFClientError("RecordedFuture API returned warnings", warnings)
            data = response_json.get("data")
            if not data:
                raise RFClientError("RecordedFuture API response does not include data")

            return data
        except requests.exceptions.HTTPError as err:
            raise RFClientError("An HTTP error occurred") from err
        except requests.exceptions.RequestException as err:
            raise RFClientError(
                "Unexpected error while fetching RecordedFuture API"
            ) from err

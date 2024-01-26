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

import logging
import urllib.parse

import requests

from .rf_utils import extract_and_combine_links

API_BASE = "https://api.recordedfuture.com"
CONNECT_BASE = urllib.parse.urljoin(API_BASE, "/v2")
LINK_SEARCH = urllib.parse.urljoin(API_BASE, "/links/search")

LOGGER = logging.getLogger("name")


class RFClient:
    """class for talking to the RF API, specifically for enriching indicators"""

    def __init__(self, token, helper, header="OpenCTI-Enrichment/2.0"):
        """Initialize the RFClient with API token and session settings."""
        self.token = token
        headers = {"X-RFToken": token, "User-Agent": header}
        self.session = requests.Session()
        self.session.headers.update(headers)
        self.helper = helper

    def full_enrichment(self, entity, type_):
        """Enrich an individual IOC with additional links."""
        reason, enrichment = self._enrich(entity, type_)
        if enrichment:
            links_reason, links = self._get_links(enrichment["entity"]["id"])
            if links:
                enrichment["links"] = links
            else:
                LOGGER.warning(f"Failed to return links: {links_reason}")
                enrichment["links"] = None
        return reason, enrichment

    def _enrich(self, entity, type_):
        """Enrich entity and get its risk score."""
        fields = "entity,risk"
        if type_.lower() == "hash":
            fields += ",hashAlgorithm"

        url = f"{CONNECT_BASE}/{type_}/{urllib.parse.quote(entity, safe='')}"

        try:
            res = self.session.get(url, params={"fields": fields})
            return self._handle_response(res)
        except requests.exceptions.RequestException as e:
            LOGGER.error(f"Error making request: {e}")
            return None, None

    def _get_links(self, rfid):
        """Retrieve links for a given entity ID."""
        query = {
            "entities": [f"{rfid}"],
            "limits": {"search_scope": "medium", "per_entity_type": 100},
        }
        try:
            res = self.session.post(LINK_SEARCH, json=query)
            LOGGER.debug(f"Response: {res.json()}")
            return self._handle_response(res, expected_key="links")
        except requests.exceptions.RequestException as e:
            LOGGER.error(f"Error making request: {e}")
            return "Error making Request", None

    def _handle_response(self, response, expected_key=None):
        """Handle API response, returning the relevant part if successful."""
        if response.status_code == 200:
            json_data = response.json().get("data", None)
            if json_data:
                if expected_key == "links":
                    joined_lists = extract_and_combine_links(json_data)
                    return response.reason, joined_lists
                else:
                    return response.reason, json_data
            else:
                LOGGER.warning('Response does not include the key: "data".')
                return response.reason, None
        else:
            LOGGER.warning(
                f"Status Code: {response.status_code}, Response: {response.reason}"
            )
            return response.reason, None

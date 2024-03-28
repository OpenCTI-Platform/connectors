import os
from typing import Dict

import requests
from pycti import OpenCTIConnectorHelper


class SafeBrowsingConnector:
    """Specific external-import connector

    This class encapsulates the main actions, expected to be run by the
    any external-import connector. Note that the attributes defined below
    will be complemented per each connector type.

    Attributes:
        helper (OpenCTIConnectorHelper): The helper to use.
        update_existing_data (str): Whether to update existing data or not in OpenCTI.
    """

    def __init__(self):
        self.helper = OpenCTIConnectorHelper({})

        update_existing_data = os.environ.get("CONNECTOR_UPDATE_EXISTING_DATA", "false")
        if update_existing_data.lower() in ["true", "false"]:
            self.update_existing_data = update_existing_data.lower()
        else:
            msg = f"Error when grabbing CONNECTOR_UPDATE_EXISTING_DATA environment variable: '{self.interval}'. It SHOULD be either `true` or `false`. `false` is assumed. "
            self.helper.log_warning(msg)
            self.update_existing_data = "false"

    def google_safe_browsing(self, observable):
        """Checks a domain against the Google Safe Browsing API."""

        API_KEY = os.environ.get("GOOGLE_SAFE_BROWSING_API_KEY", "")
        domain = observable["value"]
        url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={API_KEY}"
        payload = {
            "client": {
                "clientId": "OpenCTI_Connector",
                "clientVersion": "1.0",
            },
            "threatInfo": {
                "threatTypes": [
                    "MALWARE",
                    "SOCIAL_ENGINEERING",
                    "UNWANTED_SOFTWARE",
                    "POTENTIALLY_HARMFUL_APPLICATION",
                    "THREAT_TYPE_UNSPECIFIED",
                ],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": [
                    "URL",
                    "EXECUTABLE",
                    "THREAT_ENTRY_TYPE_UNSPECIFIED",
                ],
                "threatEntries": [{"url": domain}],
            },
        }
        response = requests.post(
            url,
            json=payload,
        )
        if response.status_code == 200:
            if response.json():
                # self.helper.log_info(f"Domain {domain} flagged by Safe Browsing")

                # Get the existing description and add the new one

                if observable.get("x_opencti_description") is None:
                    existing_description = ""
                else:
                    existing_description = (
                        observable.get("x_opencti_description") + "\n"
                    )

                safe_browsing_output = response.json()

                first_output = safe_browsing_output.get("matches")[0]

                observable_description = f"Domain flagged by Safe Browsing \n + Threat Type: {first_output.get('threatType')} \n + Platform Type: {first_output.get('platformType')} \n + Threat Entry Type: {first_output.get('threatEntryType')}"

                self.helper.api.stix_cyber_observable.update_field(
                    id=observable["id"],
                    input={
                        "key": "x_opencti_description",
                        "value": existing_description + observable_description,
                    },
                )

                self.helper.api.stix_cyber_observable.add_label(
                    id=observable["id"], label_name=first_output.get("threatType")
                )

        else:
            self.helper.log_error(f"Error checking domain: {response.status_code}")

        return None

    def process_message(self, data: Dict):
        """Processing the enrichment request

        Build a bundle

        Args:
            data (dict): The data to process. The `enrichment_entity` attribute contains the object to enrich.
        """
        self.entity_id = data["entity_id"]
        observable = self.helper.api.stix_cyber_observable.read(id=self.entity_id)

        if observable["entity_type"] == "DomainName":
            return self.google_safe_browsing(observable)
        elif observable["entity_type"] == "Url":
            return self.google_safe_browsing(observable)
        elif observable["entity_type"] == "Hostname":
            return self.google_safe_browsing(observable)

    # Start the main loop
    def start(self):
        self.helper.listen(message_callback=self.process_message)

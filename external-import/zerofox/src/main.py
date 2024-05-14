import os
import sys
import time
from datetime import datetime
from typing import Any, List

import stix2
from lib.external_import import ExternalImportConnector
from mappers import threat_feed_to_stix
from zerofox.app.endpoints import CTIEndpoint
from zerofox.app.zerofox import ZeroFox

ZEROFOX_REFERENCE = stix2.ExternalReference(
    source_name="ZeroFox Threat Intelligence",
    url="https://www.zerofox.com/threat-intelligence/",
    description="ZeroFox provides comprehensive, accurate, and timely intelligence bundles through its API.",
)


class ZeroFoxConnector(ExternalImportConnector):
    def __init__(self):
        """ZeroFox connector for OpenCTI."""
        super().__init__()
        self.zerofox_username = os.environ.get("ZEROFOX_USERNAME", "")
        self.zerofox_password = os.environ.get("ZEROFOX_PASSWORD", "")
        self.client = ZeroFox(user=self.zerofox_username, token=self.zerofox_password)

    def fetch_stix_from_endpoint(
        self, endpoint: CTIEndpoint, now: datetime, last_run: datetime
    ) -> List[Any]:
        stix_objects = []
        self.helper.log_debug(f"Fetching data from {endpoint}")
        try:
            for entry in self.client.fetch_feed(endpoint, last_run):
                self.helper.log_debug(entry)
                stix_data = threat_feed_to_stix(endpoint)(now, entry)
                self.helper.log_debug(
                    f"{len(stix_data)} STIX2 objects have been obtained from malware entry {entry}."
                )
                stix_objects.extend(stix_data)
            return stix_objects
        except Exception as e:
            self.helper.log_error(f"Error fetching data from {endpoint}: {str(e)}")
            return stix_objects

    def _collect_intelligence(self, now: datetime, last_run: datetime) -> List[Any]:
        """
        Collects intelligence from channels

        Add your code depending on the use case as stated at https://docs.opencti.io/latest/development/connectors/.
        Some sample code is provided as a guide to add a specific observable and a reference to the main object.
        Consider adding additional methods to the class to make the code more readable.

        Returns:
            stix_objects: A list of STIX2 objects.
        """
        self.helper.log_debug(
            f"{self.helper.connect_name} connector is starting the collection of objects..."
        )
        stix_objects = []
        # ===========================
        for endpoint in [CTIEndpoint.Phishing]:
            self.helper.log_debug(f"Fetching data from {endpoint}")
            stix_objects += self.fetch_stix_from_endpoint(endpoint, now, last_run)
        # ===========================

        self.helper.log_info(
            f"{len(stix_objects)} STIX2 objects have been compiled by {self.helper.connect_name} connector. "
        )
        return stix_objects


if __name__ == "__main__":
    try:
        connector = ZeroFoxConnector()
        print("connector created")
        connector.run()
    except Exception as e:
        print(e)
        time.sleep(10)
        sys.exit(0)

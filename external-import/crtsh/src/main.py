# import os
import sys
import time
import traceback
from datetime import datetime

from crtsh import CrtSHClient
from lib.external_import import ExternalImportConnector

MARKING_REFS = ["TLP:WHITE", "TLP:GREEN", "TLP:AMBER", "TLP:RED"]


class CrtshConnector(ExternalImportConnector):
    def __init__(self):
        """Initialization of the connector"""
        super().__init__()
        self._get_config_variables()
        self.api = CrtSHClient(
            self.domain,
            labels=self.labels,
            marking_refs=self.marking_refs,
            is_expired=self.is_expired,
            is_wildcard=self.is_wildcard,
        )

    def _get_config_variables(self):
        """Get config variables from the connector settings"""
        self.domain = self.config.crtsh.domain
        self.labels = self.config.crtsh.labels
        self.marking_refs = self.config.crtsh.marking_refs
        self.is_expired = self.config.crtsh.is_expired
        self.is_wildcard = self.config.crtsh.is_wildcard

    def _collect_intelligence(self, since: datetime = None) -> list:
        """Collects intelligence from channels and transforms it into STIX2 objects.

        Returns:
            stix_objects: A list of STIX2 objects."""
        self.helper.log_debug(
            f"{self.helper.connect_name} connector is starting the collection of objects..."
        )

        stix_objects = self.api.get_stix_objects(since=since)
        if stix_objects:
            stix_objects.append(self.api.author)

        self.helper.log_info(
            f"{len(stix_objects)} STIX2 objects have been compiled by {self.helper.connect_name} connector. "
        )
        return stix_objects


if __name__ == "__main__":
    try:
        connector = CrtshConnector()
        connector.run()
    except Exception:
        traceback.print_exc()
        time.sleep(10)
        sys.exit(1)

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
        self._next_last_cert_id = None
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

    def _collect_intelligence(  # pylint: disable=unused-argument
        self, since: datetime = None
    ) -> list:
        """Collects intelligence from channels and transforms it into STIX2 objects.

        Only certificates with a crt.sh id higher than the ``last_cert_id`` stored
        in the connector state are imported. ``since`` (the last run time) is no
        longer used, because crt.sh stopped returning ``entry_timestamp``.

        Returns:
            stix_objects: A list of STIX2 objects."""
        self.helper.log_debug(
            f"{self.helper.connect_name} connector is starting the collection of objects..."
        )
        current_state = self.helper.get_state() or {}
        last_cert_id = current_state.get("last_cert_id")
        if last_cert_id is None:
            self.helper.log_info(
                f"{self.helper.connect_name} connector has no last_cert_id in its state, "
                "importing every certificate returned by crt.sh"
            )

        self._next_last_cert_id = None
        stix_objects, next_last_cert_id = self.api.get_stix_objects(
            last_cert_id=last_cert_id
        )
        if stix_objects:
            stix_objects.append(self.api.author)
        self._next_last_cert_id = next_last_cert_id
        self.helper.log_info(
            f"{len(stix_objects)} STIX2 objects have been compiled by {self.helper.connect_name} connector. "
        )
        return stix_objects

    def _get_state_updates(self) -> dict:
        """Store the highest certificate id seen, once the run has succeeded."""
        if self._next_last_cert_id is None:
            return {}
        return {"last_cert_id": self._next_last_cert_id}


if __name__ == "__main__":
    try:
        connector = CrtshConnector()
        connector.run()
    except Exception:
        traceback.print_exc()
        time.sleep(10)
        sys.exit(1)

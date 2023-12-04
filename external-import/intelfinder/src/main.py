import sys
import time
from os import environ

from intelfinder import Intelfinder
from intelfinder.utils import (
    format_labels,
    validate_api_key,
    validate_labels,
    validate_tlp_marking,
)
from lib.external_import import ExternalImportConnector


class IntelfinderConnector(ExternalImportConnector):
    def __init__(self):
        """Initialization of the connector"""
        super().__init__()
        self.helper.log_info("Initializing Intelfinder connector")
        self._get_config_variables()

    def _get_config_variables(self):
        """Get config variables from the environment"""
        self.helper.log_info("Getting config variables from environment")
        # Get INTELFINDER_TOKEN environment variable and validate it is valid.
        self.intelfinder_token = environ.get("INTELFINDER_TOKEN", None)
        if not validate_api_key(self.intelfinder_token):
            msg = "Error when grabbing INTELFINDER_TOKEN environment variable."
            self.helper.log_error(msg)
            raise ValueError(msg)
        # Get INTELFINDER_LABELS environment variable and validate it is valid. Defaults to TLP:WHITE if not set.
        self.intelfinder_labels = environ.get("INTELFINDER_LABELS", None)
        if not validate_labels(self.intelfinder_labels):
            msg = "Error when grabbing INTELFINDER_LABELS environment variable."
            self.helper.log_error(msg)
            raise ValueError(msg)
        else:
            self.intelfinder_labels = format_labels(self.intelfinder_labels)
        self.intelfinder_marking_refs = environ.get("INTELFINDER_MARKING_REFS", None)
        if not validate_tlp_marking(self.intelfinder_marking_refs):
            msg = "Error when grabbing INTELFINDER_MARKING_REFS environment variable. It SHOULD be a valid TLP marking."
            self.helper.log_error(msg)
            raise ValueError(msg)

        self.current_state = self.helper.get_state() if self.helper.get_state() else {}
        self.cursor = self._get_cursor()

    def _get_cursor(self):
        """Get the cursor from the state"""
        if isinstance(self.current_state, dict) and self.current_state:
            self.helper.log_info(
                f"Getting state cursor: {self.current_state.get('cursor', None)}"
            )
            return self.current_state.get("cursor", None)
        else:
            self.helper.log_warning("No state cursor found")
            return None

    def _set_cursor_state(self):
        """Set the state of the connector"""

        if self.current_state:
            self.current_state["cursor"] = self.cursor
        else:
            self.current_state = {"cursor": self.cursor}
        self.helper.log_info(
            f"Setting state cursor to {self.cursor}, {self.current_state}"
        )
        self.helper.set_state(self.current_state)
        self.helper.log_debug(f"Updated State: {self.helper.get_state()}")

    def _collect_intelligence(self) -> []:
        """Collects intelligence from channels

        Aadd your code depending on the use case as stated at https://docs.opencti.io/latest/development/connectors/.
        Some sample code is provided as a guide to add a specific observable and a reference to the main object.
        Consider adding additional methods to the class to make the code more readable.

        Returns:
            stix_objects: A list of STIX2 objects."""
        self.helper.log_debug(
            f"{self.helper.connect_name} connector is starting the collection of objects..."
        )
        stix_objects = []

        # ===========================
        # === Add your code below ===
        # ===========================
        """Processing the enrichment request"""
        self.helper.log_info("Processing enrichment request")
        intelfinder = Intelfinder(
            api_key=self.intelfinder_token,
            cursor=self.cursor,
            labels=self.intelfinder_labels,
            object_marking_refs=self.intelfinder_marking_refs,
        )
        stix_objects = []
        while intelfinder.has_next:
            self.helper.log_info(
                f"Retrieving alerts from Intelfinder, cursor: {self.cursor}"
            )
            intelfinder_stix_objects = intelfinder.get_stix_objects(
                cursor=intelfinder.cursor
            )
            self.cursor = intelfinder.get_cursor()
            if len(intelfinder_stix_objects) > 0:
                self.helper.log_info(
                    f"Retrieved {len(intelfinder_stix_objects)} STIX objects from Intelfinder"
                )
                stix_objects.extend(intelfinder_stix_objects)
            else:
                self.helper.log_info("No STIX objects retrieved from Intelfinder")
                break
        # ===========================
        # === Add your code above ===
        # ===========================
        self._set_cursor_state()
        self.helper.log_info(
            f"{len(stix_objects)} STIX2 objects have been compiled by {self.helper.connect_name} connector. "
        )
        self.helper.log_warning(f"Total processed alerts: {intelfinder.get_index()}")
        return stix_objects


if __name__ == "__main__":
    try:
        connector = IntelfinderConnector()
        connector.helper.log_info("Starting Intelfinder connector")
        connector.run()
    except Exception as e:
        print(e)
        time.sleep(10)
        sys.exit(0)

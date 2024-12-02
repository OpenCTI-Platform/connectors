# import os
import sys
import time
from datetime import datetime
from os import environ

from validators import domain as domain_validator

from crtsh import CrtSHClient
from lib.external_import import ExternalImportConnector

MARKING_REFS = ["TLP:WHITE", "TLP:GREEN", "TLP:AMBER", "TLP:RED"]


class crtshConnector(ExternalImportConnector):
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
        """Get config variables from the environment"""
        self.domain = environ.get("CRTSH_DOMAIN", None)
        if not domain_validator(self.domain):
            msg = f"Error when grabbing CRTSH_DOMAIN environment variable: '{self.domain}'. It SHOULD be a valid domain name. "
            self.helper.log_error(msg)
            raise ValueError(msg)
        self.labels = environ.get("CRTSH_LABELS", None)
        if not isinstance(self.labels, str):
            msg = f"Error when grabbing CRTSH_LABELS environment variable: '{self.labels}'. It SHOULD be a string. "
            self.helper.log_error(msg)
            raise ValueError(msg)
        self.marking_refs = environ.get("CRTSH_MARKING_REFS", None)
        if self.marking_refs is not None and self.marking_refs not in MARKING_REFS:
            msg = f"Error when grabbing CRTSH_MARKING_REFS environment variable: '{self.marking_refs}'. It SHOULD be one of {MARKING_REFS}. "
            self.helper.log_error(msg)
            raise ValueError(msg)
        self.is_expired = environ.get("CRTSH_IS_EXPIRED", False)
        if self.is_expired not in [True, False, "true", "false"]:
            msg = f"Error when grabbing CRTSH_IS_EXPIRED environment variable: '{self.is_expired}'. It SHOULD be either `True` or `False`. `False` is assumed."
            self.helper.log_warning(msg)
            self.is_expired = False
        self.is_wildcard = environ.get("CRTSH_IS_WILDCARD", False)
        if self.is_wildcard not in [True, False, "true", "false"]:
            msg = f"Error when grabbing CRTSH_IS_WILDCARD environment variable: '{self.is_wildcard}'. It SHOULD be either `True` or `False`. `False` is assumed."
            self.helper.log_warning(msg)
            self.is_wildcard = False

    def _collect_intelligence(self, since: datetime = None) -> []:
        """Collects intelligence from channels and transforms it into STIX2 objects.

        Returns:
            stix_objects: A list of STIX2 objects."""
        self.helper.log_debug(
            f"{self.helper.connect_name} connector is starting the collection of objects..."
        )

        stix_objects = self.api.get_stix_objects(since=since)

        self.helper.log_info(
            f"{len(stix_objects)} STIX2 objects have been compiled by {self.helper.connect_name} connector. "
        )
        return stix_objects


if __name__ == "__main__":
    try:
        connector = crtshConnector()
        connector.run()
    except Exception as e:
        print(e)
        time.sleep(10)
        sys.exit(0)

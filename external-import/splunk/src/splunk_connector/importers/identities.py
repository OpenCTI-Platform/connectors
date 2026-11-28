"""Asset and identity importer."""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from splunk_connector.importers.base import BaseImporter


class IdentitiesImporter(BaseImporter):
    """Import Splunk ES assets and identities."""

    state_key = "identities"
    name = "Identities"

    @property
    def interval(self) -> timedelta:
        return self.config.splunk.identities_interval

    def collect(self, state: dict[str, Any]) -> tuple[list[Any], dict[str, Any]]:
        if self.config.splunk.identities_search:
            records = self.client.run_search(
                self.config.splunk.identities_search,
                max_records=self.config.splunk.max_records_per_run,
            )
        else:
            records = self.client.get_assets_identities()
            records = self._cap_records(records, self.config.splunk.max_records_per_run)

        objects = []
        for record in records:
            objects.extend(self.converter.asset_identity_to_stix(record))
        return objects, self.success_state(len(objects), len(records))

"""Saved-search indicator importer."""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from splunk_connector.importers.base import BaseImporter


class IndicatorsImporter(BaseImporter):
    """Import Splunk saved searches as SPL indicators."""

    state_key = "indicators"
    name = "Indicators"

    @property
    def interval(self) -> timedelta:
        return self.config.splunk.indicators_interval

    def collect(self, state: dict[str, Any]) -> tuple[list[Any], dict[str, Any]]:
        if self.config.splunk.indicators_search:
            records = self.client.run_search(
                self.config.splunk.indicators_search,
                max_records=self.config.splunk.max_records_per_run,
            )
        else:
            records = self.client.get_saved_searches(
                include_disabled=self.config.splunk.include_disabled
            )
            records = self._cap_records(records, self.config.splunk.max_records_per_run)

        objects = []
        for record in records:
            objects.extend(
                self.converter.saved_search_to_stix(
                    record,
                    note_type=self.config.splunk.note_type_search_parameters,
                )
            )
        return objects, self.success_state(len(objects), len(records))

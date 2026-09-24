"""Finding and alert incident importer."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from splunk_connector.importers.base import BaseImporter


class IncidentsImporter(BaseImporter):
    """Import Splunk ES findings as incidents and sightings."""

    state_key = "incidents"
    name = "Incidents"

    @property
    def interval(self) -> timedelta:
        return self.config.splunk.incidents_interval

    def collect(self, state: dict[str, Any]) -> tuple[list[Any], dict[str, Any]]:
        earliest_time = self._earliest_time(state)
        if self.config.splunk.incidents_search:
            records = self.client.run_search(
                self.config.splunk.incidents_search,
                earliest_time=earliest_time,
                max_records=self.config.splunk.max_records_per_run,
            )
        else:
            records = self.client.get_findings(earliest_time=earliest_time)
            records = self._cap_records(records, self.config.splunk.max_records_per_run)

        objects = []
        for record in records:
            objects.extend(self.converter.finding_to_stix(record))
        new_state = self.success_state(len(objects), len(records))
        new_state["last_earliest_time"] = earliest_time
        return objects, new_state

    def _earliest_time(self, state: dict[str, Any]) -> str:
        dataset_state = state.get(self.state_key, {})
        last_success = dataset_state.get("last_success")
        if last_success:
            return str(last_success)
        start = datetime.now(UTC) - self.config.splunk.incidents_lookback
        return start.isoformat()

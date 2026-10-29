"""Import Cyble engine advisories as Reports."""

from __future__ import annotations

from typing import Generator

from connector.data_processors.engine_base import EngineDocumentsProcessor
from connector.mappers.engine_reports import checkpoint_value, map_advisory
from connectors_sdk.models import BaseIdentifiedObject


class AdvisoriesProcessor(EngineDocumentsProcessor):
    """Fetch advisory catalog cards and convert them to STIX Reports."""

    work_name = "Cyble Vision advisories import"

    def collect(self) -> Generator[list[dict], None, None]:
        yield from self.collect_pages(
            self.client.iter_advisories,
            self.state.last_advisory_publish_date,
            "advisory",
        )

    def transform(
        self, pages: Generator[list[dict], None, None]
    ) -> Generator[list[BaseIdentifiedObject], None, None]:
        for page in pages:
            objects: list[BaseIdentifiedObject] = []
            last_published = self.state.last_advisory_publish_date
            for item in page:
                try:
                    objects.extend(
                        map_advisory(item, self.author, self.default_marking)
                    )
                    stamp = checkpoint_value(item, "publish_date")
                    if stamp and (last_published is None or stamp > last_published):
                        last_published = stamp
                except Exception as err:
                    self.logger.warning(
                        "Failed to convert advisory, skipping it",
                        {"advisory_id": item.get("id"), "error": str(err)},
                    )
            if last_published:
                self.state.last_advisory_publish_date = last_published
            if objects:
                yield [self.author, self.default_marking] + objects

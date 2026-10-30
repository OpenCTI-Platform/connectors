"""Import Cyble engine newsflash items as Reports."""

from __future__ import annotations

from typing import Generator

from connector.data_processors.engine_base import EngineDocumentsProcessor
from connector.mappers.engine_reports import checkpoint_value, map_newsflash
from connectors_sdk.models import BaseIdentifiedObject


class NewsflashProcessor(EngineDocumentsProcessor):
    """Fetch newsflash spot reports and convert them to STIX Reports."""

    work_name = "Cyble Vision newsflash import"

    def collect(self) -> Generator[list[dict], None, None]:
        yield from self.collect_pages(
            self.client.iter_newsflash,
            self.state.last_newsflash_published_date,
            "newsflash",
        )

    def transform(
        self, pages: Generator[list[dict], None, None]
    ) -> Generator[list[BaseIdentifiedObject], None, None]:
        for page in pages:
            objects: list[BaseIdentifiedObject] = []
            last_published = self.state.last_newsflash_published_date
            for item in page:
                try:
                    objects.extend(
                        map_newsflash(item, self.author, self.default_marking)
                    )
                    stamp = checkpoint_value(item, "publishedDate")
                    if stamp and (last_published is None or stamp > last_published):
                        last_published = stamp
                except Exception as err:
                    self.logger.warning(
                        "Failed to convert newsflash item, skipping it",
                        {"title": item.get("title"), "error": str(err)},
                    )
            if last_published:
                self.state.last_newsflash_published_date = last_published
            if objects:
                yield [self.author, self.default_marking] + objects

"""Import Cyble engine newsfeed articles as Reports."""

from __future__ import annotations

from typing import Generator

from connector.data_processors.engine_base import EngineDocumentsProcessor
from connector.mappers.engine_reports import checkpoint_value, map_newsfeed
from connectors_sdk.models import BaseIdentifiedObject


class NewsfeedProcessor(EngineDocumentsProcessor):
    """Fetch newsfeed articles and convert them to STIX Reports."""

    work_name = "Cyble Vision newsfeed import"

    def collect(self) -> Generator[list[dict], None, None]:
        yield from self.collect_pages(
            self.client.iter_newsfeed,
            self.state.last_newsfeed_post_date,
            "newsfeed",
        )

    def transform(
        self, pages: Generator[list[dict], None, None]
    ) -> Generator[list[BaseIdentifiedObject], None, None]:
        for page in pages:
            objects: list[BaseIdentifiedObject] = []
            last_posted = self.state.last_newsfeed_post_date
            for item in page:
                try:
                    objects.extend(
                        map_newsfeed(item, self.author, self.default_marking)
                    )
                    stamp = checkpoint_value(item, "post_date", "created_at")
                    if stamp and (last_posted is None or stamp > last_posted):
                        last_posted = stamp
                except Exception as err:
                    self.logger.warning(
                        "Failed to convert newsfeed item, skipping it",
                        {"title": item.get("post_title"), "error": str(err)},
                    )
            if last_posted:
                self.state.last_newsfeed_post_date = last_posted
            if objects:
                yield [self.author, self.default_marking] + objects

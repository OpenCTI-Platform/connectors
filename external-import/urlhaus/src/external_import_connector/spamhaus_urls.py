"""Query client for the Spamhaus commercial URLhaus API (`GET /urlhaus/v1/urls`).

The JSON records are mapped onto the nine-column rows of the community CSV export
(`id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter`), so
that the converter to STIX is shared by both authentication modes.
"""

from collections.abc import Generator
from datetime import datetime, timezone
from typing import Any

from dateutil.parser import parse

URLS_PATH = "/urlhaus/v1/urls"
# Maximum accepted by the API
PAGE_SIZE = 100

_REQUIRED_FIELDS = ("id", "url", "url_status", "first_seen", "urlhaus_reference")


def item_to_row(item: dict[str, Any]) -> list[str]:
    """Map a Spamhaus `Url` record to a community CSV row.

    :param item: one element of the `items` list of the response
    :return: the row, as expected by `ConverterToStix`
    :raises ValueError: when a required field is missing
    """
    for field in _REQUIRED_FIELDS:
        if item.get(field) in (None, ""):
            raise ValueError(f"missing field '{field}'")
    return [
        str(item["id"]),
        item["first_seen"],
        item["url"],
        item["url_status"],
        # Omitted by the API while the URL is online
        item.get("last_online") or "",
        item.get("threat") or "",
        ",".join(tag for tag in item.get("tags") or [] if tag),
        item["urlhaus_reference"],
        item.get("reporter") or "",
    ]


def _format_since(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class SpamhausUrlsClient:
    """Read the URLs added to URLhaus since the checkpoint, page by page.

    `spamhaus` is the `connectors_sdk.shared.spamhaus.SpamhausClient`: it logs in, reuses the JWT, renews it
    once on a 401, and follows the cursor pagination (`paginate`).
    """

    def __init__(self, spamhaus, helper, config, state):
        self.spamhaus = spamhaus
        self.helper = helper
        self.config = config
        self.state = state

    def _since(self) -> datetime:
        if self.state.last_processed_entry_old > 0:
            return datetime.fromtimestamp(
                self.state.last_processed_entry_old, tz=timezone.utc
            )
        return self.config.urlhaus.spamhaus_import_from

    def get_entities(self) -> Generator[list[list[str]], None, None]:
        """Yield the rows of each page, advancing the checkpoint in the state.

        :raises SpamhausCommercialError: when the commercial API cannot be used
        """
        pages = self.spamhaus.paginate(
            URLS_PATH,
            params={"since": _format_since(self._since())},
            page_size=PAGE_SIZE,
        )
        for items in pages:
            rows = []
            for item in items:
                row = self._convert(item)
                if row is None:
                    continue
                # Seen, whether imported or filtered out below
                self.state.last_processed_entry_new = max(
                    parse(row[1]).timestamp(), self.state.last_processed_entry_new
                )
                if self.config.urlhaus.import_offline is False and row[3] == "offline":
                    continue
                rows.append(row)
            yield rows

    def _convert(self, item: dict[str, Any]) -> list[str] | None:
        """Map an item, or log a warning and return None when it is unusable."""
        try:
            row = item_to_row(item)
            parse(row[1])
        except (ValueError, OverflowError) as err:
            self.helper.connector_logger.warning(
                "[API] Skipping a URLhaus record that cannot be converted",
                {"id": item.get("id"), "reason": str(err)},
            )
            return None
        return row

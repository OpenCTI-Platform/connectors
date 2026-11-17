"""Relay the account's AbuseIPDB TAXII feed into OpenCTI, one bundle per page."""

from collections.abc import Generator, Iterable
from typing import Any

from abuseipdb_taxii_client import (
    AbuseIPDBTaxiiClient,
    TaxiiBadRequestError,
    TaxiiPage,
)
from connector.settings import ConnectorSettings
from connector.state import ConnectorState
from connectors_sdk import (
    BaseDataProcessor,
    ConnectorError,
    ProviderApiInvalidResponseError,
)


class TaxiiRepeatedCursorError(ProviderApiInvalidResponseError):
    """The TAXII server returned a continuation cursor already seen in this pull."""


class TaxiiFeedProcessor(BaseDataProcessor[ConnectorSettings, ConnectorState]):
    """Drain the account's TAXII feed and relay every page unchanged.

    ``collect()`` follows ``more``/``next`` until the feed answers
    ``more: false``. ``transform()`` hands each page's objects to the SDK and
    only then records the position, so the saved state never points past a page
    that was not sent.
    """

    work_name = "AbuseIPDB TAXII feed import"

    def post_init(self) -> None:
        config = self.settings.abuseipdb_taxii
        self.client = AbuseIPDBTaxiiClient(
            api_root=config.api_root,
            username=config.username,
            password=config.password.get_secret_value(),
            timeout=config.request_timeout_seconds,
            ssl_verify=config.verify_ssl,
        )

    def collect(self) -> Generator[TaxiiPage, None, None]:
        config = self.settings.abuseipdb_taxii
        collection_id = self.client.discover_collection_id(config.collection_id)
        # The server accepts a position from another feed, so a saved position
        # is only reused for the feed it was recorded on.
        if (
            self.state.collection_id is not None
            and self.state.collection_id != collection_id
        ):
            self.state.next_cursor = None
            self.state.added_after = None
            self.logger.info(
                "AbuseIPDB TAXII feed changed; the saved position is dropped"
            )
        self.state.collection_id = collection_id

        # A relative import start is resolved again at every process start, so
        # it is saved: a pull that restarts before its first server watermark
        # must begin where the first attempt did.
        if self.state.added_after is None:
            self.state.added_after = config.import_since_iso
        added_after = self.state.added_after
        cursor = self.state.next_cursor
        seen_cursors: set[str | None] = {cursor} if cursor else set()

        self.logger.info(
            "AbuseIPDB TAXII pull started", meta={"resumed": cursor is not None}
        )

        more = True
        while more:
            page = self.client.get_objects_page(
                collection_id,
                added_after=added_after,
                next_cursor=cursor,
                limit=config.page_size,
            )
            yield page
            more = page.more
            if more:
                if page.next_cursor in seen_cursors:
                    raise TaxiiRepeatedCursorError(
                        "AbuseIPDB TAXII returned a repeated continuation cursor"
                    )
                seen_cursors.add(page.next_cursor)
                cursor = page.next_cursor

    def transform(
        self, pages: Iterable[TaxiiPage]
    ) -> Generator[list[dict[str, Any]], None, None]:
        page_count = 0
        objects_submitted = 0
        drained = False
        try:
            for page in pages:
                if page.objects:
                    yield page.objects
                page_count += 1
                objects_submitted += len(page.objects)
                if page.more:
                    self.state.next_cursor = page.next_cursor
                else:
                    self.state.next_cursor = None
                    if page.added_last is not None:
                        self.state.added_after = page.added_last
                    drained = True
        # Only connector errors end the pull here; any other error must reach the
        # SDK so the work fails and no state from this run is saved.
        except ConnectorError as err:
            if (
                isinstance(err, (TaxiiBadRequestError, TaxiiRepeatedCursorError))
                and self.state.next_cursor is not None
            ):
                self.state.next_cursor = None
            self.logger.exception(
                "AbuseIPDB TAXII pull stopped early",
                meta={"error_type": type(err).__name__, "error": str(err)},
            )
        self.logger.info(
            "AbuseIPDB TAXII pull finished",
            meta={
                "drained": drained,
                "pages": page_count,
                "objects_submitted": objects_submitted,
            },
        )

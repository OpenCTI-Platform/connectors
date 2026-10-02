"""Relay the account's AbuseIPDB TAXII feed into OpenCTI, one bundle per page."""

from __future__ import annotations

from collections.abc import Generator, Iterable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

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
from pycti import Indicator

if TYPE_CHECKING:
    from pycti import OpenCTIConnectorHelper


class TaxiiRepeatedCursorError(ProviderApiInvalidResponseError):
    """The TAXII server returned a continuation cursor already seen in this pull."""


def _indicator_ids(stix_object: dict[str, Any]) -> set[str]:
    """Return the IDs OpenCTI may know an indicator by.

    That is the feed's own ID, plus the ID OpenCTI derives from the pattern.
    """
    ids = {stix_object["id"]}
    pattern = stix_object.get("pattern")
    if isinstance(pattern, str) and pattern:
        ids.add(Indicator.generate_id(pattern))
    return ids


@dataclass(frozen=True)
class CollectedPage:
    """A fetched page and the indicator IDs OpenCTI already held when it was fetched."""

    page: TaxiiPage
    known_ids: frozenset[str]


@dataclass
class PullStats:
    """Counts of what one pull submitted to OpenCTI."""

    pages: int = 0
    objects_submitted: int = 0
    new_indicators: int = 0
    re_served_indicators: int = 0
    _seen_ids: set[str] = field(default_factory=set, init=False, repr=False)

    def record_page(
        self, objects: list[dict[str, Any]], known_ids: frozenset[str]
    ) -> None:
        """Count one delivered page.

        An indicator is re-served when OpenCTI already held it, or when it was
        delivered earlier in the same pull; otherwise it is new.
        """
        self.pages += 1
        self.objects_submitted += len(objects)
        for stix_object in objects:
            if stix_object["type"] != "indicator":
                continue
            ids = _indicator_ids(stix_object)
            if ids & known_ids or ids & self._seen_ids:
                self.re_served_indicators += 1
            else:
                self.new_indicators += 1
            self._seen_ids |= ids


class TaxiiFeedProcessor(BaseDataProcessor[ConnectorSettings, ConnectorState]):
    """Drain the account's TAXII feed and relay every page unchanged.

    ``collect()`` follows ``more``/``next`` until the feed answers
    ``more: false``. ``transform()`` hands each page's objects to the SDK and
    only then records the position, so the saved state never points past a page
    that was not sent.
    """

    work_name = "AbuseIPDB TAXII feed import"

    def inject_dependencies(
        self,
        settings: ConnectorSettings,
        helper: OpenCTIConnectorHelper,
        state: ConnectorState,
    ) -> None:
        super().inject_dependencies(settings=settings, helper=helper, state=state)
        self._helper = helper

    def post_init(self) -> None:
        config = self.settings.abuseipdb_taxii
        self.client = AbuseIPDBTaxiiClient(
            api_root=config.api_root,
            username=config.username,
            password=config.password.get_secret_value(),
            timeout=config.request_timeout_seconds,
            ssl_verify=config.verify_ssl,
        )

    def _known_indicator_ids(self, objects: list[dict[str, Any]]) -> frozenset[str]:
        """Return the IDs of the page's indicators that OpenCTI already holds."""
        indicators = [obj for obj in objects if obj["type"] == "indicator"]
        if not indicators:
            return frozenset()

        feed_ids = sorted({obj["id"] for obj in indicators})
        canonical_ids = sorted(
            {
                Indicator.generate_id(obj["pattern"])
                for obj in indicators
                if isinstance(obj.get("pattern"), str) and obj["pattern"]
            }
        )
        filters: list[dict[str, Any]] = [
            {"key": "x_opencti_stix_ids", "values": feed_ids}
        ]
        if canonical_ids:
            filters.append({"key": "standard_id", "values": canonical_ids})

        known: set[str] = set()
        # The lookup only feeds the run summary, so a failure must never cost the
        # page: on server-paced feeds a page that is not sent is not served again.
        try:
            matches = self._helper.api.stix_core_object.list(
                types=["Indicator"],
                filters={"mode": "or", "filters": filters, "filterGroups": []},
                first=len(feed_ids) + len(canonical_ids),
                customAttributes="standard_id x_opencti_stix_ids",
            )
            for match in matches:
                if not isinstance(match, dict):
                    continue
                standard_id = match.get("standard_id")
                if isinstance(standard_id, str):
                    known.add(standard_id)
                stix_ids = match.get("x_opencti_stix_ids")
                if isinstance(stix_ids, list):
                    known.update(
                        stix_id for stix_id in stix_ids if isinstance(stix_id, str)
                    )
        except Exception as err:
            self.logger.warning(
                "AbuseIPDB TAXII indicator lookup failed; the page's indicators are counted as new",
                meta={"error_type": type(err).__name__},
            )
            return frozenset()
        return frozenset(known)

    def collect(self) -> Generator[CollectedPage, None, None]:
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

        added_after = self.state.added_after or config.import_since_iso
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
            yield CollectedPage(
                page=page, known_ids=self._known_indicator_ids(page.objects)
            )
            more = page.more
            if more:
                if page.next_cursor in seen_cursors:
                    raise TaxiiRepeatedCursorError(
                        "AbuseIPDB TAXII returned a repeated continuation cursor"
                    )
                seen_cursors.add(page.next_cursor)
                cursor = page.next_cursor

    def transform(
        self, pages: Iterable[CollectedPage]
    ) -> Generator[list[dict[str, Any]], None, None]:
        stats = PullStats()
        drained = False
        try:
            for collected in pages:
                page = collected.page
                if page.objects:
                    yield page.objects
                stats.record_page(page.objects, collected.known_ids)
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
                "pages": stats.pages,
                "objects_submitted": stats.objects_submitted,
                "new_indicators": stats.new_indicators,
                "re_served_indicators": stats.re_served_indicators,
            },
        )

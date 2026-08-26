"""ORKL report processor pipeline.

Wires the ORKL client -> models -> converter -> OpenCTI using the SDK
``BaseDataProcessor`` contract. This module owns the incremental-sync
strategy; all ORKL -> STIX mapping lives in :mod:`orkl.converter_to_stix`.
"""

from __future__ import annotations

from collections.abc import Generator
from datetime import datetime, timezone
from typing import Any

from connectors_sdk import BaseDataProcessor
from connectors_sdk.models.base_identified_entity import BaseIdentifiedEntity
from orkl.client_api import OrklClient
from orkl.converter_to_stix import OrklConverter
from orkl.models import OrklLibraryEntry, _parse_iso8601
from pydantic import ValidationError


def _dedupe_by_id(objects: list[Any]) -> list[Any]:
    """Return objects with duplicate ids removed, order preserved.

    Objects without an ``id`` are always kept. Duplicate ids arise
    legitimately when one report carries the same real-world actor several
    times under different names: they regenerate the same deterministic id.
    """
    seen: set[str] = set()
    unique: list[Any] = []
    for obj in objects:
        obj_id = getattr(obj, "id", None)
        if obj_id is None:
            unique.append(obj)
            continue
        if obj_id in seen:
            continue
        seen.add(obj_id)
        unique.append(obj)
    return unique


class OrklReportProcessor(BaseDataProcessor):
    """Collect ORKL library entries and convert them into STIX Reports.

    Pipeline:
        collect() -> lazily page ORKL entries (newest-updated first),
            apply the incremental-sync cutoff, yield surviving raw dicts.
        transform() -> parse each dict, convert to STIX objects, yield
            one deduplicated bundle per page.
    """

    _config: Any
    _client: OrklClient
    _converter: OrklConverter

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def post_init(self) -> None:
        """Build the client and converter once dependencies are injected."""
        self._config = self.settings.orkl  # type: ignore[attr-defined]
        api_base_url = str(self._config.api_base_url).rstrip("/")
        self._client = OrklClient(base_url=api_base_url)
        self._converter = OrklConverter(
            api_base_url=api_base_url,
            tlp_level=self._config.tlp_level.value,
            threat_actor_as_intrusion_set=self._config.threat_actor_as_intrusion_set,
            ingest_tools=self._config.ingest_tools,
        )

    # ------------------------------------------------------------------
    # Pipeline
    # ------------------------------------------------------------------

    def collect(self) -> Generator[list[dict[str, Any]], None, None]:
        """Page through ORKL entries, applying the incremental-sync cutoff.

        ORKL exposes no server-side date filter; the only lever is
        ``order_by=updated_at&order=desc``. Entries arrive newest-updated
        first, so once an entry is older than or equal to the cutoff every
        entry after it is older too and we stop iterating immediately. The
        client generator is lazy, so stopping here stops the HTTP requests.

        Yields:
            Pages of surviving raw entry dicts. Fully-filtered pages are not
            yielded.
        """
        cutoff = self._resolve_cutoff()
        self.work_name = f"ORKL reports since {cutoff.isoformat()}"
        self.logger.info(f"Collecting ORKL reports updated after {cutoff.isoformat()}")

        pages_fetched = 0
        entries_seen = 0
        skipped_deleted = 0
        kept_unparseable = 0
        stop = False

        for page in self._client.iter_library_entries():
            pages_fetched += 1
            surviving: list[dict[str, Any]] = []
            for raw in page:
                entries_seen += 1
                updated = _parse_iso8601(raw.get("updated_at"))

                if updated is not None and updated <= cutoff:
                    # Descending order guarantees everything after this is
                    # also older than the cutoff; stop paging entirely.
                    stop = True
                    break

                if updated is None:
                    # An unparseable date cannot be positioned against the
                    # cutoff. Stopping here would silently truncate the
                    # import, so keep the entry and keep going instead.
                    kept_unparseable += 1
                    self.logger.warning(
                        f"ORKL entry {raw.get('id')!r} has an unparseable "
                        f"updated_at ({raw.get('updated_at')!r}); keeping it "
                        "and continuing rather than stopping the run."
                    )

                if raw.get("deleted_at") is not None:
                    # Tombstoned rows are ordinary entries that happen to be
                    # deleted, not a stop signal: live entries may follow.
                    skipped_deleted += 1
                    continue

                surviving.append(raw)

            if surviving:
                self.logger.info(
                    f"Page {pages_fetched}: {len(surviving)} entries to process."
                )
                yield surviving

            if stop:
                break

        self.logger.info(
            "ORKL collection complete: "
            f"{pages_fetched} page(s) fetched, {entries_seen} entries seen, "
            f"{skipped_deleted} deleted skipped, {kept_unparseable} with an "
            "unparseable date kept."
        )

    def transform(
        self, data: Generator[list[dict[str, Any]], None, None]
    ) -> Generator[list[Any], None, None]:
        """Parse raw entries and convert them to STIX objects, one bundle per page.

        Each entry is parsed and converted inside its own guard so a single
        malformed or unconvertible row can never abort the run -- this is a
        public feed we do not control.

        Args:
            data: Generator of raw entry pages from ``collect()``.

        Yields:
            Deduplicated lists of STIX/SDK objects, one per page.
        """
        reports_produced = 0
        for page in data:
            stix_objects: list[Any] = []
            for raw in page:
                try:
                    entry = OrklLibraryEntry.model_validate(raw)
                except ValidationError as err:
                    self.logger.error(
                        f"Skipping ORKL entry {raw.get('id')!r}: "
                        f"failed to parse ({err})."
                    )
                    continue

                try:
                    objects = self._converter.convert_entry(entry)
                except Exception as err:  # noqa: BLE001
                    self.logger.error(
                        f"Skipping ORKL entry {entry.id!r}: "
                        f"failed to convert to STIX ({err})."
                    )
                    continue

                stix_objects.extend(objects)

            if stix_objects:
                unique = _dedupe_by_id(stix_objects)
                page_reports = sum(
                    1
                    for obj in unique
                    if isinstance(obj, BaseIdentifiedEntity)
                    and obj.id.startswith("report--")
                )
                reports_produced += page_reports
                self.logger.info(
                    f"Sending {len(unique)} STIX object(s) "
                    f"({page_reports} report(s)) for page."
                )
                yield unique

        self.logger.info(
            f"ORKL transform complete: {reports_produced} report(s) produced."
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _resolve_cutoff(self) -> datetime:
        """Return the incremental-sync cutoff as a tz-aware datetime.

        Uses ``state.last_run`` when set, otherwise falls back to
        ``now(UTC) - import_start_date``. A naive ``last_run`` is treated as
        UTC so it can be compared against tz-aware entry timestamps.
        """
        last_run = self.state.last_run
        if last_run is not None:
            if last_run.tzinfo is None:
                return last_run.replace(tzinfo=timezone.utc)
            return last_run
        return datetime.now(timezone.utc) - self._config.import_start_date

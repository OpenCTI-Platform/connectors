"""ORKL report processor: collect library entries and convert them to STIX.

Owns both the incremental-sync strategy and the ORKL -> STIX mapping, using the
SDK ``BaseDataProcessor`` contract. Every STIX object is built through
connectors-sdk models (deterministic pycti ids); the stix2 constructors are
never called directly, so the repository's STIX-id pylint plugin stays happy.
"""

from __future__ import annotations

from collections.abc import Generator
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import urlparse

from connectors_sdk import BaseDataProcessor
from connectors_sdk.models import (
    ExternalReference,
    IntrusionSet,
    OrganizationAuthor,
    Relationship,
    Report,
    ThreatActorGroup,
    TLPMarking,
    Tool,
)
from connectors_sdk.models.base_identified_entity import BaseIdentifiedEntity
from connectors_sdk.models.enums import RelationshipType
from orkl.client_api import OrklClient
from orkl.models import OrklLibraryEntry, OrklThreatActor, _parse_iso8601
from pydantic import ValidationError

# --- Constants ---

# Any parsed date before this year is the API's "no known date" sentinel and is
# treated as unusable (mirrors ``orkl.models._MIN_VALID_YEAR``).
_MIN_VALID_YEAR = 1970

# Last-resort publication date. A Report's STIX id derives from
# ``PyctiReport.generate_id(name, published)``, so a non-deterministic fallback
# such as ``datetime.now(UTC)`` would mint a brand-new id on every conversion
# and silently duplicate the Report on each sync. A fixed 1970 sentinel keeps
# the id stable and is a visible signal that ORKL supplied no usable date.
_ID_STABILITY_SENTINEL_DATE = datetime(1970, 1, 1, tzinfo=timezone.utc)

# Safety overlap subtracted from ``state.last_run`` when computing the next
# incremental-sync cutoff. The SDK stamps ``last_run`` only after every
# processor finishes (T_end), while ``collect()`` reads its first page at the
# start of the run. Any entry whose ``updated_at`` falls in that window would
# otherwise be imported by neither run. Re-scanning a few minutes of boundary is
# harmless because every emitted STIX id is deterministic, so re-processing an
# entry updates it in place rather than duplicating it.
_CUTOFF_OVERLAP = timedelta(minutes=5)

# Module-level author reused across every emitted object; identity is stable so
# ``created_by_ref`` resolves to a single Identity in the produced bundle.
ORKL_AUTHOR = OrganizationAuthor(
    name="ORKL",
    description=(
        "ORKL is a community-driven library of publicly released cyber threat "
        "intelligence reports, sponsored by Sunet."
    ),
)

_ARCHIVE_SOURCE_NAME = "ORKL Archive"
_REFERENCE_FALLBACK_SOURCE_NAME = "ORKL reference"


# --- Pure helpers ---


def _usable_datetime(value: datetime | None) -> datetime | None:
    """Return `value` only when it is a genuine date past the year sentinel."""
    if value is None or value.year < _MIN_VALID_YEAR:
        return None
    return value


def _datetime_from_epoch(value: int | None) -> datetime | None:
    """Parse a Unix-epoch timestamp to a usable tz-aware datetime, or None."""
    if value is None:
        return None
    try:
        parsed = datetime.fromtimestamp(value, tz=timezone.utc)
    except (OSError, OverflowError, ValueError):
        return None
    return _usable_datetime(parsed)


def _is_usable_url(url: str) -> bool:
    """Return True when `url` has both a scheme and a network location."""
    try:
        parsed = urlparse(url)
    except ValueError:
        return False
    return bool(parsed.scheme and parsed.netloc)


def _reference_source_name(url: str) -> str:
    """Derive a non-empty source name from a URL's hostname (``www.`` stripped)."""
    try:
        host = urlparse(url).hostname
    except ValueError:
        return _REFERENCE_FALLBACK_SOURCE_NAME
    if not host:
        return _REFERENCE_FALLBACK_SOURCE_NAME
    return host[len("www.") :] if host.startswith("www.") else host


def _dedupe_by_id(objects: list[Any]) -> list[Any]:
    """Return objects with duplicate ids removed, order preserved.

    Objects without an ``id`` are always kept. Duplicate ids arise legitimately
    when one report carries the same real-world actor several times under
    different names (e.g. two ``SaintBear`` entries from different sources):
    they regenerate the same deterministic id and should be referenced once.
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
        collect() -> lazily page ORKL entries (newest-updated first), apply the
            incremental-sync cutoff, yield surviving raw dicts.
        transform() -> parse each dict, convert to STIX objects, yield one
            deduplicated bundle per page.
    """

    _config: Any
    _client: OrklClient
    _api_base_url: str
    _marking: TLPMarking
    _threat_actor_as_intrusion_set: bool
    _ingest_tools: bool

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def post_init(self) -> None:
        """Build the client and read conversion config once dependencies exist."""
        self._config = self.settings.orkl  # type: ignore[attr-defined]
        self._api_base_url = str(self._config.api_base_url).rstrip("/")
        self._client = OrklClient(base_url=self._api_base_url, logger=self.logger)
        self._marking = TLPMarking(level=self._config.tlp_level.value)
        self._threat_actor_as_intrusion_set = self._config.threat_actor_as_intrusion_set
        self._ingest_tools = self._config.ingest_tools

    # ------------------------------------------------------------------
    # Pipeline
    # ------------------------------------------------------------------

    def collect(self) -> Generator[list[dict[str, Any]], None, None]:
        """Page through ORKL entries, applying the incremental-sync cutoff.

        ORKL exposes no server-side date filter, only ``order_by=updated_at&
        order=desc``. Entries arrive newest-updated first, so once one is older
        than or equal to the cutoff every entry after it is too and we stop; the
        lazy client generator then issues no further HTTP requests.

        Yields:
            Pages of surviving raw entry dicts. Fully-filtered pages are skipped.
        """
        cutoff = self._resolve_cutoff()
        self.work_name = f"ORKL reports since {cutoff.isoformat()}"
        self.logger.info(
            "Collecting ORKL reports", {"updated_after": cutoff.isoformat()}
        )

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
                    # Descending order guarantees everything after this is also
                    # older than the cutoff; stop paging entirely.
                    stop = True
                    break

                if updated is None:
                    # An unparseable date cannot be positioned against the
                    # cutoff. Stopping here would silently truncate the import,
                    # so keep the entry and keep going instead.
                    kept_unparseable += 1
                    self.logger.warning(
                        "ORKL entry has an unparseable updated_at; keeping it "
                        "and continuing rather than stopping the run",
                        {
                            "entry_id": raw.get("id"),
                            "updated_at": raw.get("updated_at"),
                        },
                    )

                if raw.get("deleted_at") is not None:
                    # Tombstoned rows are ordinary entries that happen to be
                    # deleted, not a stop signal: live entries may follow.
                    skipped_deleted += 1
                    continue

                surviving.append(raw)

            if surviving:
                self.logger.info(
                    "Collected ORKL entries page",
                    {"page": pages_fetched, "entries": len(surviving)},
                )
                yield surviving

            if stop:
                break

        self.logger.info(
            "ORKL collection complete",
            {
                "pages_fetched": pages_fetched,
                "entries_seen": entries_seen,
                "skipped_deleted": skipped_deleted,
                "kept_unparseable": kept_unparseable,
            },
        )

    def transform(
        self, data: Generator[list[dict[str, Any]], None, None]
    ) -> Generator[list[Any], None, None]:
        """Parse and convert raw entries to STIX, one deduplicated bundle per page.

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
                        "Skipping ORKL entry: failed to parse",
                        {"entry_id": raw.get("id"), "error": str(err)},
                    )
                    continue

                try:
                    objects = self._convert_entry(entry)
                except Exception as err:  # noqa: BLE001
                    self.logger.error(
                        "Skipping ORKL entry: failed to convert to STIX",
                        {"entry_id": entry.id, "error": str(err)},
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
                    "Sending STIX objects for page",
                    {"objects": len(unique), "reports": page_reports},
                )
                yield unique

        self.logger.info(
            "ORKL transform complete", {"reports_produced": reports_produced}
        )

    # ------------------------------------------------------------------
    # Conversion
    # ------------------------------------------------------------------

    def _convert_entry(self, entry: OrklLibraryEntry) -> list[BaseIdentifiedEntity]:
        """Return every object to bundle for one entry; the Report is first.

        Actors, tools and ``uses`` relationships follow the report and are also
        referenced from ``Report.objects``. An empty list is the right answer
        for an entry that yields nothing usable.
        """
        actors: list[BaseIdentifiedEntity] = []
        actor_pairs: list[tuple[BaseIdentifiedEntity, OrklThreatActor]] = []
        for raw_actor in entry.threat_actors:
            actor = self._build_actor(raw_actor)
            if actor is None:
                continue
            actors.append(actor)
            actor_pairs.append((actor, raw_actor))

        tools: list[BaseIdentifiedEntity] = []
        relationships: list[BaseIdentifiedEntity] = []
        if self._ingest_tools:
            tools, relationships = self._build_tools_and_relationships(actor_pairs)

        report_objects = _dedupe_by_id([*actors, *tools, *relationships])
        report = self._build_report(entry, report_objects)
        return [report, *actors, *tools, *relationships]

    # --- Report ---

    def _build_report(
        self, entry: OrklLibraryEntry, objects: list[BaseIdentifiedEntity]
    ) -> Report:
        return Report(
            name=entry.name,
            description=entry.description,
            publication_date=self._resolve_publication_date(entry),
            labels=entry.labels or None,
            objects=objects or None,
            external_references=self._build_report_references(entry) or None,
            author=ORKL_AUTHOR,
            markings=[self._marking],
        )

    def _resolve_publication_date(self, entry: OrklLibraryEntry) -> datetime:
        """Return a required, tz-aware, deterministic ``publication_date``.

        It feeds the Report's deterministic id, so every branch must yield the
        same value for the same entry.
        """
        # Real candidates first (ISO dates, then their ``ts_*`` Unix-epoch
        # encodings); only when all are unusable does the fixed sentinel apply,
        # keeping the id stable rather than duplicating the Report on every sync.
        #
        # Update timestamps (``updated_at`` / ``ts_updated_at``) are deliberately
        # excluded: the incremental cursor re-fetches an entry *precisely because*
        # its ``updated_at`` changed, so deriving the id from an update timestamp
        # would mint a brand-new id on every re-fetch and duplicate the Report
        # instead of updating it. Do not re-add them.
        candidates = (
            # ``entry.publication_date`` already covers file_creation_date/created_at.
            entry.publication_date,
            _usable_datetime(_parse_iso8601(entry.file_modification_date)),
            _datetime_from_epoch(entry.ts_creation_date),
            _datetime_from_epoch(entry.ts_modification_date),
            _datetime_from_epoch(entry.ts_created_at),
        )
        for candidate in candidates:
            if candidate is not None:
                return candidate
        # The 1970 date is itself the visible warning that no usable date exists.
        return _ID_STABILITY_SENTINEL_DATE

    def _build_report_references(
        self, entry: OrklLibraryEntry
    ) -> list[ExternalReference]:
        references: list[ExternalReference] = []

        # 1. The ORKL entry itself. The ORKL single-page app returns HTTP 200
        # for any path, so no frontend permalink could be verified; the API URL
        # is used deliberately.
        references.append(
            ExternalReference(
                source_name="ORKL",
                external_id=entry.id,
                url=f"{self._api_base_url}/library/entry/{entry.id}",
            )
        )

        # 2. The SHA1 of the source file.
        if entry.sha1_hash:
            references.append(
                ExternalReference(
                    source_name="ORKL",
                    external_id=entry.sha1_hash,
                    description="SHA-1 hash of the source report file.",
                )
            )

        # 3. The original publishers.
        for url in entry.references:
            if not _is_usable_url(url):
                continue
            references.append(
                ExternalReference(
                    source_name=_reference_source_name(url),
                    url=url,
                )
            )

        # 4. The ORKL archive links (links only, never downloaded).
        if entry.files is not None:
            for url, description in (
                (entry.files.pdf, "ORKL archive copy of the report (PDF)."),
                (entry.files.text, "ORKL archive extracted plain text."),
                (entry.files.img, "ORKL archive preview image."),
            ):
                if url:
                    references.append(
                        ExternalReference(
                            source_name=_ARCHIVE_SOURCE_NAME,
                            url=url,
                            description=description,
                        )
                    )

        return references

    # --- Threat actors ---

    def _build_actor(self, actor: OrklThreatActor) -> BaseIdentifiedEntity | None:
        name = actor.main_name.strip() if actor.main_name else ""
        if not name:
            # `name` has min_length=1; an empty main_name would raise.
            return None

        # In OpenCTI, STIX `Threat-Actor` is abstract: the concrete type derives
        # from `resource_level` and defaults to Threat-Actor-Group. Emitting an
        # IntrusionSet or ThreatActorGroup gives a concrete, regenerable id; a
        # bare `threat-actor--...` id is one no concrete type reproduces, which
        # would orphan the entity. Do not "simplify" this to a generic actor.
        actor_class = (
            IntrusionSet if self._threat_actor_as_intrusion_set else ThreatActorGroup
        )
        # The external reference exists only to preserve the cross-source
        # identifier carried by `source_name` (e.g. ``MITRE:APT28``). When it is
        # absent the reference would carry a `source_name` but no `external_id`,
        # `url` or `description`, which satisfies the SDK's ExternalReference
        # model but violates STIX's at-least-one-property invariant and blows up
        # at bundle serialization (AtLeastOnePropertyError). With no identifier
        # to record, there is nothing to reference, so omit the reference.
        external_references = None
        if actor.source_name:
            external_references = [
                ExternalReference(
                    source_name=actor.source_id or "ORKL",
                    external_id=actor.source_name,
                )
            ]
        return actor_class(
            name=name,
            aliases=actor.other_aliases or None,
            author=ORKL_AUTHOR,
            markings=[self._marking],
            external_references=external_references,
        )

    # --- Tools ---

    def _build_tools_and_relationships(
        self,
        actor_pairs: list[tuple[BaseIdentifiedEntity, OrklThreatActor]],
    ) -> tuple[list[BaseIdentifiedEntity], list[BaseIdentifiedEntity]]:
        # Opt-in only: the ORKL feed mixes malware families (Remcos, PoisonIvy,
        # gh0st RAT, ...) into ``tools[]`` alongside genuine tools (PsExec,
        # Mimikatz, certutil), so enabling this creates Tool entities for what
        # are in fact malware.
        tools_by_name: dict[str, Tool] = {}
        tools: list[BaseIdentifiedEntity] = []
        relationships: list[BaseIdentifiedEntity] = []
        for actor_entity, raw_actor in actor_pairs:
            for raw_name in raw_actor.tools:
                name = raw_name.strip() if raw_name else ""
                if not name:
                    continue
                tool = tools_by_name.get(name)
                if tool is None:
                    tool = self._build_tool(name)
                    tools_by_name[name] = tool
                    tools.append(tool)
                relationships.append(self._build_uses(actor_entity, tool))
        return tools, relationships

    def _build_tool(self, name: str) -> Tool:
        return Tool(
            name=name,
            author=ORKL_AUTHOR,
            markings=[self._marking],
        )

    def _build_uses(
        self, source: BaseIdentifiedEntity, target: BaseIdentifiedEntity
    ) -> Relationship:
        return Relationship(
            type=RelationshipType.USES,
            source=source,
            target=target,
            author=ORKL_AUTHOR,
            markings=[self._marking],
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _resolve_cutoff(self) -> datetime:
        """Return the incremental-sync cutoff as a tz-aware datetime.

        Uses ``state.last_run`` when set (minus ``_CUTOFF_OVERLAP``), otherwise
        ``now(UTC) - import_start_date``. A naive ``last_run`` is treated as UTC
        so it can be compared against tz-aware entry timestamps.
        """
        last_run = self.state.last_run
        if last_run is not None:
            if last_run.tzinfo is None:
                last_run = last_run.replace(tzinfo=timezone.utc)
            # Overlap only on the last_run path (never the first-run
            # import_start_date path) so entries updated mid-run are re-scanned
            # instead of permanently missed. Safe because deterministic ids
            # update an entry in place rather than duplicating it.
            return last_run - _CUTOFF_OVERLAP
        return datetime.now(timezone.utc) - self._config.import_start_date

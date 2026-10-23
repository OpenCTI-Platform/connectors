"""ORKL report processor: collect library entries and convert them to STIX.

Owns both the sync strategy (full import, then new entries per ORKL library
version, with a periodic full re-import) and the ORKL -> STIX mapping, using the
SDK ``BaseDataProcessor`` contract. Every STIX object is built through
connectors-sdk models, which generate deterministic ids.
"""

from __future__ import annotations

from collections.abc import Generator
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import urlparse

from connectors_sdk import ApiClientError, ApiNotFoundError, BaseDataProcessor
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
from connectors_sdk.models.enums import RelationshipType, ReportType
from orkl.client_api import PAGE_SIZE, OrklClient
from orkl.models import (
    MIN_VALID_YEAR,
    OrklLibraryEntry,
    OrklThreatActor,
    parse_iso8601,
)
from orkl.settings import OrklConfig
from orkl.state import OrklState
from pydantic import ValidationError

# --- Constants ---

# Last-resort publication date. A Report's STIX id derives from
# ``PyctiReport.generate_id(name, published)``, so a non-deterministic fallback
# such as ``datetime.now(UTC)`` would mint a brand-new id on every conversion
# and silently duplicate the Report on each sync. A fixed 1970 sentinel keeps
# the id stable and is a visible signal that ORKL supplied no usable date.
_ID_STABILITY_SENTINEL_DATE = datetime(1970, 1, 1, tzinfo=timezone.utc)

# Module-level author reused across every emitted object; identity is stable so
# ``created_by_ref`` resolves to a single Identity in the produced bundle.
ORKL_AUTHOR = OrganizationAuthor(
    name="ORKL",
    description=(
        "ORKL is a community-driven library of publicly released cyber threat "
        "intelligence reports, sponsored by Sunet."
    ),
)

# Incremental sync: a few entries failing to fetch must not block the import of
# everything newer forever, but an ORKL outage must fail the run so the cursor
# stays put. The run fails when every fetch failed or when failures exceed this.
_MAX_FETCH_FAILURES = 10

_ARCHIVE_SOURCE_NAME = "ORKL Archive"
_REFERENCE_FALLBACK_SOURCE_NAME = "ORKL reference"


# --- Pure helpers ---


def _usable_datetime(value: datetime | None) -> datetime | None:
    """Return `value` only when it is a genuine date past the year sentinel."""
    if value is None or value.year < MIN_VALID_YEAR:
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


def _web_entry_url(api_base_url: str, entry_id: str) -> str:
    """Return the ORKL web permalink of an entry, on the API's scheme and host.

    The ORKL frontend is a single-page app whose router exposes a
    ``/libraryEntry/:entryId`` route; the host is taken from ``api_base_url``
    so a self-hosted ORKL mirror keeps consistent links.
    """
    parsed = urlparse(api_base_url)
    return f"{parsed.scheme}://{parsed.netloc}/libraryEntry/{entry_id}"


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

    Sync strategy (``collect()``):
        - first run, or when ``full_resync_period`` has elapsed since the last
          full import: walk the whole library (full sync);
        - otherwise: read the ORKL library versions created since the one stored
          in the state and fetch the entries they list (incremental sync).
        ORKL rewrites ``updated_at`` on every entry during its nightly rebuild,
        so a timestamp cursor cannot be used; the library version counter is the
        only reliable change signal, and it only records creations. Changes on
        existing entries (new actor tags, better titles) are therefore picked up
        by the periodic full sync only.

    The state fields (``last_library_version``, ``last_full_sync``) are written
    once ``collect()`` has yielded its last page; the SDK saves the state only
    when the whole run succeeded, so a failed run restarts from the previous
    cursor.

    transform() -> parse each dict, convert to STIX objects, yield one
        deduplicated bundle per page.
    """

    state: OrklState
    _config: OrklConfig
    _client: OrklClient
    _api_base_url: str
    _marking: TLPMarking
    _threat_actor_as_intrusion_set: bool
    _ingest_actor_aliases: bool
    _ingest_tools: bool

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def post_init(self) -> None:
        """Build the client and read conversion config once dependencies exist."""
        self._config = self.settings.orkl  # type: ignore[attr-defined]
        self._api_base_url = str(self._config.api_base_url).rstrip("/")
        self._client = OrklClient(base_url=self._api_base_url)
        self._marking = TLPMarking(level=self._config.tlp_level.value)
        self._threat_actor_as_intrusion_set = self._config.threat_actor_as_intrusion_set
        self._ingest_actor_aliases = self._config.ingest_actor_aliases
        self._ingest_tools = self._config.ingest_tools

    # ------------------------------------------------------------------
    # Pipeline
    # ------------------------------------------------------------------

    def collect(self) -> Generator[list[dict[str, Any]], None, None]:
        """Yield pages of raw entry dicts, from a full or an incremental sync.

        Deleted entries (``deleted_at`` set) are skipped in both modes. Pages
        with no surviving entry are not yielded.
        """
        current_version = self._client.get_library_version()
        last_version = self.state.last_library_version
        # ORKL sometimes rolls versions back and renumbers from there: a current
        # version lower than the stored one means the version log can no longer
        # be trusted to list what changed, so start over.
        rolled_back = last_version is not None and current_version < last_version
        full_sync = last_version is None or rolled_back or self._full_resync_due()

        if full_sync:
            if last_version is None:
                reason = "first run"
            elif rolled_back:
                reason = "library version rollback"
            else:
                reason = "periodic"
            self.work_name = f"ORKL full sync (library version {current_version})"
            self.logger.info(
                "Importing the whole ORKL library",
                meta={
                    "library_version": current_version,
                    "last_library_version": last_version,
                    "reason": reason,
                },
            )
            pages = self._client.iter_library_entries()
        else:
            self.work_name = (
                f"ORKL new entries (library versions {last_version + 1} to "
                f"{current_version})"
            )
            self.logger.info(
                "Importing ORKL entries created since the last run",
                meta={
                    "last_library_version": last_version,
                    "library_version": current_version,
                },
            )
            pages = self._iter_new_entries(since_version=last_version)

        pages_fetched = entries_seen = skipped_deleted = 0
        for page in pages:
            pages_fetched += 1
            surviving: list[dict[str, Any]] = []
            for raw in page:
                entries_seen += 1
                if raw.get("deleted_at") is not None:
                    skipped_deleted += 1
                    continue
                surviving.append(raw)
            if surviving:
                self.logger.info(
                    "Collected ORKL entries page",
                    meta={"page": pages_fetched, "entries": len(surviving)},
                )
                yield surviving

        self.logger.info(
            "ORKL collection complete",
            meta={
                "mode": "full" if full_sync else "incremental",
                "pages_fetched": pages_fetched,
                "entries_seen": entries_seen,
                "skipped_deleted": skipped_deleted,
            },
        )
        # Only reached when every page was consumed, i.e. sent: the SDK persists
        # the state at the end of a successful run.
        self.state.last_library_version = current_version
        if full_sync:
            self.state.last_full_sync = datetime.now(timezone.utc)

    def _full_resync_due(self) -> bool:
        """True when the periodic full re-import is enabled and overdue."""
        period = self._config.full_resync_period
        if period <= timedelta(0):
            return False
        last_full_sync = self.state.last_full_sync
        if last_full_sync is None:
            return True
        if last_full_sync.tzinfo is None:
            last_full_sync = last_full_sync.replace(tzinfo=timezone.utc)
        return datetime.now(timezone.utc) - last_full_sync >= period

    def _iter_new_entries(
        self, *, since_version: int
    ) -> Generator[list[dict[str, Any]], None, None]:
        """Fetch the entries created in the library versions after ``since_version``.

        Entries are fetched one by one (the version log only carries ids) and
        yielded in pages of ``PAGE_SIZE``. An entry that ORKL no longer serves
        (HTTP 404) is skipped silently with a warning: it was created and removed
        between two runs. Any other API error on one entry is skipped too, so a
        single broken entry cannot block the import of everything newer forever;
        the run still fails when every fetch failed or when more than
        ``_MAX_FETCH_FAILURES`` did, which is an ORKL outage rather than bad data.

        Raises:
            ApiClientError: Too many entries could not be fetched.
        """
        seen: set[str] = set()
        page: list[dict[str, Any]] = []
        attempted = failures = 0
        for version in self._client.iter_library_versions_since(since_version):
            for ref in version.get("created_library_entries") or []:
                entry_id = ref.get("id") if isinstance(ref, dict) else None
                if not entry_id or entry_id in seen:
                    continue
                seen.add(entry_id)
                attempted += 1
                try:
                    raw = self._client.get_library_entry(entry_id)
                except ApiNotFoundError:
                    self.logger.warning(
                        "ORKL entry listed in a library version no longer exists",
                        meta={
                            "entry_id": entry_id,
                            "library_version": version.get("ID"),
                        },
                    )
                    continue
                except ApiClientError as err:
                    failures += 1
                    self.logger.warning(
                        "Skipping ORKL entry: failed to fetch",
                        meta={
                            "entry_id": entry_id,
                            "library_version": version.get("ID"),
                            "error": str(err),
                        },
                    )
                    continue
                if not raw:
                    continue
                page.append(raw)
                if len(page) >= PAGE_SIZE:
                    yield page
                    page = []
        if failures and (failures == attempted or failures > _MAX_FETCH_FAILURES):
            raise ApiClientError(
                f"ORKL incremental sync: {failures} of {attempted} entries could "
                "not be fetched; not advancing the library version cursor"
            )
        if page:
            yield page

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
                    self.logger.warning(
                        "Skipping ORKL entry: failed to parse",
                        meta={"entry_id": raw.get("id"), "error": str(err)},
                    )
                    continue

                try:
                    objects = self._convert_entry(entry)
                except Exception as err:  # noqa: BLE001
                    self.logger.warning(
                        "Skipping ORKL entry: failed to convert to STIX",
                        meta={"entry_id": entry.id, "error": str(err)},
                    )
                    continue

                stix_objects.extend(objects)

            if stix_objects:
                unique = _dedupe_by_id(stix_objects)
                page_reports = sum(1 for obj in unique if isinstance(obj, Report))
                reports_produced += page_reports
                self.logger.info(
                    "Sending STIX objects for page",
                    meta={"objects": len(unique), "reports": page_reports},
                )
                yield unique

        self.logger.info(
            "ORKL transform complete", meta={"reports_produced": reports_produced}
        )

    # ------------------------------------------------------------------
    # Conversion
    # ------------------------------------------------------------------

    def _convert_entry(self, entry: OrklLibraryEntry) -> list[BaseIdentifiedEntity]:
        """Return every object to bundle for one entry.

        The author and TLP marking come first, then the Report, then the actors,
        tools and ``uses`` relationships that are also referenced from
        ``Report.objects``.
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
        # The SDK serialises only the objects it is given, so the author and
        # marking must be in the bundle or their refs dangle. They stay out of
        # ``report_objects`` so they do not land in the Report's ``object_refs``.
        return [ORKL_AUTHOR, self._marking, report, *actors, *tools, *relationships]

    # --- Report ---

    def _build_report(
        self, entry: OrklLibraryEntry, objects: list[BaseIdentifiedEntity]
    ) -> Report:
        return Report(
            name=entry.name,
            description=entry.description,
            publication_date=self._resolve_publication_date(entry),
            report_types=[ReportType.THREAT_REPORT],
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
        # excluded: ORKL rewrites ``updated_at`` on every entry during its
        # nightly rebuild, so deriving the id from it would mint a new Report id
        # on each re-sync and duplicate the Report. Do not re-add them.
        candidates = (
            # ``entry.publication_date`` already covers file_creation_date/created_at.
            entry.publication_date,
            _usable_datetime(parse_iso8601(entry.file_modification_date)),
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

        # 1. The ORKL entry itself, as the analyst-facing web page (the API
        # record stays reachable through `external_id`).
        references.append(
            ExternalReference(
                source_name="ORKL",
                external_id=entry.id,
                url=_web_entry_url(self._api_base_url, entry.id),
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
        # The reference only preserves the cross-source identifier in the actor's
        # `source_name` (e.g. ``MITRE:APT28``); without it the reference would
        # have no `external_id`, `url` or `description` and fail STIX serialization.
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
            aliases=(
                (actor.other_aliases or None) if self._ingest_actor_aliases else None
            ),
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

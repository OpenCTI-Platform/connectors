"""Pure ORKL -> STIX mapping layer.

This module converts parsed :class:`~orkl.models.OrklLibraryEntry` objects into
connectors-sdk model instances. It performs no I/O: no HTTP calls, no state, no
``OpenCTIConnectorHelper``. Deciding whether to skip deleted entries or apply a
date cutoff is the processor's job, not this module's.

Every emitted STIX object is built through connectors-sdk models, which derive
deterministic ids via pycti. The stix2 constructors are never called directly,
so the repository's custom STIX-id pylint plugin stays satisfied.

Known caveats, deliberately accepted:

* Tools vs malware. The ORKL feed does not distinguish malware from tools: an
  actor's ``tools[]`` mixes genuine tools (PsExec, Mimikatz, certutil) with
  malware families (Remcos, PoisonIvy, gh0st RAT, GraphSteel, GrimPlant).
  Emitting ``Tool`` entities for these is therefore opt-in and disabled by
  default (see ``ingest_tools``).

* Duplicate actors. One entry frequently carries the same real-world actor
  several times under different ``main_name``s from different sources, e.g.
  ``SaintBear`` (MISPGALAXY), ``Ember Bear`` (MITRE), ``Saint Bear`` (MITRE)
  and ``SaintBear`` (ETDA), all listing ``UAC-0056`` among their aliases. This
  produces several distinct entities from a single report. The decision is to
  emit them as-is and let OpenCTI's own deduplication and the analyst handle
  the merge, rather than attempt fuzzy merging here.
"""

from __future__ import annotations

from datetime import datetime, timezone
from urllib.parse import urlparse

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
from orkl.models import OrklLibraryEntry, OrklThreatActor, _parse_iso8601

# Any parsed date before this year is the API's "no known date" sentinel and is
# treated as unusable (mirrors ``orkl.models._MIN_VALID_YEAR``).
_MIN_VALID_YEAR = 1970

# Last-resort publication date. The SDK derives a Report's STIX id from
# ``PyctiReport.generate_id(name, published)``, so a non-deterministic fallback
# such as ``datetime.now(UTC)`` would mint a brand-new id on every conversion
# and silently duplicate the Report on each sync. A fixed sentinel keeps the id
# stable, and a Report dated 1970 is a visible signal that ORKL supplied no
# usable date - preferable to silent duplication.
_ID_STABILITY_SENTINEL_DATE = datetime(1970, 1, 1, tzinfo=timezone.utc)


def _usable_datetime(value: datetime | None) -> datetime | None:
    """Return `value` only when it is a genuine date past the year-1 sentinel."""
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


# Module-level author reused across every emitted object; identity is stable so
# `created_by_ref` resolves to a single Identity in the produced bundle.
ORKL_AUTHOR = OrganizationAuthor(
    name="ORKL",
    description=(
        "ORKL is a community-driven library of publicly released cyber threat "
        "intelligence reports, sponsored by Sunet."
    ),
)

_ARCHIVE_SOURCE_NAME = "ORKL Archive"
_REFERENCE_FALLBACK_SOURCE_NAME = "ORKL reference"


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


def _dedupe_by_id(objects: list[BaseIdentifiedEntity]) -> list[BaseIdentifiedEntity]:
    """Return objects with duplicate STIX ids removed, order preserved.

    Duplicate ids arise legitimately: two actors sharing a `main_name`
    (e.g. two ``SaintBear`` entries from different sources) regenerate the
    same deterministic id. `object_refs` should reference each id once.
    """
    seen: set[str] = set()
    unique: list[BaseIdentifiedEntity] = []
    for obj in objects:
        if obj.id in seen:
            continue
        seen.add(obj.id)
        unique.append(obj)
    return unique


class OrklConverter:
    """Convert ORKL library entries into connectors-sdk STIX model instances."""

    def __init__(
        self,
        *,
        api_base_url: str,
        tlp_level: str,
        threat_actor_as_intrusion_set: bool = True,
        ingest_tools: bool = False,
    ) -> None:
        self._api_base_url = api_base_url.rstrip("/")
        self._marking = TLPMarking(level=tlp_level)
        self._threat_actor_as_intrusion_set = threat_actor_as_intrusion_set
        self._ingest_tools = ingest_tools

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def convert_entry(self, entry: OrklLibraryEntry) -> list[BaseIdentifiedEntity]:
        """Return every object to bundle for one entry; the Report is first.

        Returns actors, tools and ``uses`` relationships after the report, all
        of them also referenced from ``Report.objects``. An empty list is the
        right answer for an entry that yields nothing usable.
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

    # ------------------------------------------------------------------
    # Report
    # ------------------------------------------------------------------

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
        """Return a `publication_date` that is required, tz-aware and stable.

        `publication_date` feeds the Report's deterministic id, so every branch
        must yield the same value for the same entry. Real candidates are tried
        first (ISO dates, then their `ts_*` Unix-epoch encodings); only when all
        are unusable does the fixed `_ID_STABILITY_SENTINEL_DATE` apply, which
        keeps the id stable rather than duplicating the Report on every sync.

        Update timestamps (`updated_at` / `ts_updated_at`) are deliberately
        excluded from this chain. The incremental cursor re-fetches an entry
        *precisely because* its `updated_at` changed, so deriving the id from an
        update timestamp would mint a brand-new id on every re-fetch and create
        a duplicate Report instead of updating the existing one - exactly the
        failure `_ID_STABILITY_SENTINEL_DATE` exists to avoid. Do not re-add
        them.
        """
        candidates = (
            # `entry.publication_date` already covers file_creation_date/created_at.
            entry.publication_date,
            _usable_datetime(_parse_iso8601(entry.file_modification_date)),
            _datetime_from_epoch(entry.ts_creation_date),
            _datetime_from_epoch(entry.ts_modification_date),
            _datetime_from_epoch(entry.ts_created_at),
        )
        for candidate in candidates:
            if candidate is not None:
                return candidate
        # This module is deliberately I/O-free and has no logger; the 1970 date
        # is itself the visible warning that no usable date was supplied.
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

    # ------------------------------------------------------------------
    # Threat actors
    # ------------------------------------------------------------------

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
        # absent the reference would carry a `source_name` but no
        # `external_id`, `url` or `description`, which satisfies the SDK's
        # ExternalReference model but violates STIX's at-least-one-property
        # invariant and blows up at bundle serialization
        # (AtLeastOnePropertyError). With no identifier to record, there is
        # nothing to reference, so omit the reference entirely.
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

    # ------------------------------------------------------------------
    # Tools
    # ------------------------------------------------------------------

    def _build_tools_and_relationships(
        self,
        actor_pairs: list[tuple[BaseIdentifiedEntity, OrklThreatActor]],
    ) -> tuple[list[BaseIdentifiedEntity], list[BaseIdentifiedEntity]]:
        # Opt-in only: the ORKL feed mixes malware families into `tools[]`, so
        # enabling this creates Tool entities for what are in fact malware.
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

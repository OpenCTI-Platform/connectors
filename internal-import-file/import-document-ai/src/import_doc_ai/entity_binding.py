"""Bind the entities extracted from a document to the entities OpenCTI knows.

The extraction names an entity the way the document spells it ("Clop",
"Graceful Spider", "USA") and derives its STIX id from that spelling: sent as
is, an entity the platform knows under another name or alias is created again
(OpenCTI-Platform/opencti#14997). Each named entity of the extracted bundle is
therefore looked up with the ``curationResolve`` query of the platform first.
A match binds the extracted object to the existing entity: it takes the
entity's standard id and canonical name, keeps the spelling of the document as
an alias, and every reference to its former id follows.

The lookups run with the permissions of the user who triggered the import, in
the draft the import targets, are sent in batches of names per request, are
cached and bounded per document, and never block the import: a platform that
does not expose ``curationResolve`` is detected on the first request and the
binding is skipped for the lifetime of the process, and any other failure
leaves the entities as extracted.
"""

import enum
import functools
import json
import re
import threading
import time
import uuid
from collections import OrderedDict
from collections.abc import Callable, Hashable, Iterable
from dataclasses import dataclass, field

import stix2
from import_doc_ai.util import (
    merge_duplicate_objects,
    merge_rewritten_relationships,
    remap_references_in_bundle,
    remove_objects_from_bundle,
    stix_object_to_dict,
)
from pycti import OpenCTIConnectorHelper

_RESOLUTION_SELECTION = (
    "entity_id standard_id entity_type name match_type score matched_value"
)

MAX_LOOKUPS_PER_DOCUMENT = 500
LOOKUPS_PER_REQUEST = 20
MAX_CONSECUTIVE_FAILED_REQUESTS = 3
RESOLUTION_CACHE_SIZE = 1024
RESOLUTION_CACHE_TTL_SECONDS = 600.0

# OpenCTI rejects names shorter than 2 characters, and a longer text than this
# is a sentence the extraction mistook for a name.
_MIN_NAME_LENGTH = 2
_MAX_NAME_LENGTH = 256
_MAX_ERROR_LENGTH = 500

_SINGLE_ENTITY_TYPES = {
    "attack-pattern": "Attack-Pattern",
    "campaign": "Campaign",
    "channel": "Channel",
    "course-of-action": "Course-Of-Action",
    "event": "Event",
    "infrastructure": "Infrastructure",
    "intrusion-set": "Intrusion-Set",
    "malware": "Malware",
    "narrative": "Narrative",
    "tool": "Tool",
    "vulnerability": "Vulnerability",
}
_IDENTITY_TYPES_BY_CLASS = {
    "class": "Sector",
    "individual": "Individual",
    "organization": "Organization",
    "system": "System",
}
_IDENTITY_TYPES = frozenset(_IDENTITY_TYPES_BY_CLASS.values())
_LOCATION_TYPES = frozenset({"Administrative-Area", "City", "Country", "Region"})
_THREAT_ACTOR_TYPES = frozenset({"Threat-Actor-Group", "Threat-Actor-Individual"})
# The OpenCTI types storing their aliases in x_opencti_aliases, the others in
# aliases (opencti-graphql resolveAliasesField).
_X_OPENCTI_ALIASES_TYPES = frozenset(
    {"Course-Of-Action", "Vulnerability", *_IDENTITY_TYPES, *_LOCATION_TYPES}
)
# When a document names more entities than the lookup budget, the threat
# entities are looked up first.
_LOOKUP_PRIORITY = {
    stix_type: rank
    for rank, stix_type in enumerate(
        (
            "intrusion-set",
            "threat-actor",
            "campaign",
            "malware",
            "tool",
            "channel",
            "attack-pattern",
            "vulnerability",
            "infrastructure",
            "narrative",
            "event",
            "course-of-action",
            "identity",
            "location",
        )
    )
}

_SCHEMA_ERROR_CODE = "GRAPHQL_VALIDATION_FAILED"
_UNKNOWN_QUERY_MESSAGE = 'Cannot query field "curationResolve"'
_STIX_TYPE_RE = re.compile(r"[a-z][a-z0-9-]*[a-z0-9]")


@functools.lru_cache(maxsize=LOOKUPS_PER_REQUEST)
def curation_resolve_query(size: int) -> str:
    """The query resolving ``size`` names in one request.

    Name ``i`` is sent in the variables ``name<i>`` and ``type<i>``, and
    answered by the aliased field ``resolve<i>``.

    Args:
        size (int): The number of names the request resolves, at least 1.

    Returns:
        (str): The GraphQL query.
    """
    if size < 1:
        raise ValueError("A curationResolve request resolves at least one name")
    variables = ", ".join(
        f"$name{index}: String!, $type{index}: String!" for index in range(size)
    )
    fields = "".join(
        f"\n  resolve{index}: curationResolve(name: $name{index}, type: $type{index})"
        f" {{ {_RESOLUTION_SELECTION} }}"
        for index in range(size)
    )
    return f"query CurationResolve({variables}) {{{fields}\n}}"


def is_stix_id(value: object) -> bool:
    """Whether a value is a STIX identifier: ``<type>--<UUID>``, in canonical form.

    Args:
        value (object): The value to check.

    Returns:
        (bool): True for an identifier such as
            ``malware--e5fd2b5f-3ae4-5b44-8a46-0a24c7f2e2f1``.

    Examples:
        >>> is_stix_id("malware--e5fd2b5f-3ae4-5b44-8a46-0a24c7f2e2f1")
        True
        >>> is_stix_id("malware--invalid")
        False
    """
    if not isinstance(value, str):
        return False
    stix_type, separator, identifier = value.partition("--")
    if not separator or not _STIX_TYPE_RE.fullmatch(stix_type):
        return False
    try:
        return str(uuid.UUID(identifier)) == identifier
    except ValueError:
        return False


def resolve_entity_type(stix_object: stix2.v21._STIXBase21 | dict) -> str | None:
    """The OpenCTI entity type an extracted STIX object is imported as.

    Args:
        stix_object (stix2.v21._STIXBase21 | dict): The extracted STIX object.

    Returns:
        (str | None): The OpenCTI entity type (``Intrusion-Set``, ``Country``,
            ``Sector``...), or None for an object that is not a named entity
            OpenCTI can hold aliases for, or whose exact type is unknown (a
            location without a location type).

    Examples:
        >>> import pycti
        >>> import stix2
        >>> sector = stix2.Identity(
        ...     id=pycti.Identity.generate_id("Energy", "class"),
        ...     name="Energy",
        ...     identity_class="class",
        ... )
        >>> resolve_entity_type(sector)
        'Sector'
    """
    stix_type = stix_object.get("type")
    if stix_type in _SINGLE_ENTITY_TYPES:
        return _SINGLE_ENTITY_TYPES[stix_type]
    declared_type = stix_object.get(
        "x_opencti_type"
    ) or OpenCTIConnectorHelper.get_attribute_in_extension("type", stix_object)
    if stix_type == "identity":
        if declared_type:
            return declared_type if declared_type in _IDENTITY_TYPES else None
        identity_class = str(stix_object.get("identity_class", "")).lower()
        return _IDENTITY_TYPES_BY_CLASS.get(identity_class)
    if stix_type == "location":
        location_type = stix_object.get("x_opencti_location_type") or declared_type
        return location_type if location_type in _LOCATION_TYPES else None
    if stix_type == "threat-actor":
        if declared_type:
            return declared_type if declared_type in _THREAT_ACTOR_TYPES else None
        if str(stix_object.get("resource_level", "")).lower() == "individual":
            return "Threat-Actor-Individual"
        return "Threat-Actor-Group"
    return None


def _clean_name(name: object) -> str | None:
    if not isinstance(name, str):
        return None
    cleaned = " ".join(name.split())
    if not _MIN_NAME_LENGTH <= len(cleaned) <= _MAX_NAME_LENGTH:
        return None
    return cleaned


def _name_key(name: str) -> str:
    return " ".join(name.split()).casefold()


@dataclass(frozen=True)
class _Candidate:
    """An extracted named entity to look up."""

    stix_type: str
    entity_type: str
    name: str

    @property
    def key(self) -> tuple[str, str]:
        return self.entity_type, _name_key(self.name)

    @property
    def alias_property(self) -> str:
        if self.entity_type in _X_OPENCTI_ALIASES_TYPES:
            return "x_opencti_aliases"
        return "aliases"


def _candidate(stix_object: stix2.v21._STIXBase21 | dict) -> _Candidate | None:
    # An attack pattern holding a MITRE ATT&CK id is reunified by that id, a
    # name lookup could only contradict it.
    if stix_object.get("type") == "attack-pattern" and stix_object.get("x_mitre_id"):
        return None
    entity_type = resolve_entity_type(stix_object)
    name = _clean_name(stix_object.get("name"))
    if entity_type is None or name is None:
        return None
    return _Candidate(stix_object["type"], entity_type, name)


@dataclass(frozen=True)
class EntityResolution:
    """The existing OpenCTI entity ``curationResolve`` matched a name to."""

    entity_id: str
    standard_id: str
    entity_type: str
    name: str
    match_type: str
    score: float
    matched_value: str

    @classmethod
    def from_payload(cls, payload: object) -> "EntityResolution":
        """Read a ``CurationResolution`` returned by the platform.

        Args:
            payload (object): The ``curationResolve`` field of the response.

        Returns:
            (EntityResolution): The resolution.

        Raises:
            ValueError: When the payload is not a usable resolution.
        """
        if not isinstance(payload, dict):
            raise ValueError(f"expected an object, got {type(payload).__name__}")
        standard_id = payload.get("standard_id")
        entity_type = payload.get("entity_type")
        name = payload.get("name")
        if not is_stix_id(standard_id):
            raise ValueError(f"invalid standard_id {standard_id!r}")
        if not (
            isinstance(entity_type, str)
            and entity_type
            and isinstance(name, str)
            and name.strip()
        ):
            raise ValueError("missing entity_type or name")
        score = payload.get("score")
        matched_value = payload.get("matched_value")
        return cls(
            entity_id=str(payload.get("entity_id") or ""),
            standard_id=standard_id,
            entity_type=entity_type,
            name=name,
            match_type=str(payload.get("match_type") or ""),
            score=float(score) if isinstance(score, (int, float)) else 0.0,
            matched_value=matched_value if isinstance(matched_value, str) else name,
        )

    def is_of_type(self, candidate: _Candidate) -> bool:
        """Whether the resolved entity has the type of the extracted object."""
        return (
            self.entity_type.casefold() == candidate.entity_type.casefold()
            and self.standard_id.split("--", 1)[0] == candidate.stix_type
        )


@dataclass(frozen=True)
class EntityBinding:
    """An extracted object bound to an existing OpenCTI entity."""

    entity_type: str
    extracted_id: str
    extracted_name: str
    bound_id: str
    bound_name: str
    match_type: str
    score: float
    alias_added: bool


@dataclass
class BindingSummary:
    """What binding the entities of a bundle did.

    ``lookups`` counts the names sent to the platform, ``requests`` the
    requests that carried them. ``unresolved_names`` counts the distinct
    names that were not looked up: the document named more entities than the
    lookup budget, too many requests failed in a row, or the platform does
    not expose ``curationResolve``.
    """

    bindings: list[EntityBinding] = field(default_factory=list)
    lookups: int = 0
    requests: int = 0
    cache_hits: int = 0
    failed_lookups: int = 0
    rejected_resolutions: int = 0
    unresolved_names: int = 0
    merged_objects: int = 0
    dropped_relationships: int = 0


class ResolutionCache:
    """A bounded, thread-safe LRU cache of resolutions that expire.

    A miss (``None``) is cached like a match: the platform answered that no
    entity matches the name.
    """

    def __init__(
        self,
        max_size: int = RESOLUTION_CACHE_SIZE,
        ttl_seconds: float = RESOLUTION_CACHE_TTL_SECONDS,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._max_size = max_size
        self._ttl_seconds = ttl_seconds
        self._clock = clock
        self._entries: OrderedDict[Hashable, tuple[float, EntityResolution | None]] = (
            OrderedDict()
        )
        self._lock = threading.Lock()

    def __len__(self) -> int:
        with self._lock:
            return len(self._entries)

    def get(self, key: Hashable) -> tuple[bool, EntityResolution | None]:
        """Return whether ``key`` is cached, and its resolution."""
        with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                return False, None
            stored_at, resolution = entry
            if self._clock() - stored_at >= self._ttl_seconds:
                del self._entries[key]
                return False, None
            self._entries.move_to_end(key)
            return True, resolution

    def put(self, key: Hashable, resolution: EntityResolution | None) -> None:
        """Cache the resolution of ``key``, evicting the least recently used."""
        with self._lock:
            self._entries[key] = (self._clock(), resolution)
            self._entries.move_to_end(key)
            while len(self._entries) > self._max_size:
                self._entries.popitem(last=False)


def _graphql_errors(error: Exception) -> list[dict]:
    """The GraphQL errors carried by an exception pycti raised.

    pycti raises a ``ValueError`` holding a dict (``name``, ``error_message``)
    for a GraphQL error answered with HTTP 200, as OpenCTI does, and holding
    the response text for any other HTTP status.
    """
    if not isinstance(error, ValueError) or not error.args:
        return []
    detail = error.args[0]
    if isinstance(detail, dict):
        return [detail]
    if not isinstance(detail, str):
        return []
    try:
        payload = json.loads(detail)
    except ValueError:
        return []
    errors = payload.get("errors") if isinstance(payload, dict) else None
    if not isinstance(errors, list):
        return []
    return [
        graphql_error for graphql_error in errors if isinstance(graphql_error, dict)
    ]


def is_schema_error(error: Exception) -> bool:
    """Whether a failed query was rejected by the GraphQL schema of the platform.

    A platform without ``curationResolve`` fails the validation of the query
    (``Cannot query field "curationResolve" on type "Query"``) whatever the
    name looked up: the binding can never work against it.

    Args:
        error (Exception): The exception the query raised.

    Returns:
        (bool): True for a schema validation error, False for any other
            failure (network, HTTP status, permission, invalid value...).
    """
    for graphql_error in _graphql_errors(error):
        extensions = graphql_error.get("extensions")
        code = graphql_error.get("name") or (
            extensions.get("code") if isinstance(extensions, dict) else None
        )
        message = str(
            graphql_error.get("error_message") or graphql_error.get("message") or ""
        )
        if code == _SCHEMA_ERROR_CODE or _UNKNOWN_QUERY_MESSAGE in message:
            return True
    return False


class _LookupStatus(enum.Enum):
    ANSWERED = "answered"
    UNSUPPORTED = "unsupported"
    FAILED = "failed"


@dataclass(frozen=True)
class _LookupResult:
    status: _LookupStatus
    resolution: EntityResolution | None = None
    error: str | None = None


@dataclass(frozen=True)
class _RequestResult:
    """What a request answered: its status, and one result per name it carried."""

    status: _LookupStatus
    results: tuple[_LookupResult, ...] = ()
    error: str | None = None


def _describe(error: Exception) -> str:
    return f"{type(error).__name__}: {error}"[:_MAX_ERROR_LENGTH]


def _read_resolution(data: dict, field_name: str) -> _LookupResult:
    """Read the answer to one name from the ``data`` of a batched response."""
    if field_name not in data:
        return _LookupResult(
            _LookupStatus.FAILED,
            error=f"unexpected response: no {field_name} data",
        )
    payload = data[field_name]
    if payload is None:
        return _LookupResult(_LookupStatus.ANSWERED)
    try:
        resolution = EntityResolution.from_payload(payload)
    except ValueError as error:
        return _LookupResult(
            _LookupStatus.FAILED,
            error=f"unexpected curationResolve result: {error}"[:_MAX_ERROR_LENGTH],
        )
    return _LookupResult(_LookupStatus.ANSWERED, resolution)


def _bind_object(
    stix_object: stix2.v21._STIXBase21 | dict,
    candidate: _Candidate,
    resolution: EntityResolution,
    known_names: set[str],
) -> tuple[stix2.v21._STIXBase21 | dict, bool]:
    """Turn an extracted object into the existing entity it names.

    The object takes the standard id and the canonical name of the entity,
    and keeps the spelling of the document as an alias unless the entity
    already holds it: its name, the alias ``curationResolve`` matched, or a
    name another object bound to the same entity brings. Every other property
    is kept as extracted.

    Args:
        stix_object (stix2.v21._STIXBase21 | dict): The extracted object.
        candidate (_Candidate): What was looked up for it.
        resolution (EntityResolution): The entity it names.
        known_names (set[str]): The name keys the entity holds or is given by
            the objects of the bundle bound to it so far, updated with the
            names this object brings.

    Returns:
        (tuple[stix2.v21._STIXBase21 | dict, bool]): The bound object
            (``stix_object`` itself when binding changes nothing) and whether
            an alias was added.
    """
    extracted = stix_object_to_dict(stix_object)
    bound = dict(extracted)
    bound["id"] = resolution.standard_id
    bound["name"] = resolution.name
    known_names.update(
        {_name_key(resolution.name), _name_key(resolution.matched_value)}
    )
    aliases = []
    for alias in extracted.get(candidate.alias_property) or []:
        if isinstance(alias, str) and alias.strip():
            alias_key = _name_key(alias)
            if alias_key not in known_names:
                known_names.add(alias_key)
                aliases.append(alias)
    alias_added = _name_key(candidate.name) not in known_names
    if alias_added:
        known_names.add(_name_key(candidate.name))
        aliases.append(candidate.name)
    if aliases:
        bound[candidate.alias_property] = aliases
    else:
        bound.pop(candidate.alias_property, None)
    if bound == extracted:
        return stix_object, False
    return stix2.parse(bound, allow_custom=True), alias_added


class ExistingEntityBinder:
    """Bind the named entities of extracted bundles to existing OpenCTI entities.

    One binder serves every document the connector imports: it remembers
    whether the platform exposes ``curationResolve`` and caches the
    resolutions across documents, per user and draft, for a few minutes.
    """

    def __init__(
        self,
        helper: OpenCTIConnectorHelper,
        enabled: bool = True,
        max_lookups_per_document: int = MAX_LOOKUPS_PER_DOCUMENT,
        lookups_per_request: int = LOOKUPS_PER_REQUEST,
        cache: ResolutionCache | None = None,
    ) -> None:
        """Initialize the binder.

        Args:
            helper (OpenCTIConnectorHelper): The connector helper; lookups go
                through its impersonating API client, so that they only see
                what the user who triggered the import can see.
            enabled (bool): Whether to bind at all.
            max_lookups_per_document (int): The most names a single document
                may look up.
            lookups_per_request (int): The most names a single request looks
                up, between 1 and ``LOOKUPS_PER_REQUEST``.
            cache (ResolutionCache | None): The cross-document cache
                (a new one by default).
        """
        if not 1 <= lookups_per_request <= LOOKUPS_PER_REQUEST:
            raise ValueError(
                f"lookups_per_request must be between 1 and {LOOKUPS_PER_REQUEST}"
            )
        self._helper = helper
        self._enabled = enabled
        self._platform_supported = True
        self._max_lookups_per_document = max_lookups_per_document
        self._lookups_per_request = lookups_per_request
        self._cache = cache if cache is not None else ResolutionCache()

    @property
    def active(self) -> bool:
        """Whether bundles are bound: enabled, and supported by the platform."""
        return self._enabled and self._platform_supported

    def bind(self, bundle: stix2.Bundle) -> tuple[stix2.Bundle, BindingSummary]:
        """Bind the named entities of a bundle to the existing OpenCTI entities.

        Each extracted intrusion set, threat actor, campaign, malware, tool,
        channel, attack pattern (without MITRE ATT&CK id), vulnerability,
        infrastructure, narrative, event, course of action, identity
        (organization, individual, sector, system) and location (country,
        region, city, administrative area) is looked up by name and type. A
        match of the same type binds the object (see ``_bind_object``), every
        reference to its former id is rewritten, the objects and relationships
        that end up identical are merged, and a relationship the binding turns
        into a self-loop is dropped. A name the platform resolves to nothing,
        or to an entity of another type, is left as extracted.

        Args:
            bundle (stix2.Bundle): The extracted STIX bundle.

        Returns:
            (tuple[stix2.Bundle, BindingSummary]): The bound bundle
                (``bundle`` itself when nothing is bound) and what changed.
        """
        summary = BindingSummary()
        if not self.active:
            return bundle, summary
        candidates = {}
        for stix_object in bundle.get("objects", []):
            candidate = _candidate(stix_object)
            if candidate is not None:
                candidates[stix_object["id"]] = candidate
        if not candidates:
            return bundle, summary
        resolutions = self._resolve(candidates.values(), summary)

        bound_objects = {}
        id_mapping = {}
        known_names_by_id: dict[str, set[str]] = {}
        for stix_object in bundle.get("objects", []):
            candidate = candidates.get(stix_object["id"])
            resolution = resolutions.get(candidate.key) if candidate else None
            if resolution is None:
                continue
            if not resolution.is_of_type(candidate):
                summary.rejected_resolutions += 1
                self._helper.connector_logger.warning(
                    "curationResolve matched an entity of another type, "
                    "importing the extracted entity as extracted",
                    {
                        "type": candidate.entity_type,
                        "name": candidate.name,
                        "resolved_type": resolution.entity_type,
                        "resolved_id": resolution.standard_id,
                    },
                )
                continue
            bound_object, alias_added = _bind_object(
                stix_object,
                candidate,
                resolution,
                known_names_by_id.setdefault(resolution.standard_id, set()),
            )
            summary.bindings.append(
                EntityBinding(
                    entity_type=candidate.entity_type,
                    extracted_id=stix_object["id"],
                    extracted_name=candidate.name,
                    bound_id=resolution.standard_id,
                    bound_name=resolution.name,
                    match_type=resolution.match_type,
                    score=resolution.score,
                    alias_added=alias_added,
                )
            )
            if bound_object is stix_object:
                continue
            bound_objects[stix_object["id"]] = bound_object
            if resolution.standard_id != stix_object["id"]:
                id_mapping[stix_object["id"]] = resolution.standard_id
        if not bound_objects:
            return bundle, summary
        return self._rewrite_bundle(bundle, bound_objects, id_mapping, summary), summary

    def _resolve(
        self, candidates: Iterable[_Candidate], summary: BindingSummary
    ) -> dict[tuple[str, str], EntityResolution]:
        """Look each distinct name up once, threat entities first."""
        pending: dict[tuple[str, str], _Candidate] = {}
        for candidate in sorted(
            candidates, key=lambda candidate: _LOOKUP_PRIORITY[candidate.stix_type]
        ):
            pending.setdefault(candidate.key, candidate)
        # The impersonating client sends the lookups as the user who triggered
        # the import and in the draft the import targets (pycti sets both per
        # message): a resolution only holds for that user in that draft.
        scope = (
            getattr(self._helper, "applicant_id", None),
            getattr(self._helper, "draft_id", None) or None,
        )
        resolutions = {}
        over_budget = 0
        to_look_up: list[tuple[tuple, _Candidate]] = []
        for key, candidate in pending.items():
            cache_key = (*scope, *key)
            cached, resolution = self._cache.get(cache_key)
            if cached:
                summary.cache_hits += 1
                if resolution is not None:
                    resolutions[key] = resolution
            elif not self._platform_supported:
                summary.unresolved_names += 1
            elif len(to_look_up) >= self._max_lookups_per_document:
                summary.unresolved_names += 1
                over_budget += 1
            else:
                to_look_up.append((cache_key, candidate))

        consecutive_failures = 0
        after_failures = 0
        for start in range(0, len(to_look_up), self._lookups_per_request):
            batch = to_look_up[start : start + self._lookups_per_request]
            if not self._platform_supported:
                summary.unresolved_names += len(batch)
                continue
            if consecutive_failures >= MAX_CONSECUTIVE_FAILED_REQUESTS:
                summary.unresolved_names += len(batch)
                after_failures += len(batch)
                continue
            summary.requests += 1
            summary.lookups += len(batch)
            answer = self._lookup([candidate for _, candidate in batch])
            if answer.status is _LookupStatus.UNSUPPORTED:
                self._platform_supported = False
                summary.unresolved_names += len(batch)
                self._helper.connector_logger.info(
                    "OpenCTI does not expose the curationResolve query, "
                    "extracted entities are imported as extracted",
                    {"error": answer.error},
                )
                continue
            if answer.status is _LookupStatus.FAILED:
                consecutive_failures += 1
                summary.failed_lookups += len(batch)
                self._helper.connector_logger.warning(
                    "Could not resolve extracted entities against OpenCTI, "
                    "importing them as extracted",
                    {
                        "entities": [
                            {"type": candidate.entity_type, "name": candidate.name}
                            for _, candidate in batch
                        ],
                        "error": answer.error,
                    },
                )
                continue
            consecutive_failures = 0
            for (cache_key, candidate), result in zip(batch, answer.results):
                if result.status is _LookupStatus.FAILED:
                    summary.failed_lookups += 1
                    self._helper.connector_logger.warning(
                        "Could not resolve an extracted entity against OpenCTI, "
                        "importing it as extracted",
                        {
                            "type": candidate.entity_type,
                            "name": candidate.name,
                            "error": result.error,
                        },
                    )
                    continue
                self._cache.put(cache_key, result.resolution)
                if result.resolution is not None:
                    resolutions[candidate.key] = result.resolution
        if after_failures:
            self._helper.connector_logger.warning(
                "Stopped resolving the extracted entities of the document after "
                "consecutive failed requests, importing the others as extracted",
                {
                    "failed_requests": MAX_CONSECUTIVE_FAILED_REQUESTS,
                    "unresolved": after_failures,
                },
            )
        if over_budget:
            self._helper.connector_logger.warning(
                "The document names more entities than the lookup budget, "
                "importing the others as extracted",
                {
                    "max_lookups": self._max_lookups_per_document,
                    "unresolved": over_budget,
                },
            )
        return resolutions

    def _lookup(self, candidates: list[_Candidate]) -> _RequestResult:
        """Resolve a batch of names in one ``curationResolve`` request, never raising.

        A request that fails, or whose response carries none of the names,
        fails every name of the batch; an answer that cannot be read fails
        its name only.
        """
        variables = {}
        for index, candidate in enumerate(candidates):
            variables[f"name{index}"] = candidate.name
            variables[f"type{index}"] = candidate.entity_type
        try:
            response = self._helper.api_impersonate.query(
                curation_resolve_query(len(candidates)), variables
            )
        except Exception as error:  # the binding never fails an import
            status = (
                _LookupStatus.UNSUPPORTED
                if is_schema_error(error)
                else _LookupStatus.FAILED
            )
            return _RequestResult(status, error=_describe(error))
        data = response.get("data") if isinstance(response, dict) else None
        fields = [f"resolve{index}" for index in range(len(candidates))]
        if not isinstance(data, dict) or not any(name in data for name in fields):
            return _RequestResult(
                _LookupStatus.FAILED,
                error="unexpected response: no curationResolve data",
            )
        return _RequestResult(
            _LookupStatus.ANSWERED,
            tuple(_read_resolution(data, name) for name in fields),
        )

    @staticmethod
    def _rewrite_bundle(
        bundle: stix2.Bundle,
        bound_objects: dict[str, stix2.v21._STIXBase21 | dict],
        id_mapping: dict[str, str],
        summary: BindingSummary,
    ) -> stix2.Bundle:
        objects = [
            bound_objects.get(obj["id"], obj) for obj in bundle.get("objects", [])
        ]
        rewritten_relationship_ids = {
            obj["id"]
            for obj in objects
            if obj.get("type") == "relationship"
            and (
                obj.get("source_ref") in id_mapping
                or obj.get("target_ref") in id_mapping
            )
        }
        bound_bundle = remap_references_in_bundle(
            stix2.Bundle(type=bundle["type"], objects=objects, allow_custom=True),
            id_mapping,
        )
        # "Cozy Bear related-to APT29" once both name the same intrusion set.
        self_loop_ids = {
            obj["id"]
            for obj in bound_bundle.get("objects", [])
            if obj["id"] in rewritten_relationship_ids
            and obj.get("source_ref") == obj.get("target_ref")
        }
        bound_bundle = remove_objects_from_bundle(bound_bundle, self_loop_ids)
        bound_bundle = merge_rewritten_relationships(
            bound_bundle, rewritten_relationship_ids - self_loop_ids
        )
        merged_bundle = merge_duplicate_objects(bound_bundle)
        summary.dropped_relationships = len(self_loop_ids)
        summary.merged_objects = len(bound_bundle.get("objects", [])) - len(
            merged_bundle.get("objects", [])
        )
        return merged_bundle

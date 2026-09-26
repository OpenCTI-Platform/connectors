# -*- coding: utf-8 -*-
"""OpenCTI internal-enrichment connector for XposedOrNot.

Enriches Email-Addr observables with data-breach exposure. Works without any
API key via the free community API; an optional key switches to the Plus API.

Privacy note: the observable's email address (personal information) is sent
over TLS to xposedornot.com. Gate what may leave the platform with
XPOSEDORNOT_MAX_TLP, and use the results only within lawful, authorised
investigations.
"""

from __future__ import annotations

import json
import re
import traceback
from copy import deepcopy
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from connectors_sdk.models import Reference, TLPMarking
from pycti import MarkingDefinition as PyctiMarkingDefinition
from pycti import OpenCTIConnectorHelper
from src.xposedornot.client_api import XposedOrNotClient, redact, usable_score
from src.xposedornot.converter_to_stix import (
    ConverterToStix,
    ObservableNote,
    read_timestamp,
)
from src.xposedornot.settings import ConnectorSettings

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

TLP_MARKING_CREATED = "2017-01-20T00:00:00.000Z"

TLP_RANK = {
    "clear": 0,
    "white": 0,
    "green": 1,
    "amber": 2,
    "amber+strict": 3,
    "red": 4,
}


def listed(value: Any) -> list[Any]:
    """A field that should hold a list, read as one.

    Labels and external references each arrive under two spellings, and a
    malformed payload can put a bare string or a mapping where the list
    belongs. `list()` would iterate a string's characters and a mapping's keys,
    turning one bad field into a pile of junk entries, so anything that is not
    a genuine sequence is read as absent.
    """
    return list(value) if isinstance(value, (list, tuple)) else []


class MarkingResolutionError(Exception):
    """A marking on the enriched entity cannot be represented in the bundle."""


def marking_sequence(value: Any, field: str) -> list[Any]:
    """The entries of a marking field, refusing anything that is not a sequence.

    An empty list is a real answer and means no markings. A mapping or a bare
    string is not: iterating one yields its keys or its characters, and an
    empty mapping yields nothing at all, so the observable would read as
    unmarked on the strength of a field nobody could parse. Both marking
    fields go through this, because a restriction that cannot be read is not
    the same as a restriction that is absent.
    """
    if value is None:
        return []
    if not isinstance(value, (list, tuple)):
        raise MarkingResolutionError(
            f"{field} of the enriched observable is {type(value).__name__}, not"
            " a list; refusing to enrich rather than read an access-control"
            " field this connector cannot interpret."
        )
    return list(value)


def custom_marking_fields(marking: dict[str, Any]) -> tuple[str, str] | None:
    """The `x_opencti_definition_type`/`x_opencti_definition` pair, when both are set.

    connectors-sdk carries the real type and level of its statement-shaped
    markings here, and pycti's importer reads this pair in preference to the
    STIX fields. Anything that identifies or rebuilds a marking has to look at
    it too, or the sdk shape is silently unrecognisable.
    """
    definition_type = marking.get("x_opencti_definition_type")
    definition = marking.get("x_opencti_definition")
    if _filled(definition_type) and _filled(definition):
        return definition_type, definition
    return None


def _filled(value: Any) -> bool:
    """A string carrying something other than whitespace."""
    return isinstance(value, str) and bool(value.strip())


MARKING_ID_RE = re.compile(
    r"^marking-definition--[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}"
    r"-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)


def is_marking_id(value: Any) -> bool:
    """Whether a value is a STIX marking-definition identifier.

    Anything else placed in `object_marking_refs`, or used as a definition's
    own `id`, produces a bundle the platform cannot resolve. A non-empty
    string is not enough: `"not-a-stix-id"` was travelling into both.
    """
    return isinstance(value, str) and bool(MARKING_ID_RE.match(value.strip()))


def marking_id(marking: dict[str, Any]) -> str | None:
    """The STIX id of an OpenCTI objectMarking entry.

    A blank or malformed `standard_id` is not an id. Accepting one emitted it
    as both the reference and the rebuilt definition's own id, so the bundle
    carried an identifier nothing could resolve. The definition itself is
    authoritative, so an entry whose `standard_id` is unusable is identified
    from its type and value instead, and only one that survives none of these
    routes is unidentifiable.
    """
    standard_id = marking.get("standard_id")
    if is_marking_id(standard_id):
        return standard_id.strip()
    custom = custom_marking_fields(marking)
    if custom:
        return PyctiMarkingDefinition.generate_id(*custom)
    definition_type = marking.get("definition_type")
    definition = marking.get("definition")
    if _filled(definition_type) and _filled(definition):
        return PyctiMarkingDefinition.generate_id(definition_type, definition)
    return None


def materialize_marking(marking: dict[str, Any]) -> dict[str, Any] | None:
    """Rebuild a STIX marking definition from an OpenCTI objectMarking entry.

    Mirrors the shape pycti's prepare_export puts in data["stix_objects"], so
    any marking type the platform knows round-trips without special casing.

    A marking that already carries the OpenCTI custom fields is rebuilt in the
    statement shape connectors-sdk uses, keeping that pair intact. Rebuilding
    it from `definition_type` alone would either drop the marking, which makes
    the connector refuse a source it can in fact read, or re-label it as a
    plain statement and lose the level entirely.

    A TLP level the sdk knows is built by the sdk itself, so the definition
    the connector materialises and the one it applies to its own Note are the
    same object. CLEAR and AMBER+STRICT are OpenCTI custom statement markings
    rather than standard STIX tlp values: writing them as `definition_type:
    tlp` produced a body stix2 refuses to parse against their ids, and left
    two different bodies sharing one id in a bundle, where deduplication keeps
    whichever happened to come first. The standard four are unaffected, since
    the sdk spells them exactly as the prepare_export shape does.

    A typed marking that is neither TLP nor a plain statement, PAP above all,
    is written in the same custom shape, which is what the platform's own
    constants use. The prepare_export spelling lowercases both halves, and
    pycti's importer reads them straight back out for anything but TLP, so a
    PAP:RED entry would return as `pap` / `pap:red` and no longer match the
    canonical definition its id points at. Statement markings keep the
    prepare_export shape, which already round-trips intact.
    """
    identifier = marking_id(marking)
    if identifier is None:
        return None
    custom = custom_marking_fields(marking)
    if custom:
        custom_type, custom_definition = custom
        return {
            "type": "marking-definition",
            "spec_version": "2.1",
            "id": identifier,
            "created": (
                TLP_MARKING_CREATED
                if custom_type.upper() == "TLP"
                else marking.get("created") or TLP_MARKING_CREATED
            ),
            "definition_type": "statement",
            "definition": {"statement": "custom"},
            "x_opencti_definition_type": custom_type,
            "x_opencti_definition": custom_definition,
        }
    definition_type = marking.get("definition_type")
    definition = marking.get("definition")
    if not isinstance(definition_type, str) or not isinstance(definition, str):
        return None
    if definition_type.upper() == "TLP":
        level = tlp_level_of(definition)
        if level is not None:
            built = json.loads(TLPMarking(level=level).to_stix2_object().serialize())
            built["id"] = identifier
            return built
    if definition_type.lower() not in ("tlp", "statement"):
        return {
            "type": "marking-definition",
            "spec_version": "2.1",
            "id": identifier,
            "created": marking.get("created") or TLP_MARKING_CREATED,
            "definition_type": "statement",
            "definition": {"statement": "custom"},
            "x_opencti_definition_type": definition_type,
            "x_opencti_definition": definition,
        }
    if definition_type.upper() == "TLP":
        created = TLP_MARKING_CREATED
    else:
        created = marking.get("created") or TLP_MARKING_CREATED
    return {
        "type": "marking-definition",
        "spec_version": "2.1",
        "id": identifier,
        "created": created,
        "definition_type": definition_type.lower(),
        "name": definition,
        "definition": {definition_type.lower(): definition.lower().replace("tlp:", "")},
    }


def resolve_source_markings(
    stix_entity: dict[str, Any],
    observable: dict[str, Any],
    bundled: list[dict[str, Any]],
) -> tuple[list[str], list[dict[str, Any]]]:
    """Every marking the source carries, and the definitions the bundle lacks.

    Both halves come from one pass so the references placed on derived objects
    and the definitions shipped alongside them cannot drift apart. A reference
    that is neither bundled nor described by the observable raises instead of
    being left dangling for cleanup_inconsistent_bundle to strip, which would
    publish derived data under a weaker restriction than the source.

    `object_marking_refs` is read from the entity and from the observable. The
    two payloads normally divide the work, the entity carrying the references
    and the observable the resolved `objectMarking`, but a reference that
    appeared only on the observable would otherwise be collected by neither,
    and the gate cannot afford to depend on which half of the message a
    marking happened to arrive in.

    A reference that is not a usable id raises rather than being skipped, and
    so does a field that is not a list of them at all. The entity is asserting
    a marking either way, and quietly discarding what this connector cannot
    parse would leave it looking unmarked to the gate, which is the one
    conclusion the payload never supports. This is why the field is not read
    through `listed`: ignoring a malformed label costs a label, while ignoring
    a malformed marking costs the restriction itself.
    """
    supplied = []
    for source in (stix_entity, observable):
        supplied.extend(
            marking_sequence(source.get("object_marking_refs"), "object_marking_refs")
        )
    for ref in supplied:
        if not is_marking_id(ref):
            raise MarkingResolutionError(
                f"Marking reference {ref!r} of the enriched observable is not a"
                " usable identifier; refusing to enrich rather than treat the"
                " observable as carrying one marking fewer."
            )
    entries = marking_sequence(observable.get("objectMarking"), "objectMarking")
    identifiers = []
    for marking in entries:
        identifier = marking_id(marking) if hasattr(marking, "get") else None
        if identifier is None:
            raise MarkingResolutionError(
                f"Marking {marking!r} of the enriched observable cannot be"
                " assigned an identifier; refusing to enrich rather than drop"
                " a restriction this connector could not read."
            )
        identifiers.append(identifier)
    refs = list(dict.fromkeys(supplied + identifiers))
    present = {
        obj.get("id") for obj in bundled if obj.get("type") == "marking-definition"
    }
    candidates = {}
    for marking in entries:
        built = materialize_marking(marking)
        if built:
            candidates[built["id"]] = built
    missing = {}
    for ref in refs:
        if ref in present:
            continue
        definition = candidates.get(ref)
        if definition is None:
            raise MarkingResolutionError(
                f"Marking {ref} of the enriched observable cannot be resolved"
                " from the bundle or the entity markings; refusing to enrich"
                " with downgraded markings."
            )
        missing[ref] = definition
    return refs, list(missing.values())


def tlp_level_of(definition: str) -> str | None:
    """The connectors-sdk level name behind a `TLP:...` marking definition."""
    level = str(definition or "").strip().upper().removeprefix("TLP:").lower()
    return level if level in TLP_RANK else None


def tlp_marking_value(marking: Any) -> tuple[bool, Any]:
    """Whether a marking declares itself TLP, and the raw value it carries.

    A TLP marking reaches the connector in three shapes. The platform sends
    `definition_type: TLP` with the level in `definition`, or, once exported
    into a bundle, in `name`. Plain stix2 markings carry it in
    `definition["tlp"]` and have no name. connectors-sdk expresses TLP:CLEAR
    and TLP:AMBER+STRICT as *custom statement* markings, where
    `definition_type` is `statement` and the real level lives in
    `x_opencti_definition_type` and `x_opencti_definition`.

    pycti's importer reads the OpenCTI fields first and falls back to the STIX
    ones, so reading them in that same order makes this connector see the level
    the platform will actually store. Checking `definition_type` alone made
    every AMBER+STRICT marking that arrived in the sdk shape invisible, which
    let it past the gate unlooked at.
    """
    custom_type = marking.get("x_opencti_definition_type")
    if isinstance(custom_type, str) and custom_type.strip().upper() == "TLP":
        return True, marking.get("x_opencti_definition")
    if str(marking.get("definition_type") or "").strip().upper() != "TLP":
        return False, None
    definition = marking.get("definition")
    if hasattr(definition, "get"):
        return True, marking.get("name") or definition.get("tlp")
    if definition is None:
        return True, marking.get("name")
    return True, definition


def source_tlp_levels(
    observable: dict[str, Any],
    definitions: list[dict[str, Any]] | None = None,
) -> tuple[list[str], list[Any]]:
    """Canonical levels of every TLP marking on the source, and the unreadable ones.

    Markings reach the connector two ways: as `objectMarking` on the observable
    and as `object_marking_refs` on the entity, resolved against the bundled
    definitions. The gate must see both, or a marking expressed only as a
    reference would let an entity past on a restriction nobody looked at.

    Both sources go through one pass and one reader, so a shape understood in
    one place cannot be missed in the other.

    A marking that declares itself TLP but carries no value this connector can
    read is reported as unreadable rather than ignored: treating it as "no
    marking" would let an entity past on the strength of a field nobody parsed.
    """
    levels: list[str] = []
    unreadable: list[Any] = []
    sources = list(observable.get("objectMarking") or []) + list(definitions or [])
    for marking in sources:
        if not hasattr(marking, "get"):
            unreadable.append(marking)
            continue
        is_tlp, raw = tlp_marking_value(marking)
        if not is_tlp:
            continue
        level = tlp_level_of(raw)
        if level is None:
            unreadable.append(raw)
        elif level not in levels:
            levels.append(level)
    return levels, unreadable


def canonical_tlp(level: str) -> str:
    """The `TLP:...` spelling pycti compares against."""
    return f"TLP:{level.upper()}"


def effective_tlp_level(
    observable: dict[str, Any],
    configured: str,
    definitions: list[dict[str, Any]] | None = None,
) -> str:
    """The stricter of the observable's own markings and the configured level.

    The note repeats personal data derived from the observable, so it must
    never be readable by groups that cannot see the observable itself. Taking
    the maximum also honours an operator who deliberately configures a level
    stricter than the source. Equal ranks keep the configured name, so a
    `white` observable with `clear` configured yields the modern spelling.
    """
    levels, _ = source_tlp_levels(observable, definitions)
    return max([configured] + levels, key=lambda level: TLP_RANK[level])


def normalise_email(observable: dict[str, Any]) -> str:
    """The address the connector actually sends, lowercased and stripped."""
    raw = observable.get("observable_value") or observable.get("value") or ""
    return str(raw).strip().lower()


def is_valid_email(value: str) -> bool:
    return bool(value) and len(value) <= 254 and bool(EMAIL_RE.match(value))


def is_playbook_run(data: dict[str, Any]) -> bool:
    """Playbook steps arrive without an event_type; manual enrichments carry one."""
    return not data.get("event_type")


def refused_tlps(
    observable: dict[str, Any],
    max_tlp: str,
    definitions: list[dict[str, Any]] | None = None,
) -> tuple[list[str], list[Any]]:
    """Markings above the configured maximum, and markings that are unreadable.

    Both fail closed, but they are reported separately so the operator is told
    which of the two happened rather than being shown a malformed sentence.
    """
    levels, unreadable = source_tlp_levels(observable, definitions)
    return [
        canonical_tlp(level)
        for level in levels
        if not OpenCTIConnectorHelper.check_max_tlp(canonical_tlp(level), max_tlp)
    ], unreadable


def normalised_url(value: Any) -> str:
    """A URL with only the parts that are case-insensitive folded.

    RFC 3986 makes the scheme and the host case-insensitive and leaves the
    path, query and fragment case-sensitive. Folding the whole URL therefore
    merged references to genuinely different documents: `/Report` and
    `/report` are not the same page, and one of the analyst's own references
    was being dropped as a duplicate of the other.
    """
    text = str(value or "").strip()
    if not text:
        return ""
    try:
        parts = urlsplit(text)
    except ValueError:
        return text
    if not parts.scheme and not parts.netloc:
        return text
    return urlunsplit(
        (
            parts.scheme.casefold(),
            parts.netloc.casefold(),
            parts.path,
            parts.query,
            parts.fragment,
        )
    )


OWN_REFERENCE_SOURCE = "XposedOrNot"


def is_own_reference(reference: Any) -> bool:
    """Whether an external reference is one this connector wrote.

    Matched without regard to case or padding. A stale entry spelled
    `xposedornot` was not recognised, so it survived and a second one was
    appended beside it, and the same comparison decides whether the
    observable was enriched before, which drives score retraction.
    """
    if not hasattr(reference, "get"):
        return False
    source = str(reference.get("source_name") or "").strip().casefold()
    return source == OWN_REFERENCE_SOURCE.casefold()


def named_labels(value: Any) -> list[str]:
    """The labels in a field, keeping only entries that name something.

    Filtering has to happen before deduplication rather than after: a label
    that is a dict or a list is unhashable, and `dict.fromkeys` raised on it,
    which turned one malformed entry into a failed enrichment. Blank entries
    are dropped too, since a label of spaces names nothing.
    """
    return [
        label for label in listed(value) if isinstance(label, str) and label.strip()
    ]


def unique_by_id(objects: list[Any]) -> list[Any]:
    """Drop repeated STIX ids, keeping the first occurrence.

    The connector builds its own marking for the note, which collides with the
    identical definition the platform already bundled. A bundle carrying the
    same id twice can be rejected outright by the worker.
    """
    seen: set[str] = set()
    unique = []
    for obj in objects:
        identifier = obj.get("id") if hasattr(obj, "get") else None
        if identifier is not None:
            if identifier in seen:
                continue
            seen.add(identifier)
        unique.append(obj)
    return unique


class XposedOrNotConnector:
    OWNED_LABELS = ("data-breach", "plaintext-password-exposure")

    def __init__(self, config: ConnectorSettings, helper: OpenCTIConnectorHelper):
        self.config = config
        self.helper = helper
        self.scopes = list(config.connector.scope)

        api_key = (
            config.xposedornot.api_key.get_secret_value()
            if config.xposedornot.api_key
            else None
        )
        self.max_tlp = config.xposedornot.max_tlp
        self.tlp_level = config.xposedornot.tlp_level
        self.client = XposedOrNotClient(
            helper, api_key, str(config.xposedornot.api_base_url)
        )
        self.converter = ConverterToStix(
            author=ConverterToStix.make_author(),
            max_table_rows=config.xposedornot.max_note_breaches,
        )

    def _send_bundle(
        self, stix_objects: list[dict[str, Any]], update: bool = False
    ) -> None:
        bundle = self.helper.stix2_create_bundle(list(stix_objects))
        self.helper.send_stix2_bundle(
            bundle, update=update, cleanup_inconsistent_bundle=True
        )

    def _forward_unchanged(self, data: dict[str, Any], message: str) -> str:
        """Return the message; inside a playbook also hand the bundle back untouched
        so the next step still receives its input.

        The markings are resolved first, even on paths that never otherwise
        look at them. Forwarding runs the cleanup pass, which drops a reference
        whose target is missing from the bundle, so a bundle carrying a marking
        that cannot be resolved would come back out with weaker access control
        than it went in. The check belongs here rather than at each caller
        because a path that returns early, an out-of-scope entity above all,
        would otherwise skip it: the entity is none of this connector's
        business, but publishing it stripped of its markings still is.

        Any definition the bundle was missing travels with it. Resolving a
        reference is not enough on its own: a definition the platform sent
        only as `objectMarking` is not in the bundle, so cleanup would drop
        the reference pointing at it and weaken the very entity being handed
        back untouched. The bundle keeps everything it arrived with and gains
        only the definitions its own references need.

        The status message is redacted here as well. Several of these messages
        quote the payload so the operator can see what was refused, an
        unreadable marking or an unsupported entity type among them, and the
        returned string reaches the platform's work status. Redacting at this
        one funnel rather than at each caller means a message added later
        cannot miss it.
        """
        message = self._redacted(message, data)
        if is_playbook_run(data):
            try:
                _, missing_markings = resolve_source_markings(
                    data.get("stix_entity") or {},
                    data.get("enrichment_entity") or {},
                    data.get("stix_objects") or [],
                )
            except MarkingResolutionError as error:
                return self._refuse_unresolved_marking(error, data)
            forwarded = list(data["stix_objects"])
            referenced = {
                ref
                for obj in forwarded
                if hasattr(obj, "get")
                for ref in (obj.get("object_marking_refs") or [])
            }
            self._send_bundle(
                unique_by_id(
                    forwarded
                    + [
                        definition
                        for definition in missing_markings
                        if definition["id"] in referenced
                    ]
                )
            )
        return message

    def _refuse_unresolved_marking(self, error: Exception, data: dict[str, Any]) -> str:
        """Refuse without handing the bundle on.

        Every other no-op forwards its input so a playbook step still produces
        output, and that forward is cleaned, which is what the platform wants
        for a bundle carrying a reference to an object it cannot see. Here the
        unresolvable reference is the whole reason for refusing, so cleaning it
        would strip the source marking and republish the entity unrestricted,
        and shipping it uncleaned would only trade that for the missing
        reference error the cleanup exists to avoid. Nothing is published under
        a marking this connector could not establish; the playbook step stops
        here rather than passing on data it cannot mark correctly.

        The reason is redacted first. It quotes the offending reference or
        entry verbatim so an operator can see what was wrong with it, and a
        payload is free to put the observable's own address in a marking
        field, which would otherwise walk it straight past the redaction every
        other log line goes through.
        """
        reason = self._redacted(str(error), data)
        self.helper.connector_logger.error(
            "Refusing to enrich: a source marking cannot be represented in the"
            " bundle, and the bundle is not forwarded",
            meta={"reason": reason},
        )
        return reason

    def _process_message(self, data: dict[str, Any]) -> str:
        observable = data["enrichment_entity"]
        entity_type = observable.get("entity_type")
        if entity_type not in self.scopes:
            return self._forward_unchanged(data, f"Unsupported type: {entity_type}")

        try:
            marking_refs, missing_markings = resolve_source_markings(
                data["stix_entity"], observable, data["stix_objects"]
            )
        except MarkingResolutionError as error:
            return self._refuse_unresolved_marking(error, data)
        source_definitions = [
            obj
            for obj in list(data["stix_objects"]) + missing_markings
            if obj.get("type") == "marking-definition" and obj.get("id") in marking_refs
        ]

        too_high, unreadable = refused_tlps(
            observable, self.max_tlp, source_definitions
        )
        if too_high:
            return self._forward_unchanged(
                data,
                f"TLP of the observable ({', '.join(too_high)}) is higher than"
                f" what the connector is allowed to enrich ({self.max_tlp});"
                " skipping.",
            )
        if unreadable:
            return self._forward_unchanged(
                data,
                "The observable carries a marking this connector cannot read"
                f" ({', '.join(repr(value) for value in unreadable)}); refusing"
                " to enrich rather than treat it as unmarked.",
            )

        email = normalise_email(observable)
        if not is_valid_email(email):
            return self._forward_unchanged(
                data, "The observable value is not a valid email address."
            )

        result = self.client.lookup(email)
        if result is None:
            return self._forward_unchanged(
                data, "XposedOrNot request failed (see logs)."
            )
        if not result:
            return self._forward_unchanged(
                data, "No known breach exposure for this email address (XposedOrNot)."
            )

        breaches = result.get("breaches") or []

        stix_objects = data["stix_objects"]
        stix_entity = data["stix_entity"]
        enriched_entity = deepcopy(stix_entity)
        if marking_refs:
            enriched_entity["object_marking_refs"] = marking_refs
        existing_refs = [
            ref
            for ref in listed(enriched_entity.get("external_references"))
            + listed(enriched_entity.get("x_opencti_external_references"))
            if hasattr(ref, "get")
        ]
        enriched_before = any(is_own_reference(ref) for ref in existing_refs)
        raw_score = result.get("risk_score")
        score = usable_score(raw_score)
        if score is not None:
            enriched_entity["x_opencti_score"] = score
        elif raw_score is not None:
            self.helper.connector_logger.warning(
                "XposedOrNot returned a risk score this connector cannot use;"
                " leaving the observable's existing score untouched",
                meta={"type": type(raw_score).__name__},
            )
        elif enriched_before and enriched_entity.get("x_opencti_score") is not None:
            enriched_entity["x_opencti_score"] = None
        owned_labels = named_labels(enriched_entity.get("x_opencti_labels"))
        existing_labels = owned_labels + [
            label
            for label in named_labels(enriched_entity.get("labels"))
            if label not in owned_labels
        ]
        labels = [
            label
            for label in dict.fromkeys(existing_labels)
            if label not in self.OWNED_LABELS
        ]
        labels.append("data-breach")
        if self.converter.has_plaintext_exposure(breaches):
            labels.append("plaintext-password-exposure")
        enriched_entity["x_opencti_labels"] = labels
        enriched_entity.pop("labels", None)
        seen: set[tuple[str, str]] = set()
        external_references = []
        for ref in existing_refs:
            if is_own_reference(ref):
                continue
            key = (
                str(ref.get("source_name") or "").strip().casefold(),
                normalised_url(ref.get("url")),
            )
            if any(key):
                if key in seen:
                    continue
                seen.add(key)
            external_references.append(ref)
        external_references.append(
            {
                "source_name": "XposedOrNot",
                "url": "https://xposedornot.com",
                "description": "XposedOrNot breach exposure check",
            }
        )
        enriched_entity["x_opencti_external_references"] = external_references
        enriched_entity.pop("external_references", None)
        enriched_objects = [
            enriched_entity if obj["id"] == enriched_entity["id"] else obj
            for obj in stix_objects
        ]
        if all(obj["id"] != enriched_entity["id"] for obj in enriched_objects):
            enriched_objects.append(enriched_entity)

        # Per-breach detail as a markdown Note attached to the observable.
        note_tlp = TLPMarking(
            level=effective_tlp_level(observable, self.tlp_level, source_definitions)
        )
        note_markings = [note_tlp] + [
            Reference(id=ref) for ref in marking_refs if ref != note_tlp.id
        ]
        note_id = ObservableNote.stable_id(enriched_entity["id"])
        superseded = [
            read_timestamp(obj.get("modified"))
            for obj in enriched_objects
            if obj.get("id") == note_id
        ]
        note = self.converter.build_note(
            enriched_entity["id"],
            result,
            markings=note_markings,
            observed_at=observable.get("created_at"),
            supersedes=max([stamp for stamp in superseded if stamp], default=None),
        )
        note_object = note.to_stix2_object()
        enriched_objects = [
            obj for obj in enriched_objects if obj["id"] != note_object["id"]
        ]
        enriched_objects += [
            self.converter.author.to_stix2_object(),
            note_tlp.to_stix2_object(),
            note_object,
        ]
        enriched_objects += missing_markings
        enriched_objects = unique_by_id(enriched_objects)

        self._send_bundle(enriched_objects, update=True)

        first_year, latest_year = self.converter.years(breaches)
        span = (
            f" (first {first_year}, latest {latest_year})"
            if first_year and latest_year
            else ""
        )
        return (
            f"Found {len(breaches)} breach(es){span}; observable updated and"
            " summary note attached."
        )

    def _redacted(self, text: str, data: dict[str, Any]) -> str:
        """Text with the observable value and the API key blanked.

        Both spellings are blanked: text may quote the address as the platform
        supplied it, or as the connector normalised it before use.
        """
        observable = data.get("enrichment_entity") or {}
        raw = str(observable.get("observable_value") or observable.get("value") or "")
        return redact(text, raw, normalise_email(observable), self.client.api_key)

    def _safe_trace(self, data: dict[str, Any]) -> str:
        """The traceback, redacted."""
        return self._redacted(traceback.format_exc(), data)

    def _process_callback(self, data: dict[str, Any]) -> str:
        try:
            return self._process_message(data)
        except MarkingResolutionError as error:
            return self._refuse_unresolved_marking(error, data)
        except Exception:
            self.helper.connector_logger.error(
                "Error during enrichment", meta={"trace": self._safe_trace(data)}
            )
            message = "Internal error (see logs)."
            try:
                return self._forward_unchanged(data, message)
            except Exception:
                self.helper.connector_logger.error(
                    "Could not hand the original bundle back to the playbook",
                    meta={"trace": self._safe_trace(data)},
                )
                return message

    def run(self) -> None:
        self.helper.connector_logger.info("Starting the XposedOrNot connector.")
        self.helper.listen(message_callback=self._process_callback)

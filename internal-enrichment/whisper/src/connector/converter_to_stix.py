"""Pure-function mappers from Whisper graph nodes/edges to STIX 2.1 objects.

Input shape (normalized; the Cypher → normalized translation lives in #7):

    node = {
        "id":   "<stable whisper id>",
        "type": "<one of NODE_MAPPERS keys>",
        "properties": {<type-specific fields>},
    }

    edge = {
        "id":        "<stable whisper id>",   # optional
        "source_id": "<whisper node id>",
        "target_id": "<whisper node id>",
        "type":      "<one of ALLOWED_RELATIONSHIPS>",
        "properties": {"description": "..."},  # optional
    }
"""

import logging
from collections.abc import Callable
from typing import Any

import pycti
import stix2
from connector.exceptions import StixMappingError

# Module-level logger (same idiom as result_parser.py): this module is pure
# functions with no connector context, so the pycti connector_logger is not
# threaded in here.
logger = logging.getLogger(__name__)

# SDO / Relationship / Note STIX IDs are generated with pycti's deterministic
# ``generate_id`` helpers — the same method every first-party OpenCTI connector
# uses — so objects this connector produces dedup against ones produced by
# other connectors and across re-enrichments (per the upstream PR review,
# OpenCTI-Platform/connectors#6708). SCOs keep the stix2 library's own
# spec-deterministic IDs (derived from key properties; no explicit ``id=``).

# Author Identity stamped on every object this connector emits, so analysts
# can tell Whisper-sourced intel apart in OpenCTI (upstream Verified linter
# VC302: an author Identity must be defined *and* referenced). The ID is
# deterministic — pycti hashes exactly (name, identity_class) — so it is
# stable across runs, connectors, and the upstream port. Collision-by-design:
# a Whisper ORGANIZATION graph node literally named "Whisper" would generate
# this same Identity ID; that dedup is acceptable and arguably correct.
# The author Identity itself carries no created_by_ref.
_AUTHOR_ID = pycti.Identity.generate_id(name="Whisper", identity_class="organization")
WHISPER_AUTHOR = stix2.Identity(
    id=_AUTHOR_ID,
    name="Whisper",
    identity_class="organization",
    description=(
        "Whisper — internet infrastructure graph enrichment "
        "(https://whisper.security)"
    ),
)


def _require_props(node: dict, *keys: str) -> None:
    props = node.get("properties") or {}
    missing = [k for k in keys if props.get(k) in (None, "")]
    if missing:
        raise StixMappingError(
            f"node id={node.get('id')!r} type={node.get('type')!r} "
            f"missing required properties: {missing}"
        )


# --- SCO mappers -----------------------------------------------------------
# SCO IDs are deterministic per STIX 2.1 spec, derived from the key
# properties by the stix2 library — we don't pass an explicit `id=`.
#
# SCOs can't carry `created_by_ref` (STIX 2.1 reserves it for SDOs), so
# authorship rides in `x_opencti_created_by_ref` via `custom_properties` —
# the OpenCTI convention verified connectors use. Custom properties are
# excluded from stix2's ID hash, so the built-in deterministic SCO IDs are
# unchanged.

_SCO_AUTHOR = {"x_opencti_created_by_ref": _AUTHOR_ID}


def _map_ipv4(node: dict) -> stix2.IPv4Address:
    _require_props(node, "value")
    return stix2.IPv4Address(
        value=node["properties"]["value"], custom_properties=_SCO_AUTHOR
    )


def _map_ipv6(node: dict) -> stix2.IPv6Address:
    _require_props(node, "value")
    return stix2.IPv6Address(
        value=node["properties"]["value"], custom_properties=_SCO_AUTHOR
    )


def _map_domain(node: dict) -> stix2.DomainName:
    _require_props(node, "value")
    return stix2.DomainName(
        value=node["properties"]["value"], custom_properties=_SCO_AUTHOR
    )


def _map_url(node: dict) -> stix2.URL:
    _require_props(node, "value")
    return stix2.URL(value=node["properties"]["value"], custom_properties=_SCO_AUTHOR)


def _map_email(node: dict) -> stix2.EmailAddress:
    _require_props(node, "value")
    return stix2.EmailAddress(
        value=node["properties"]["value"], custom_properties=_SCO_AUTHOR
    )


def _map_autonomous_system(node: dict) -> stix2.AutonomousSystem:
    props = node.get("properties") or {}
    _require_props(node, "number")
    kwargs: dict[str, Any] = {"number": int(props["number"])}
    if props.get("name"):
        kwargs["name"] = props["name"]
    return stix2.AutonomousSystem(custom_properties=_SCO_AUTHOR, **kwargs)


def _map_file(node: dict) -> stix2.File:
    props = node.get("properties") or {}
    hashes: dict[str, str] = {}
    for whisper_key, stix_key in (
        ("md5", "MD5"),
        ("sha1", "SHA-1"),
        ("sha256", "SHA-256"),
    ):
        if props.get(whisper_key):
            hashes[stix_key] = props[whisper_key]
    if not hashes and not props.get("name"):
        raise StixMappingError(
            f"file node id={node.get('id')!r} requires at least one hash or name"
        )
    kwargs: dict[str, Any] = {}
    if hashes:
        kwargs["hashes"] = hashes
    if props.get("name"):
        kwargs["name"] = props["name"]
    return stix2.File(custom_properties=_SCO_AUTHOR, **kwargs)


# --- SDO mappers -----------------------------------------------------------
# SDOs get deterministic IDs from pycti's ``generate_id`` helpers, keyed off
# the same properties OpenCTI uses server-side — so re-enrichment and
# cross-connector dedup both line up. Every SDO carries
# ``created_by_ref=_AUTHOR_ID`` so OpenCTI attributes it to the Whisper
# author Identity (created_by_ref is not an ID-contributing property, so
# the pycti-generated IDs are unchanged).


def _map_threat_actor(node: dict) -> stix2.ThreatActor:
    props = node.get("properties") or {}
    _require_props(node, "name")
    # Build id at the literal kwarg position — the vendored STIX-ID pylint
    # plugin can't see through **kwargs spreads, so we keep id explicit at
    # every stix2 _DomainObject / Relationship constructor site.
    stix_id = pycti.ThreatActorGroup.generate_id(name=props["name"])
    extras: dict[str, Any] = {}
    if props.get("description"):
        extras["description"] = props["description"]
    return stix2.ThreatActor(
        id=stix_id, name=props["name"], created_by_ref=_AUTHOR_ID, **extras
    )


def _map_malware(node: dict) -> stix2.Malware:
    props = node.get("properties") or {}
    _require_props(node, "name")
    return stix2.Malware(
        id=pycti.Malware.generate_id(name=props["name"]),
        name=props["name"],
        is_family=bool(props.get("is_family", False)),
        created_by_ref=_AUTHOR_ID,
    )


def _map_location(node: dict) -> stix2.Location:
    # Whisper COUNTRY → STIX Location with `country` only.
    # Whisper CITY    → STIX Location with `city`+`country`+`name` (when
    #                   the "<City>, <CC>" suffix is parseable; otherwise
    #                   just `name` with the raw Whisper string).
    # pycti.Location.generate_id keys off (name, location_type) — the same
    # tuple OpenCTI hashes server-side — so the SDO dedups across connectors.
    props = node.get("properties") or {}
    # STIX 2.1 Location requires at least one of country/region/lat-long.
    # The parser only produces Location nodes when it has a country, so
    # raise loudly if that invariant is violated.
    if not props.get("country") and not props.get("region"):
        raise StixMappingError(
            f"location node id={node.get('id')!r} requires at least country or region"
        )
    if props.get("city"):
        location_type, location_name = "City", props.get("name") or props["city"]
    elif props.get("region"):
        location_type, location_name = "Region", props.get("name") or props["region"]
    else:
        location_type, location_name = "Country", props.get("name") or props["country"]
    # Build id at the literal kwarg position so the vendored STIX-ID
    # pylint plugin can see it (it doesn't follow **kwargs spreads).
    stix_id = pycti.Location.generate_id(
        name=location_name, x_opencti_location_type=location_type
    )
    extras: dict[str, Any] = {}
    for stix_field in ("country", "city", "name", "region"):
        if props.get(stix_field):
            extras[stix_field] = props[stix_field]
    return stix2.Location(id=stix_id, created_by_ref=_AUTHOR_ID, **extras)


def _map_identity(node: dict) -> stix2.Identity:
    # Whisper ORGANIZATION and REGISTRAR nodes both become Identity SDOs
    # with identity_class="organization". The edge's `description` field
    # (set by the parser when the Whisper edge type has no dedicated STIX
    # equivalent — see issue #31's pattern) carries the original Whisper
    # edge type (REGISTERED_BY, ORG_OF, etc.) so the relationship still
    # tells an analyst whether a given Identity is a registrar vs an
    # owner vs a contact organization.
    props = node.get("properties") or {}
    _require_props(node, "name")
    identity_class = props.get("identity_class", "organization")
    return stix2.Identity(
        id=pycti.Identity.generate_id(
            name=props["name"], identity_class=identity_class
        ),
        name=props["name"],
        identity_class=identity_class,
        created_by_ref=_AUTHOR_ID,
    )


NODE_MAPPERS: dict[str, Callable[[dict], Any]] = {
    "ipv4-addr": _map_ipv4,
    "ipv6-addr": _map_ipv6,
    "domain-name": _map_domain,
    "url": _map_url,
    "email-addr": _map_email,
    "autonomous-system": _map_autonomous_system,
    "file": _map_file,
    "threat-actor": _map_threat_actor,
    "malware": _map_malware,
    "location": _map_location,
    "identity": _map_identity,
}

ALLOWED_RELATIONSHIPS: frozenset[str] = frozenset(
    {
        "communicates-with",
        "resolves-to",
        "related-to",
        "attributed-to",
        "uses",
        "indicates",
        "downloads",
        "hosts",
    }
)


def map_node(node: dict) -> Any:
    """Translate one Whisper node dict into the corresponding STIX object."""
    if not node.get("id") or not node.get("type"):
        raise StixMappingError(f"node missing required fields 'id'/'type': {node!r}")
    mapper = NODE_MAPPERS.get(node["type"])
    if mapper is None:
        raise StixMappingError(f"unsupported node type: {node['type']!r}")
    return mapper(node)


def map_edge(edge: dict, source_stix: Any, target_stix: Any) -> stix2.Relationship:
    """Translate a Whisper edge + the two already-mapped endpoints into a STIX Relationship."""
    for field in ("source_id", "target_id", "type"):
        if not edge.get(field):
            raise StixMappingError(f"edge missing required field {field!r}: {edge!r}")
    rel_type = edge["type"]
    if rel_type not in ALLOWED_RELATIONSHIPS:
        raise StixMappingError(f"unsupported relationship type: {rel_type!r}")

    # pycti keys the relationship id off (type, source, target) — the same
    # tuple OpenCTI uses server-side — so re-enrichment is idempotent and the
    # SRO dedups against identical relationships from other connectors. id
    # passed at the literal kwarg position so the vendored STIX-ID pylint
    # plugin can see it (it doesn't follow **kwargs spreads).
    stix_id = pycti.StixCoreRelationship.generate_id(
        rel_type, source_stix.id, target_stix.id
    )
    extras: dict[str, Any] = {}
    description = (edge.get("properties") or {}).get("description")
    if description:
        extras["description"] = description
    return stix2.Relationship(
        id=stix_id,
        relationship_type=rel_type,
        source_ref=source_stix.id,
        target_ref=target_stix.id,
        created_by_ref=_AUTHOR_ID,
        **extras,
    )


def build_bundle(
    nodes: list[dict],
    edges: list[dict],
    extra_objects: list[Any] | None = None,
) -> stix2.Bundle:
    """Map a list of Whisper nodes + edges into a STIX 2.1 Bundle.

    ``extra_objects`` is for already-constructed STIX objects the connector
    wants included in the same bundle — typically Notes built via
    ``build_note`` (e.g. for `LINKS_TO` cap-overflow summaries or threat
    feed evidence). They're appended after the node-and-edge objects.

    A non-empty bundle always leads with ``WHISPER_AUTHOR``, the Identity
    every other object references as its author (VC302).

    Edges that reference unknown nodes raise StixMappingError. Edges whose
    endpoints resolve to the same STIX ID (self-loops) are skipped with an
    info log — OpenCTI rejects every same-source-target relationship, so
    there is no legitimate case to ship.
    """
    by_whisper_id: dict[str, Any] = {}
    objects: list[Any] = []

    for node in nodes:
        stix_obj = map_node(node)
        by_whisper_id[node["id"]] = stix_obj
        objects.append(stix_obj)

    for edge in edges:
        src = by_whisper_id.get(edge.get("source_id"))
        dst = by_whisper_id.get(edge.get("target_id"))
        if src is None or dst is None:
            raise StixMappingError(
                f"edge references unknown node id: "
                f"source={edge.get('source_id')!r} target={edge.get('target_id')!r}"
            )
        # Distinct Whisper nodes can resolve to the same deterministic STIX
        # ID — e.g. a domain that is its own nameserver (two HOSTNAME nodes,
        # one value) or same-name Identity SDOs colliding via
        # pycti.Identity.generate_id. OpenCTI rejects every relationship
        # whose source and target are the same entity (worker
        # UNSUPPORTED_ERROR), so skip the self-loop here — the one
        # chokepoint every producer path crosses after whisper-ID →
        # STIX-ID resolution. Info, not warning: self-nameserver domains
        # recur legitimately in real data.
        if src.id == dst.id:
            logger.info(
                "skipping self-loop relationship: %s -[%s]-> itself",
                src.id,
                edge.get("type"),
            )
            continue
        objects.append(map_edge(edge, src, dst))

    if extra_objects:
        objects.extend(extra_objects)

    # Prepend the author Identity whenever the bundle carries anything —
    # every object above references it via (x_opencti_)created_by_ref, and
    # OpenCTI needs the referenced Identity present in the same bundle.
    if objects:
        objects.insert(0, WHISPER_AUTHOR)

    # allow_custom is required: the SCOs carry the x_opencti_created_by_ref
    # custom property, and stix2.Bundle raises on unregistered custom
    # properties without it.
    return stix2.Bundle(objects=objects, allow_custom=True)


def build_note(
    seed_stix_id: str,
    content: str,
    abstract: str = "Whisper enrichment note",
) -> stix2.Note:
    """Build a STIX 2.1 Note SDO attached to a seed observable's STIX ID.

    The Note's ID comes from ``pycti.Note.generate_id`` keyed off
    (content, abstract) — the same deterministic helper OpenCTI uses
    server-side — so re-enrichment with the same content produces the same
    Note ID and dedup stays clean. ``created`` is left unset so the ID is
    stable across runs (a wall-clock ``created`` would re-key it each time).

    Used by the connector for:
    - `LINKS_TO` cap-overflow summaries ("Whisper found N inbound links,
      showing first 25")
    - threat feed evidence (which feeds the seed appears in — see #51's
      pattern for invalid hostnames)
    - node-level threat property summaries
    """
    if not seed_stix_id or not content:
        raise StixMappingError("build_note requires both seed_stix_id and content")
    # created_by_ref does not re-key the Note: pycti.Note.generate_id only
    # hashes (created, content, abstract).
    return stix2.Note(
        id=pycti.Note.generate_id(None, content, abstract),
        abstract=abstract,
        content=content,
        object_refs=[seed_stix_id],
        created_by_ref=_AUTHOR_ID,
    )

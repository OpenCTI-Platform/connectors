"""Translate Whisper Cypher rows into normalized nodes/edges for the STIX mapper.

Whisper row cell shapes (per the live API, captured in PR #11):

- Node cell: ``{"nodeId": "...", "label": "<UPPERCASE>", "name": "...", ...}``
- Edge cell: ``{"type": "<UPPERCASE>", ...}``  (no source/target — inferred
  from neighbouring node columns)

Output shape (consumed by ``converter_to_stix.build_bundle``):

- ``nodes`` — list of ``{"id", "type", "properties"}``
- ``edges`` — list of ``{"source_id", "target_id", "type", "properties"}``

Whisper labels currently mapped to STIX types (see ``_LABEL_TO_STIX_TYPE``):
HOSTNAME, IPV4, IPV6, ASN, EMAIL, COUNTRY/CITY (→ Location SDO),
ORGANIZATION/REGISTRAR (→ Identity SDO). Other labels (FEED_SOURCE, PREFIX,
REGISTERED_PREFIX, ANNOUNCED_PREFIX, RIR, TLD, PHONE, etc.) are silently
dropped — no clean STIX equivalent exists yet. Edges that touch a dropped
node are also dropped.
"""

import ipaddress
import logging
import re

from connector.iana_registrars import resolve_registrar_name
from connector.whisper_client import CypherResult

logger = logging.getLogger(__name__)


# Whisper node label → STIX-style type key consumed by the STIX mapper.
_LABEL_TO_STIX_TYPE: dict[str, str] = {
    "IPV4": "ipv4-addr",
    "IPV6": "ipv6-addr",
    "HOSTNAME": "domain-name",
    "ASN": "autonomous-system",
    "EMAIL": "email-addr",
    "COUNTRY": "location",
    "CITY": "location",
    "ORGANIZATION": "identity",
    "REGISTRAR": "identity",
}

# Whisper edge type → STIX relationship type. Anything not listed here
# falls back to "related-to" with the original Whisper edge type carried in
# the relationship's `description` field — see _build_edge below.
#
# OpenCTI enforces the STIX 2.1 fixed SRO vocabulary at ingestion (custom
# relationship_type strings like "nameserver-for" are rejected with
# FUNCTIONAL_ERROR). Issue #31 explored emitting custom types directly;
# that path requires platform-side custom-relationship-type registration
# (deferred to v0.4). For now we preserve Whisper edge semantics in the
# description field — visible to analysts, queryable as text, lossless.
_EDGE_TO_STIX_REL: dict[str, str] = {
    "RESOLVES_TO": "resolves-to",
}

# STIX relationships where direction matters. Maps the STIX rel type to the
# expected source STIX type — if the row gives us the endpoints in the
# wrong order, we flip before emitting.
_EDGE_DIRECTION_SOURCE: dict[str, set[str]] = {
    "resolves-to": {"domain-name"},
}

_ASN_NAME_RE = re.compile(r"^AS(\d+)$", re.IGNORECASE)


def _is_valid_domain_name(value: str) -> bool:
    """RFC 1035 / 1123-compliant domain name check.

    OpenCTI's worker validates STIX `domain-name` SCO values against the
    spec and rejects malformed values (e.g. with `FUNCTIONAL_ERROR:
    Observable is not correctly formatted`). Whisper sometimes returns
    DNS subdomain records whose names contain characters that are valid
    DNS labels for specific record types (TXT/SPF/DKIM/DMARC use
    underscored labels like `_spf.example.com`) but are NOT valid
    general-purpose domain names per RFC 1035. We filter those at parse
    time so the bundle doesn't ship objects OpenCTI will reject — keeps
    the work-item status honest and avoids orphan relationships.
    """
    if not value or len(value) > 253 or value.endswith("."):
        return False
    for label in value.split("."):
        if not (1 <= len(label) <= 63):
            return False
        if label.startswith("-") or label.endswith("-"):
            return False
        if not all((c.isascii() and c.isalnum()) or c == "-" for c in label):
            return False
    return True


def collect_dropped_hostnames(result: CypherResult) -> list[dict]:
    """Return the HOSTNAME records that ``parse_cypher_result`` would silently
    drop for failing the RFC 1035 check, paired with the Whisper edge type
    that referenced each one.

    The connector uses this to attach a STIX ``Note`` SDO to the seed
    listing what was dropped, so analysts know Whisper had the data even
    though it couldn't ship as a ``domain-name`` SCO (issue #51 builds on
    #47's filter-and-drop foundation).

    Each entry: ``{"name": str, "edge_type": str}``. ``edge_type`` is
    empty when no edge cell exists in the same row (e.g. single-column
    RETURN). Duplicates within a row are de-duplicated by name; the
    caller is responsible for cross-row dedup.

    IP-shaped HOSTNAME values (Whisper data quirk; reclassified to IPV4 /
    IPV6 by the translator) are NOT counted as drops — they round-trip
    fine, just on a different SCO type.
    """
    dropped: list[dict] = []
    seen_in_row: set[str]
    for row in result.rows:
        if not isinstance(row, dict):
            continue
        seen_in_row = set()
        host_drops: list[tuple[int, str]] = []
        edges: list[tuple[int, str]] = []
        for idx, col in enumerate(result.columns):
            cell = row.get(col)
            if not isinstance(cell, dict):
                continue
            if "nodeId" in cell and cell.get("label") == "HOSTNAME":
                name = cell.get("name")
                if not name or name in seen_in_row:
                    continue
                try:
                    ipaddress.ip_address(name)
                    continue  # IP-shaped HOSTNAME → reclassified, not dropped.
                except ValueError:
                    pass
                if not _is_valid_domain_name(name):
                    host_drops.append((idx, name))
                    seen_in_row.add(name)
            elif "type" in cell:
                edges.append((idx, cell["type"]))
        for node_idx, name in host_drops:
            edge_type = (
                min(edges, key=lambda e: abs(e[0] - node_idx))[1] if edges else ""
            )
            dropped.append({"name": name, "edge_type": edge_type})
    return dropped


def parse_cypher_result(result: CypherResult) -> tuple[list[dict], list[dict]]:
    """Walk a CypherResult and produce normalized (nodes, edges) for build_bundle."""
    nodes_by_id: dict[str, dict] = {}
    edges: list[dict] = []

    for row in result.rows:
        ordered = [(idx, col, row.get(col)) for idx, col in enumerate(result.columns)]

        # Classify each cell and translate nodes per-row so we know which
        # column indices in this row produced a usable node.
        translated_by_idx: dict[int, dict] = {}
        edge_cells: list[tuple[int, dict]] = []
        for idx, _col, cell in ordered:
            if not isinstance(cell, dict):
                continue
            if "nodeId" in cell:
                translated = _translate_node(cell)
                if translated is not None:
                    translated_by_idx[idx] = translated
                    nodes_by_id.setdefault(translated["id"], translated)
            elif "type" in cell:
                edge_cells.append((idx, cell))

        # Pair each edge with its nearest translated node on each side.
        for idx, edge_cell in edge_cells:
            src = _nearest_node(translated_by_idx, idx, direction=-1)
            tgt = _nearest_node(translated_by_idx, idx, direction=+1)
            if src is None or tgt is None:
                continue
            whisper_type = edge_cell["type"]
            stix_rel = _EDGE_TO_STIX_REL.get(whisper_type, "related-to")
            oriented_src, oriented_tgt = _orient_edge(stix_rel, src, tgt)
            properties: dict = {}
            # When the Whisper edge has no dedicated STIX type, surface the
            # original Whisper edge name in the description so analysts can
            # still distinguish NAMESERVER_FOR from LINKS_TO etc. without
            # losing the semantics in the `related-to` collapse.
            if stix_rel == "related-to":
                properties["description"] = whisper_type
            edges.append(
                {
                    "source_id": oriented_src["id"],
                    "target_id": oriented_tgt["id"],
                    "type": stix_rel,
                    "properties": properties,
                }
            )

    return list(nodes_by_id.values()), edges


def translate_node_cell(cell: dict) -> dict | None:
    """Public wrapper around the node translator.

    The targeted Domain-Name enrichment path (issue #61) builds STIX
    relationships explicitly rather than inferring them from row column
    order, but still needs the same node normalization the main parser
    applies — IP-shaped HOSTNAME reclassification, RFC 1035 filtering,
    REGISTRAR/ORGANIZATION → Identity cleanup, ASN parsing. Returns the
    normalized ``{"id", "type", "properties"}`` dict, or ``None`` if the
    cell isn't a usable/mappable node.
    """
    if not isinstance(cell, dict) or "nodeId" not in cell:
        return None
    return _translate_node(cell)


def _translate_node(cell: dict) -> dict | None:
    label = cell.get("label")
    name = cell.get("name")

    # Whisper data quirk: some IPs (e.g. 8.8.4.4) are stored with label
    # HOSTNAME. Reclassify by IP-format so OpenCTI doesn't reject them
    # as malformed domain-name SCOs.
    if label == "HOSTNAME" and name:
        try:
            ip = ipaddress.ip_address(name)
            label = "IPV6" if isinstance(ip, ipaddress.IPv6Address) else "IPV4"
        except ValueError:
            # Not an IP — validate as RFC 1035 domain name before letting
            # this become a STIX domain-name SCO. Whisper returns some DNS
            # records (SPF/DKIM/DMARC subdomains containing underscores
            # like `_spf_telus_com.nssi.telus.com`) that OpenCTI rejects
            # at ingestion. Drop them here so the bundle stays consistent
            # with what OpenCTI will accept (issue #47).
            if not _is_valid_domain_name(name):
                # warning (not debug/info) so operators get a visible record
                # of silently dropped data — the upstream Verified linter
                # (VC307) flags except blocks whose only log call is
                # debug/info; warning is the lowest level that conforms.
                # Volume is bounded by the query LIMITs.
                logger.warning("dropping HOSTNAME with non-RFC-1035 value: %r", name)
                return None

    stix_type = _LABEL_TO_STIX_TYPE.get(label)
    if stix_type is None:
        return None
    if not name:
        return None

    props: dict = {}
    if stix_type == "autonomous-system":
        match = _ASN_NAME_RE.match(str(name))
        if not match:
            logger.debug("dropping ASN node with non-AS-prefixed name: %r", name)
            return None
        props["number"] = int(match.group(1))
        props["name"] = name
    elif stix_type == "location":
        if label == "COUNTRY":
            # Whisper COUNTRY nodes carry ISO 3166-1 alpha-2 codes in `name`
            # (e.g. "US", "GB"). Map to STIX Location's `country` field.
            props["country"] = str(name).upper()
        elif label == "CITY":
            # Whisper CITY format: "<City Name>, <CC>" (e.g. "Mountain View,
            # US"). STIX 2.1 Location requires at least country/region/
            # lat-long, so if we can't extract a country code from the
            # CITY name we drop the node rather than ship something the
            # stix2 builder would reject.
            parts = [p.strip() for p in str(name).rsplit(",", 1)]
            if len(parts) == 2 and len(parts[1]) == 2 and parts[1].isalpha():
                props["city"] = parts[0]
                props["country"] = parts[1].upper()
                props["name"] = str(name)
            else:
                logger.debug(
                    "dropping CITY with unparseable country code suffix: %r", name
                )
                return None
    elif stix_type == "identity":
        # ORGANIZATION and REGISTRAR both surface as Identity SDOs with
        # identity_class="organization". The relationship's description
        # field (set by the edge-mapping path) carries the original
        # Whisper edge type (e.g. REGISTERED_BY) so analysts can tell a
        # registrar apart from an owning organization.
        cleaned = str(name)
        if label == "REGISTRAR":
            # Whisper REGISTRAR names come in two shapes: ``iana:<id>`` (the
            # current registrar, an opaque IANA ID) and ``registrar:<name>``
            # (historical, raw WHOIS string). Resolve both to a display name —
            # the IANA ID via the vendored lookup (issue #61).
            cleaned = resolve_registrar_name(cleaned)
        if not cleaned:
            return None
        props["name"] = cleaned
        props["identity_class"] = "organization"
    else:
        props["value"] = name

    return {"id": cell.get("nodeId"), "type": stix_type, "properties": props}


def _orient_edge(stix_rel: str, src: dict, tgt: dict) -> tuple[dict, dict]:
    expected_sources = _EDGE_DIRECTION_SOURCE.get(stix_rel)
    if not expected_sources:
        return src, tgt
    if src["type"] in expected_sources:
        return src, tgt
    if tgt["type"] in expected_sources:
        return tgt, src
    return src, tgt


def _nearest_node(
    nodes_by_idx: dict[int, dict],
    edge_idx: int,
    direction: int,
) -> dict | None:
    if not nodes_by_idx:
        return None
    indices = sorted(nodes_by_idx.keys())
    if direction < 0:
        candidates = [i for i in indices if i < edge_idx]
        return nodes_by_idx[candidates[-1]] if candidates else None
    candidates = [i for i in indices if i > edge_idx]
    return nodes_by_idx[candidates[0]] if candidates else None

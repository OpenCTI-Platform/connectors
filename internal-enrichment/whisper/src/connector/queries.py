"""Cypher query templates for enriching OpenCTI entities via Whisper.

The templates carry two placeholders, ``$value`` and ``$limit``, both
substituted into the query string client-side at call time. Whisper's Cypher
engine does **not** support bound parameters for value substitution — values
must be inlined as Cypher literals, so ``$value`` is JSON-escaped to safely
produce a double-quoted Cypher string and ``$limit`` is inlined as an integer.
(The HTTP client still sends an empty ``params: {}`` object in the request
body for API-shape compatibility; Whisper ignores it. Do not rely on it to
pass query values.)

Whisper anchors searches on the ``name`` property of typed nodes (IPV4, IPV6,
HOSTNAME, ASN). Main templates use ``-[r]-`` (undirected) and let the result
parser orient STIX relationships based on label semantics.

`LINKS_TO` is excluded from the main query for every seed type — it has
massive fan-out (Whisper has 10.8B `LINKS_TO` edges; google.com alone has
~12M inbound) and direction matters semantically (outbound vs inbound web
hyperlinks have very different meanings to an analyst). The connector
issues two supplementary directed queries per Domain-Name enrichment to
collect a capped sample of each direction (see ``LINKS_TO_QUERIES``).

OpenCTI entity types without a clean Whisper-side equivalent (Url,
StixFile, Email-Addr) are intentionally absent; ``get_query_for_entity_type``
returns ``None`` and the connector skips the enrichment with a clear log
message.
"""

import json

DEFAULT_LIMIT = 50

# Cap on `LINKS_TO` neighbours emitted per direction. Whisper's link graph
# is enormous; analysts want a representative sample, not exhaustive
# enumeration. Issue #48's MVP guidance suggests 25.
LINKS_TO_CAP = 25

# Cap on FEED_SOURCE listings to retrieve for the seed-threat Note. Whisper
# has 40 FEED_SOURCE nodes total, so 100 is effectively "all of them" —
# this is a safety ceiling, not a sampling limit.
THREAT_FEED_LIMIT = 100

# Cap on rows returned by the IP→ASN supplementary query. An IP can be
# announced from multiple ANNOUNCED_PREFIXes (MOAS/anycast), so >1 is
# realistic; 10 is generous. Issue #48 Phase C.
NETWORK_CONTEXT_LIMIT = 10

# Threat-flag boolean fields carried on threat-listed HOSTNAME/IPV4/IPV6
# nodes. Listed in the order they appear in the Note output. Issue #48
# Phase B surfaces these so analysts see the threat context Whisper has
# inferred for the seed.
THREAT_FLAG_FIELDS: tuple[str, ...] = (
    "isThreat",
    "isMalware",
    "isC2",
    "isPhishing",
    "isSpam",
    "isBruteforce",
    "isScanner",
    "isBlacklist",
    "isAnonymizer",
    "isTor",
    "isProxy",
    "isVpn",
    "isWhitelist",
)

# Entity types this connector can enrich. Decoupled from ``QUERIES``
# because Domain-Name no longer rides the broad one-hop template — it uses
# the targeted directional builders below (issue #61) — yet is still very
# much in scope. IP/ASN seeds keep the broad undirected query.
SUPPORTED_ENTITY_TYPES: frozenset[str] = frozenset(
    {"IPv4-Addr", "IPv6-Addr", "Domain-Name", "Autonomous-System"}
)

QUERIES: dict[str, str] = {
    "IPv4-Addr": (
        'MATCH (n:IPV4 {name: $value})-[r]-(m) WHERE type(r) <> "LINKS_TO" '
        "RETURN n, r, m LIMIT $limit"
    ),
    "IPv6-Addr": (
        'MATCH (n:IPV6 {name: $value})-[r]-(m) WHERE type(r) <> "LINKS_TO" '
        "RETURN n, r, m LIMIT $limit"
    ),
    "Autonomous-System": (
        'MATCH (n:ASN {name: $value})-[r]-(m) WHERE type(r) <> "LINKS_TO" '
        "RETURN n, r, m LIMIT $limit"
    ),
}

# Direction-specific `LINKS_TO` templates. Only Domain-Name seeds get
# `LINKS_TO` enrichment because the edge type exists exclusively between
# HOSTNAME nodes in Whisper's schema. ``$cap`` is substituted as an integer
# literal (same inline-only-no-params rule as the main templates).
LINKS_TO_QUERIES: dict[str, dict[str, str]] = {
    "Domain-Name": {
        "outbound": (
            "MATCH (n:HOSTNAME {name: $value})-[r:LINKS_TO]->(m:HOSTNAME) "
            "RETURN n, r, m LIMIT $cap"
        ),
        "inbound": (
            "MATCH (n:HOSTNAME {name: $value})<-[r:LINKS_TO]-(m:HOSTNAME) "
            "RETURN n, r, m LIMIT $cap"
        ),
        "count_outbound": (
            "MATCH (n:HOSTNAME {name: $value})-[r:LINKS_TO]->(m:HOSTNAME) "
            "RETURN count(m) AS c"
        ),
        "count_inbound": (
            "MATCH (n:HOSTNAME {name: $value})<-[r:LINKS_TO]-(m:HOSTNAME) "
            "RETURN count(m) AS c"
        ),
    }
}


def get_query_for_entity_type(
    entity_type: str,
    value: str,
    limit: int = DEFAULT_LIMIT,
) -> str | None:
    """Return a fully-formed Cypher query, or ``None`` if the type is unsupported.

    ``value`` is JSON-escaped and substituted as a double-quoted Cypher string
    literal. ``limit`` is substituted as an integer literal. Whisper's Cypher
    engine rejects request-body parameters, so everything is inlined.
    """
    template = QUERIES.get(entity_type)
    if template is None:
        return None
    if not value:
        raise ValueError("value is required")
    limit_int = int(limit)
    if limit_int < 1:
        raise ValueError(f"limit must be >= 1, got {limit_int}")
    return template.replace("$value", json.dumps(str(value))).replace(
        "$limit", str(limit_int)
    )


# Threat-context supplementary queries. Anchors the threat-listed seed
# node (HOSTNAME / IPV4 / IPV6), then OPTIONAL MATCHes its LISTED_IN edges
# to FEED_SOURCE nodes. Returns one row per feed listing (or a single row
# with null feed fields when the seed has threat properties but isn't
# listed anywhere) — caller is responsible for collapsing into a single
# Note. ASN nodes don't carry these properties in Whisper's schema, so
# Autonomous-System seeds are intentionally omitted.
#
# Like the main templates, ``$value`` and ``$limit`` are substituted as
# Cypher literals client-side (Whisper rejects request-body params).
_THREAT_CONTEXT_RETURN: str = (
    "RETURN "
    "n.threatScore AS threatScore, n.threatLevel AS threatLevel, "
    + ", ".join(f"n.{flag} AS {flag}" for flag in THREAT_FLAG_FIELDS)
    + ", n.threatFirstSeen AS threatFirstSeen, n.threatLastSeen AS threatLastSeen, "
    "f.name AS feedName, r.firstSeen AS feedFirstSeen, "
    "r.lastSeen AS feedLastSeen, r.weight AS feedWeight"
)

THREAT_CONTEXT_QUERIES: dict[str, str] = {
    "IPv4-Addr": (
        "MATCH (n:IPV4 {name: $value}) "
        "OPTIONAL MATCH (n)-[r:LISTED_IN]->(f:FEED_SOURCE) "
        f"{_THREAT_CONTEXT_RETURN} LIMIT $limit"
    ),
    "IPv6-Addr": (
        "MATCH (n:IPV6 {name: $value}) "
        "OPTIONAL MATCH (n)-[r:LISTED_IN]->(f:FEED_SOURCE) "
        f"{_THREAT_CONTEXT_RETURN} LIMIT $limit"
    ),
    "Domain-Name": (
        "MATCH (n:HOSTNAME {name: $value}) "
        "OPTIONAL MATCH (n)-[r:LISTED_IN]->(f:FEED_SOURCE) "
        f"{_THREAT_CONTEXT_RETURN} LIMIT $limit"
    ),
}


def get_threat_context_query(
    entity_type: str,
    value: str,
    limit: int = THREAT_FEED_LIMIT,
) -> str | None:
    """Return the supplementary threat-context Cypher for the seed, or
    ``None`` if the entity type doesn't carry threat properties in Whisper.

    Only HOSTNAME/IPV4/IPV6 are supported — ASN nodes don't have
    threatScore/threatLevel/flags in Whisper's schema.
    """
    template = THREAT_CONTEXT_QUERIES.get(entity_type)
    if template is None:
        return None
    if not value:
        raise ValueError("value is required")
    limit_int = int(limit)
    if limit_int < 1:
        raise ValueError(f"limit must be >= 1, got {limit_int}")
    return template.replace("$value", json.dumps(str(value))).replace(
        "$limit", str(limit_int)
    )


# IP → ASN/prefix supplementary query. Anchors on the seed IPv4/IPv6 node,
# walks ANNOUNCED_BY→ANNOUNCED_PREFIX→ROUTES→ASN to derive the announcing
# AS (intentional 2-hop chain — IPs don't connect directly to ASNs in
# Whisper's schema), then OPTIONAL-MATCHes the ASN's HAS_NAME human label
# and the IP's static-allocation PREFIX. Returns ``ip`` and ``asn`` as full
# node cells so the caller can lift Whisper nodeIds for edge wiring;
# everything else comes back as flat columns the caller folds into a Note.
#
# Skipped for Domain-Name and Autonomous-System seeds — for Domain-Name
# the network context lives on the resolved IPs (analyst can pivot), and
# Autonomous-System seeds already ARE the ASN.
NETWORK_CONTEXT_QUERIES: dict[str, str] = {
    "IPv4-Addr": (
        "MATCH (ip:IPV4 {name: $value})-[:ANNOUNCED_BY]->(ap:ANNOUNCED_PREFIX)"
        "-[:ROUTES]->(asn:ASN) "
        "OPTIONAL MATCH (asn)-[:HAS_NAME]->(asn_name:ASN_NAME) "
        "OPTIONAL MATCH (ip)-[:BELONGS_TO]->(p:PREFIX) "
        "RETURN ip AS seed, asn AS asn, "
        "asn_name.name AS asnDescription, "
        "ap.name AS announcedPrefix, "
        "ap.threatScore AS apThreatScore, "
        "ap.threatLevel AS apThreatLevel, "
        "ap.isAnycast AS isAnycast, "
        "ap.isMoas AS isMoas, "
        "ap.isWithdrawn AS isWithdrawn, "
        "p.name AS prefix "
        "LIMIT $limit"
    ),
    "IPv6-Addr": (
        "MATCH (ip:IPV6 {name: $value})-[:ANNOUNCED_BY]->(ap:ANNOUNCED_PREFIX)"
        "-[:ROUTES]->(asn:ASN) "
        "OPTIONAL MATCH (asn)-[:HAS_NAME]->(asn_name:ASN_NAME) "
        "OPTIONAL MATCH (ip)-[:BELONGS_TO]->(p:PREFIX) "
        "RETURN ip AS seed, asn AS asn, "
        "asn_name.name AS asnDescription, "
        "ap.name AS announcedPrefix, "
        "ap.threatScore AS apThreatScore, "
        "ap.threatLevel AS apThreatLevel, "
        "ap.isAnycast AS isAnycast, "
        "ap.isMoas AS isMoas, "
        "ap.isWithdrawn AS isWithdrawn, "
        "p.name AS prefix "
        "LIMIT $limit"
    ),
}


def get_network_context_query(
    entity_type: str,
    value: str,
    limit: int = NETWORK_CONTEXT_LIMIT,
) -> str | None:
    """Return the IP→ASN/prefix supplementary Cypher, or ``None`` if the
    entity type doesn't carry one (Domain-Name and Autonomous-System).
    """
    template = NETWORK_CONTEXT_QUERIES.get(entity_type)
    if template is None:
        return None
    if not value:
        raise ValueError("value is required")
    limit_int = int(limit)
    if limit_int < 1:
        raise ValueError(f"limit must be >= 1, got {limit_int}")
    return template.replace("$value", json.dumps(str(value))).replace(
        "$limit", str(limit_int)
    )


def get_links_to_queries(
    entity_type: str,
    value: str,
    cap: int = LINKS_TO_CAP,
) -> dict[str, str] | None:
    """Return the four `LINKS_TO` queries (outbound/inbound + count for each)
    for an entity type, or ``None`` if `LINKS_TO` enrichment doesn't apply
    to that type.

    Only Domain-Name seeds get this — `LINKS_TO` is a HOSTNAME→HOSTNAME edge
    in Whisper's schema.
    """
    templates = LINKS_TO_QUERIES.get(entity_type)
    if templates is None:
        return None
    if not value:
        raise ValueError("value is required")
    cap_int = int(cap)
    if cap_int < 1:
        raise ValueError(f"cap must be >= 1, got {cap_int}")
    return {
        key: tpl.replace("$value", json.dumps(str(value))).replace("$cap", str(cap_int))
        for key, tpl in templates.items()
    }


# ---------------------------------------------------------------------------
# Targeted Domain-Name enrichment (issue #61)
#
# Domain-Name seeds no longer use a broad undirected one-hop query. Instead
# the connector issues one directional query per enrichment category, so the
# output is deterministic and each relationship carries a stable,
# analyst-readable description rather than a raw Whisper edge name. Each
# template returns ``h`` (the seed) and ``m`` (the neighbour) as full node
# cells; the connector builds the STIX relationship explicitly with the
# description key.
# ---------------------------------------------------------------------------

# Per-category cap for direct-fact categories (A/AAAA/CNAME/NS/MX/…). These
# describe the seed itself and are normally small, but RESOLVES_TO fan-out
# (CDNs) and multi-NS setups can run to dozens; 50 is generous headroom.
DOMAIN_FACT_LIMIT = 50

# Cap for "capped pivot" categories — related infrastructure reachable from
# the seed (domains the seed is NS/MX for, subdomains, inbound CNAMEs). These
# can be enormous (a popular MX serves millions of domains), so they are
# capped and the connector attaches an overflow Note when the true count
# exceeds the cap.
DOMAIN_PIVOT_CAP = 25

# Cap on SPF policy targets and WHOIS phone rows folded into their Notes.
SPF_LIMIT = 100
WHOIS_PHONE_LIMIT = 25

# Upper bound on generated lookalike candidates checked for existence in one
# query. Keeps the inlined UNWIND list bounded.
DOMAIN_VARIANT_CANDIDATE_CAP = 200

# Direct-fact categories: description -> cypher template returning ``h, m``.
# Direction in the MATCH reflects Whisper's stored edge direction (NS/MX
# edges point neighbour->seed, so the seed's own records are matched with
# ``<-``). The emitted STIX relationship is always seed -> neighbour
# regardless, carrying the description key (issue #61 AC).
#
# Order is load-bearing: ``registrar`` must precede ``previous-registrar``.
# A registrar that is both the current and a historical registrar shows up
# as the SAME Whisper REGISTRAR node under both HAS_REGISTRAR and
# PREV_REGISTRAR. The connector dedupes edges by (source, target, type) with
# first-writer-wins, so emitting ``registrar`` first keeps the current-state
# description instead of letting ``previous-registrar`` overwrite it. See
# ``WhisperConnector._collect_domain_enrichment``'s ``add_edge``.
DOMAIN_DIRECT_FACT_QUERIES: dict[str, str] = {
    "a-record": (
        "MATCH (h:HOSTNAME {name: $value})-[:RESOLVES_TO]->(m:IPV4) "
        "RETURN h, m LIMIT $limit"
    ),
    "aaaa-record": (
        "MATCH (h:HOSTNAME {name: $value})-[:RESOLVES_TO]->(m:IPV6) "
        "RETURN h, m LIMIT $limit"
    ),
    "cname": (
        "MATCH (h:HOSTNAME {name: $value})-[:ALIAS_OF]->(m:HOSTNAME) "
        "RETURN h, m LIMIT $limit"
    ),
    "name-server": (
        "MATCH (h:HOSTNAME {name: $value})<-[:NAMESERVER_FOR]-(m:HOSTNAME) "
        "RETURN h, m LIMIT $limit"
    ),
    "mx-server": (
        "MATCH (h:HOSTNAME {name: $value})<-[:MAIL_FOR]-(m:HOSTNAME) "
        "RETURN h, m LIMIT $limit"
    ),
    "registrar": (
        "MATCH (h:HOSTNAME {name: $value})-[:HAS_REGISTRAR]->(m:REGISTRAR) "
        "RETURN h, m LIMIT $limit"
    ),
    "previous-registrar": (
        "MATCH (h:HOSTNAME {name: $value})-[:PREV_REGISTRAR]->(m:REGISTRAR) "
        "RETURN h, m LIMIT $limit"
    ),
    "registered-by": (
        "MATCH (h:HOSTNAME {name: $value})-[:REGISTERED_BY]->(m:ORGANIZATION) "
        "RETURN h, m LIMIT $limit"
    ),
    "whois-email": (
        "MATCH (h:HOSTNAME {name: $value})-[:HAS_EMAIL]->(m:EMAIL) "
        "RETURN h, m LIMIT $limit"
    ),
}

# Capped-pivot categories: description -> {"rows": cypher, "count": cypher}.
# ``rows`` returns ``h, m`` capped at $cap; ``count`` returns the total ``c``
# so the connector can report overflow in a Note.
DOMAIN_PIVOT_QUERIES: dict[str, dict[str, str]] = {
    "nameserver-for-domain": {
        "rows": (
            "MATCH (h:HOSTNAME {name: $value})-[:NAMESERVER_FOR]->(m:HOSTNAME) "
            "RETURN h, m LIMIT $cap"
        ),
        "count": (
            "MATCH (h:HOSTNAME {name: $value})-[:NAMESERVER_FOR]->(m:HOSTNAME) "
            "RETURN count(m) AS c"
        ),
    },
    "mail-server-for-domain": {
        "rows": (
            "MATCH (h:HOSTNAME {name: $value})-[:MAIL_FOR]->(m:HOSTNAME) "
            "RETURN h, m LIMIT $cap"
        ),
        "count": (
            "MATCH (h:HOSTNAME {name: $value})-[:MAIL_FOR]->(m:HOSTNAME) "
            "RETURN count(m) AS c"
        ),
    },
    "subdomain": {
        "rows": (
            "MATCH (h:HOSTNAME {name: $value})<-[:CHILD_OF]-(m:HOSTNAME) "
            "RETURN h, m LIMIT $cap"
        ),
        "count": (
            "MATCH (h:HOSTNAME {name: $value})<-[:CHILD_OF]-(m:HOSTNAME) "
            "RETURN count(m) AS c"
        ),
    },
    "cname-pointing-to-seed": {
        "rows": (
            "MATCH (h:HOSTNAME {name: $value})<-[:ALIAS_OF]-(m:HOSTNAME) "
            "RETURN h, m LIMIT $cap"
        ),
        "count": (
            "MATCH (h:HOSTNAME {name: $value})<-[:ALIAS_OF]-(m:HOSTNAME) "
            "RETURN count(m) AS c"
        ),
    },
}

# SPF policy: all SPF_* edges from the seed in one pass. Returns the edge
# type (so the Note distinguishes include:/ip4:/a:/mx:) and the target name.
SPF_POLICY_QUERY: str = (
    "MATCH (h:HOSTNAME {name: $value})-[r]->(m) "
    'WHERE type(r) STARTS WITH "SPF_" '
    "RETURN type(r) AS spfType, m.name AS target LIMIT $limit"
)

# WHOIS phone contacts → Note.
WHOIS_PHONE_QUERY: str = (
    "MATCH (h:HOSTNAME {name: $value})-[:HAS_PHONE]->(p:PHONE) "
    "RETURN p.name AS phone LIMIT $limit"
)


def _inline(template: str, value: str, **int_placeholders: int) -> str:
    """Inline ``$value`` (JSON-escaped) and integer ``$<name>`` placeholders.

    Whisper's Cypher engine rejects request-body parameters, so everything is
    substituted as a literal. Integers are validated >= 1 (mirrors the guards
    on the original builders).
    """
    if not value:
        raise ValueError("value is required")
    out = template.replace("$value", json.dumps(str(value)))
    for name, raw in int_placeholders.items():
        n = int(raw)
        if n < 1:
            raise ValueError(f"{name} must be >= 1, got {n}")
        out = out.replace(f"${name}", str(n))
    return out


def get_domain_direct_fact_queries(
    value: str,
    limit: int = DOMAIN_FACT_LIMIT,
) -> dict[str, str]:
    """Return ``{description: cypher}`` for every direct-fact category."""
    return {
        desc: _inline(tpl, value, limit=limit)
        for desc, tpl in DOMAIN_DIRECT_FACT_QUERIES.items()
    }


def get_domain_pivot_queries(
    value: str,
    cap: int = DOMAIN_PIVOT_CAP,
) -> dict[str, dict[str, str]]:
    """Return ``{description: {"rows": cypher, "count": cypher}}`` per pivot."""
    return {
        desc: {
            "rows": _inline(q["rows"], value, cap=cap),
            "count": _inline(q["count"], value),
        }
        for desc, q in DOMAIN_PIVOT_QUERIES.items()
    }


def get_spf_policy_query(value: str, limit: int = SPF_LIMIT) -> str:
    """Return the SPF-policy Cypher for the seed."""
    return _inline(SPF_POLICY_QUERY, value, limit=limit)


def get_whois_phone_query(value: str, limit: int = WHOIS_PHONE_LIMIT) -> str:
    """Return the WHOIS-phone Cypher for the seed."""
    return _inline(WHOIS_PHONE_QUERY, value, limit=limit)


# --- Lookalike generation (issue #61 AC #15) -------------------------------
#
# Whisper has no LOOKALIKE_OF edge, so the connector generates typosquat
# candidates in-process and confirms which exist as HOSTNAME nodes with one
# existence query. This is a bounded subset of the algorithms the Whisper
# ``domain_variants`` endpoint runs (which the connector can't call — it only
# speaks Cypher to ``/api/query``).

_HOMOGLYPHS: dict[str, str] = {
    "o": "0",
    "0": "o",
    "l": "1",
    "i": "1",
    "e": "3",
    "s": "5",
    "a": "4",
}
_VARIANT_TLDS: tuple[str, ...] = (
    "com",
    "net",
    "org",
    "io",
    "co",
    "info",
    "biz",
    "app",
    "dev",
    "me",
    "online",
    "xyz",
    "top",
)
# Per-method confidence, roughly aligned with the Whisper domain_variants
# scale. Surfaced in the lookalikes Note so analysts can triage.
_METHOD_CONFIDENCE: dict[str, float] = {
    "homoglyph": 0.9,
    "omission": 0.7,
    "transposition": 0.7,
    "repetition": 0.7,
    "tld-swap": 0.5,
    "hyphenation": 0.3,
}


def generate_domain_variants(
    name: str,
    cap: int = DOMAIN_VARIANT_CANDIDATE_CAP,
) -> list[dict]:
    """Generate typosquat candidates for ``name``.

    Returns up to ``cap`` ``{"variant", "method", "confidence"}`` dicts,
    deduplicated and excluding the input itself. Mutations are applied to the
    label before the final dot (a naive SLD split — good enough; the existence
    check filters to registered candidates regardless). The empty list is
    returned for inputs without a dot.
    """
    name = (name or "").strip().lower()
    if "." not in name:
        return []
    sld, _, tld = name.rpartition(".")
    if not sld:
        return []

    variants: dict[str, tuple[str, float]] = {}

    def add(variant: str, method: str) -> None:
        if variant and variant != name and variant not in variants:
            variants[variant] = (method, _METHOD_CONFIDENCE[method])

    for i in range(len(sld)):  # omission
        add(f"{sld[:i]}{sld[i + 1:]}.{tld}", "omission")
    for i in range(len(sld) - 1):  # transposition of adjacent chars
        add(f"{sld[:i]}{sld[i + 1]}{sld[i]}{sld[i + 2:]}.{tld}", "transposition")
    for i in range(len(sld)):  # repetition (double a char)
        add(f"{sld[: i + 1]}{sld[i]}{sld[i + 1:]}.{tld}", "repetition")
    for i, ch in enumerate(sld):  # homoglyph substitution
        if ch in _HOMOGLYPHS:
            add(f"{sld[:i]}{_HOMOGLYPHS[ch]}{sld[i + 1:]}.{tld}", "homoglyph")
    for i in range(1, len(sld)):  # hyphenation
        add(f"{sld[:i]}-{sld[i:]}.{tld}", "hyphenation")
    for alt in _VARIANT_TLDS:  # TLD swap
        if alt != tld:
            add(f"{sld}.{alt}", "tld-swap")

    out = [
        {"variant": v, "method": m, "confidence": c} for v, (m, c) in variants.items()
    ]
    return out[:cap]


def get_variant_existence_query(candidates: list[str]) -> str | None:
    """Return a single Cypher query confirming which ``candidates`` exist as
    HOSTNAME nodes, or ``None`` when there are no candidates.

    Uses ``UNWIND`` over an inlined literal list so each lookup hits the
    ``name`` index (Whisper rejects request-body params).
    """
    names = [c for c in candidates if c]
    if not names:
        return None
    inlined = ", ".join(json.dumps(n) for n in names)
    return (
        f"UNWIND [{inlined}] AS candidate "
        "MATCH (h:HOSTNAME {name: candidate}) RETURN h.name AS name"
    )


def supported_entity_types() -> set[str]:
    """Return the OpenCTI entity types this connector can enrich."""
    return set(SUPPORTED_ENTITY_TYPES)

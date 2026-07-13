import re
from datetime import UTC, datetime

import stix2
from connector.converter_to_stix import build_bundle, build_note
from connector.exceptions import StixMappingError, WhisperClientError, WhisperTlpError
from connector.queries import (
    DEFAULT_LIMIT,
    DOMAIN_PIVOT_CAP,
    LINKS_TO_CAP,
    THREAT_FLAG_FIELDS,
    generate_domain_variants,
    get_domain_direct_fact_queries,
    get_domain_pivot_queries,
    get_links_to_queries,
    get_network_context_query,
    get_query_for_entity_type,
    get_spf_policy_query,
    get_threat_context_query,
    get_variant_existence_query,
    get_whois_phone_query,
    supported_entity_types,
)
from connector.result_parser import (
    collect_dropped_hostnames,
    parse_cypher_result,
    translate_node_cell,
)
from connector.settings import ConnectorSettings
from connector.whisper_client import WhisperClient
from pycti import OpenCTIConnectorHelper

_ASN_NAME_RE = re.compile(r"^AS(\d+)$", re.IGNORECASE)


def _append_prefix_block(lines: list[str], announcer: dict, indent: str) -> None:
    """Append the per-announcer prefix/BGP/threat lines to ``lines``.

    Extracted so single-AS and MOAS branches share the same formatting.
    """
    if announcer.get("prefix"):
        lines.append(f"{indent}Announced prefix: {announcer['prefix']}")
    flag_parts: list[str] = []
    if announcer.get("anycast"):
        flag_parts.append("anycast")
    if announcer.get("moas"):
        flag_parts.append("MOAS")
    if announcer.get("withdrawn"):
        flag_parts.append("withdrawn")
    if flag_parts:
        lines.append(f"{indent}BGP flags: {', '.join(flag_parts)}")
    score = announcer.get("score")
    level = announcer.get("level")
    if level and level != "NONE":
        if isinstance(score, (int, float)):
            lines.append(f"{indent}ANNOUNCED_PREFIX threat: {level} (score {score:g})")
        else:
            lines.append(f"{indent}ANNOUNCED_PREFIX threat: {level}")


class WhisperConnector:
    """OpenCTI internal-enrichment connector for the Whisper graph.

    For each enrichment request, resolves the observable, runs the matching
    Cypher template against Whisper, translates the result into a STIX 2.1
    bundle, and sends it to OpenCTI for ingestion.
    """

    def __init__(
        self,
        helper: OpenCTIConnectorHelper,
        config: ConnectorSettings,
        client: WhisperClient | None = None,
    ) -> None:
        """Construct the connector with externally-built helper and settings.

        ``main.py`` builds both the helper and the ``ConnectorSettings`` from
        the connectors-sdk; the connector consumes the typed ``whisper:`` block
        (``api_url``, ``api_key``, ``max_tlp``). ``client`` is injectable for
        tests; production passes a freshly-built ``WhisperClient``.
        """
        self.helper = helper
        self.config = config
        self.client = client or WhisperClient(
            api_url=config.whisper.api_url,
            api_key=config.whisper.api_key.get_secret_value(),
        )

    @staticmethod
    def _seed_stix_id(
        entity_type: str, entity_value: str, observable: dict
    ) -> str | None:
        """Derive the deterministic STIX SCO id for the seed observable.

        Mirrors what `converter_to_stix`'s node mappers produce. Used by `build_note`
        callers when they need to attach a Note to the seed without having
        the SCO object in hand.
        """
        try:
            if entity_type == "IPv4-Addr":
                return stix2.IPv4Address(value=entity_value).id
            if entity_type == "IPv6-Addr":
                return stix2.IPv6Address(value=entity_value).id
            if entity_type == "Domain-Name":
                return stix2.DomainName(value=entity_value).id
            if entity_type == "Autonomous-System":
                number = observable.get("number")
                if number is not None:
                    return stix2.AutonomousSystem(number=int(number)).id
        except (
            Exception
        ):  # noqa: BLE001 — defensive; never fail the enrichment over this
            return None
        return None

    def _is_entity_in_scope(self, entity_type: str) -> bool:
        """Whether ``entity_type`` has a Whisper Cypher template.

        Mirrors the ``QUERIES`` keyset; we don't read ``helper.connect_scope``
        because the scope env var may legitimately be a superset (the
        operator might enable the connector for ``Url`` even though we
        return ``not supported``, just to discover supported types).
        """
        return entity_type in supported_entity_types()

    def _extract_and_check_markings(self, observable: dict) -> None:
        """Refuse to enrich if the observable's TLP marking exceeds
        ``whisper.max_tlp``. Pulled from the shodan-internetdb pattern.

        The connector's Whisper API key effectively grants access to
        whatever the OpenCTI user it impersonates can see; enriching past
        the TLP ceiling would leak intel to a less-trusted Whisper
        account. Raises ``WhisperTlpError`` on violation.
        """
        max_tlp = self.config.whisper.max_tlp
        for marking in observable.get("objectMarking", []) or []:
            if marking.get("definition_type") == "TLP" and not (
                OpenCTIConnectorHelper.check_max_tlp(
                    tlp=marking["definition"], max_tlp=max_tlp
                )
            ):
                raise WhisperTlpError(
                    f"observable TLP marking {marking['definition']!r} "
                    f"exceeds whisper.max_tlp={max_tlp!r}"
                )

    def _send_passthrough_bundle(self, stix_objects: list) -> str:
        """Re-ship the worker-supplied bundle unchanged.

        Used in two cases under v7 ``playbook_compatible=True``:
        1. Out-of-scope entity arriving via a playbook chain (no
           ``event_type``) — downstream playbook nodes would lose data
           if we returned an empty bundle.
        2. Defensive default for any unanticipated playbook routing.
        """
        if not stix_objects:
            return "playbook pass-through: no stix_objects to forward"
        bundle = self.helper.stix2_create_bundle(stix_objects)
        self.helper.send_stix2_bundle(bundle, cleanup_inconsistent_bundle=True)
        return f"playbook pass-through: forwarded {len(stix_objects)} STIX object(s)"

    def _process_message(self, data: dict) -> str:
        """v7 internal-enrichment callback.

        The data dict carries everything we need — pycti 7.x hands us
        the enrichment entity, its STIX form, and the bundle's stix
        objects directly, removing the need for a separate
        ``helper.api.stix_cyber_observable.read()`` round-trip.

        Flow:
        1. TLP check → refuse if observable marking exceeds max_tlp.
        2. Scope check → for unsupported types, either return a clear
           status (real-time event) or pass through the original bundle
           (playbook chain).
        3. Delegate to ``_enrich_observable`` for the real enrichment.
        """
        observable = data.get("enrichment_entity") or {}
        stix_objects = data.get("stix_objects") or []
        if not observable:
            return "missing enrichment_entity in v7 callback payload"

        try:
            self._extract_and_check_markings(observable)
        except WhisperTlpError as exc:
            self.helper.connector_logger.warning(
                "Refusing to enrich — TLP exceeds whisper.max_tlp",
                {"entity_id": observable.get("id"), "error": str(exc)},
            )
            return str(exc)

        entity_type = observable.get("entity_type") or ""
        if not self._is_entity_in_scope(entity_type):
            if data.get("event_type"):
                # Real-time enrichment request: tell the analyst the type
                # isn't supported, don't ship a bundle.
                return (
                    f"entity type {entity_type!r} not supported by Whisper enrichment"
                )
            # Playbook chain: forward the original bundle so downstream
            # nodes see the entity untouched. This is the v7
            # playbook_compatible=True contract.
            return self._send_passthrough_bundle(stix_objects)

        return self._enrich_observable(observable)

    def run(self) -> None:
        """Block on the OpenCTI queue, dispatching ``_process_message``
        for each enrichment request. Called from ``main.py`` after the
        helper has been built.
        """
        self.helper.listen(message_callback=self._process_message)

    def _collect_links_to(
        self,
        entity_type: str,
        entity_value: str,
        observable: dict,
    ) -> tuple[list[dict], list[dict], list[stix2.Note]]:
        """For Domain-Name seeds, run the directed `LINKS_TO` queries and
        return (extra_nodes, extra_edges, cap_overflow_notes).

        Outbound edges are tagged ``description="links-to-outbound"``.
        Inbound edges have their source/target swapped (since the parser
        column-position default puts the seed on the source side, but the
        inbound semantic is neighbour→seed) and tagged ``"links-to-inbound"``.

        If Whisper has more `LINKS_TO` than the cap in either direction,
        a STIX Note is emitted attached to the seed reporting the overflow.
        """
        queries = get_links_to_queries(entity_type, entity_value, cap=LINKS_TO_CAP)
        if queries is None:
            return [], [], []

        extra_nodes: list[dict] = []
        extra_edges: list[dict] = []
        notes: list[stix2.Note] = []

        for direction in ("outbound", "inbound"):
            result = self.client.execute_cypher(queries[direction])
            dir_nodes, dir_edges = parse_cypher_result(result)
            for edge in dir_edges:
                if direction == "inbound":
                    # Swap source/target so the relationship correctly reads
                    # neighbour → seed instead of seed → neighbour.
                    edge["source_id"], edge["target_id"] = (
                        edge["target_id"],
                        edge["source_id"],
                    )
                edge["properties"] = {"description": f"links-to-{direction}"}
            extra_nodes.extend(dir_nodes)
            extra_edges.extend(dir_edges)

        # Count overflow → Note attached to the seed.
        seed_stix_id = self._seed_stix_id(entity_type, entity_value, observable)
        if seed_stix_id:
            overflow_messages: list[str] = []
            for direction in ("outbound", "inbound"):
                count_result = self.client.execute_cypher(queries[f"count_{direction}"])
                count = (
                    count_result.rows[0].get("c")
                    if count_result.rows and isinstance(count_result.rows[0], dict)
                    else 0
                )
                if isinstance(count, int) and count > LINKS_TO_CAP:
                    overflow_messages.append(
                        f"Whisper found {count} {direction} LINKS_TO neighbours; "
                        f"showing first {LINKS_TO_CAP}."
                    )
            if overflow_messages:
                notes.append(
                    build_note(
                        seed_stix_id=seed_stix_id,
                        content="\n".join(overflow_messages),
                        abstract="LINKS_TO neighbour overflow",
                    )
                )

        return extra_nodes, extra_edges, notes

    @staticmethod
    def _epoch_ms_to_iso(value: object) -> str | None:
        """Format a Whisper millisecond-epoch timestamp as ISO 8601 UTC.

        Returns ``None`` if the value isn't a positive integer/float — keeps
        the formatter robust against the LISTED_IN edges that carry null
        firstSeen/lastSeen for some feeds.
        """
        if not isinstance(value, (int, float)) or value <= 0:
            return None
        try:
            return datetime.fromtimestamp(value / 1000, tz=UTC).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            )
        except (ValueError, OSError, OverflowError):
            return None

    @staticmethod
    def _format_threat_content(first_row: dict, feeds: list[dict]) -> str:
        """Render the threat-intel Note content from one parsed result.

        ``first_row`` carries the seed-level threat fields (threatScore,
        threatLevel, the 13 boolean flags, threatFirstSeen, threatLastSeen).
        ``feeds`` is the de-duplicated list of FEED_SOURCE listings.
        """
        lines: list[str] = []
        score = first_row.get("threatScore")
        level = first_row.get("threatLevel")
        if score is not None or (level and level != "NONE"):
            level_part = level or "UNKNOWN"
            if isinstance(score, (int, float)):
                lines.append(f"Threat assessment: {level_part} (score {score:g})")
            else:
                lines.append(f"Threat assessment: {level_part}")

        first_seen = WhisperConnector._epoch_ms_to_iso(first_row.get("threatFirstSeen"))
        last_seen = WhisperConnector._epoch_ms_to_iso(first_row.get("threatLastSeen"))
        if first_seen or last_seen:
            lines.append(
                f"First seen: {first_seen or '?'}   Last seen: {last_seen or '?'}"
            )

        true_flags = [flag for flag in THREAT_FLAG_FIELDS if first_row.get(flag)]
        if true_flags:
            lines.append("Flags: " + ", ".join(true_flags))

        if feeds:
            lines.append(f"Listed in {len(feeds)} source(s):")
            for feed in feeds:
                feed_line = f"  - {feed['name']}"
                seen = []
                fs = WhisperConnector._epoch_ms_to_iso(feed.get("firstSeen"))
                ls = WhisperConnector._epoch_ms_to_iso(feed.get("lastSeen"))
                if fs:
                    seen.append(f"first {fs}")
                if ls:
                    seen.append(f"last {ls}")
                if seen:
                    feed_line += " (" + ", ".join(seen) + ")"
                lines.append(feed_line)

        return "\n".join(lines)

    @staticmethod
    def _format_dropped_hostnames_content(dropped: list[dict]) -> str:
        """Render the Note content listing HOSTNAME records the parser
        dropped for failing the RFC 1035 check.

        Dedupes by name across rows (the helper dedupes per-row but the
        same name can appear in multiple rows via different edges) and
        keeps the first edge type seen. Stable ordering by first
        occurrence so the Note content is deterministic and the UUIDv5
        on `build_note` idempotently dedupes in OpenCTI.
        """
        seen: set[str] = set()
        unique: list[dict] = []
        for entry in dropped:
            name = entry.get("name", "")
            if not name or name in seen:
                continue
            seen.add(name)
            unique.append(entry)
        lines = [
            "Whisper returned the following DNS record names that don't conform "
            "to RFC 1035 and were not included as STIX domain-name observables:",
            "",
        ]
        for entry in unique:
            edge = entry.get("edge_type") or "(unknown edge)"
            lines.append(f"  - {entry['name']}  (Whisper edge: {edge})")
        return "\n".join(lines)

    def _collect_threat_context(
        self,
        entity_type: str,
        entity_value: str,
        observable: dict,
        abstract: str = "Whisper threat intelligence",
        caveat: str | None = None,
    ) -> list[stix2.Note]:
        """Return a list with one ``stix2.Note`` if Whisper has threat-feed
        evidence for the seed, otherwise an empty list.

        ``abstract`` and ``caveat`` let the Domain-Name path (issue #61 AC #12)
        render the same threat data under the abstract ``Whisper threat feed
        evidence`` with the "score is not an authoritative verdict" caveat,
        while IP seeds keep the original ``Whisper threat intelligence`` Note.

        Skips when:
        - the entity type doesn't carry threat properties (ASN today),
        - Whisper has no record of the seed at all,
        - the seed has no score, no notable level, no true flags, and no
          feed listings (i.e. a Note would convey nothing).

        Best-effort: caller wraps in a try/except so a failure here can't
        sink the main enrichment.
        """
        query = get_threat_context_query(entity_type, entity_value)
        if query is None:
            return []

        result = self.client.execute_cypher(query)
        if not result.rows:
            return []

        first_row = result.rows[0]
        # Each row repeats the seed-level fields and adds one feed listing
        # (or a single all-null row when OPTIONAL MATCH found no feeds).
        # Dedup feeds by name so a noisy graph that double-lists the seed
        # in one source doesn't produce duplicate Note lines.
        feeds_by_name: dict[str, dict] = {}
        for row in result.rows:
            name = row.get("feedName")
            if not name or name in feeds_by_name:
                continue
            feeds_by_name[name] = {
                "name": name,
                "firstSeen": row.get("feedFirstSeen"),
                "lastSeen": row.get("feedLastSeen"),
                "weight": row.get("feedWeight"),
            }
        feeds = list(feeds_by_name.values())

        score = first_row.get("threatScore")
        level = first_row.get("threatLevel")
        has_score = isinstance(score, (int, float)) and score > 0
        has_level = bool(level) and level != "NONE"
        has_flags = any(first_row.get(flag) for flag in THREAT_FLAG_FIELDS)
        if not (has_score or has_level or has_flags or feeds):
            return []

        seed_stix_id = self._seed_stix_id(entity_type, entity_value, observable)
        if seed_stix_id is None:
            return []

        content = self._format_threat_content(first_row, feeds)
        if not content:
            return []
        if caveat:
            content = f"{content}\n\n{caveat}"

        return [
            build_note(
                seed_stix_id=seed_stix_id,
                content=content,
                abstract=abstract,
            )
        ]

    @staticmethod
    def _format_network_content(
        announcers: list[dict],
        static_prefixes: set[str],
    ) -> str:
        """Render the network-context Note content from collected announcers."""
        lines: list[str] = []
        if len(announcers) == 1:
            a = announcers[0]
            label = f"AS{a['asn_number']}"
            if a.get("description"):
                label += f" ({a['description']})"
            lines.append(f"Announced by: {label}")
            _append_prefix_block(lines, a, indent="")
        elif announcers:
            lines.append(
                f"Announced by {len(announcers)} ASN(s) — multi-origin (MOAS):"
            )
            for a in announcers:
                label = f"AS{a['asn_number']}"
                if a.get("description"):
                    label += f" ({a['description']})"
                lines.append(f"  - {label}")
                _append_prefix_block(lines, a, indent="    ")

        unannounced_static = {
            p
            for p in static_prefixes
            if not any(p == a.get("prefix") for a in announcers)
        }
        if unannounced_static:
            lines.append("Static allocation: " + ", ".join(sorted(unannounced_static)))

        return "\n".join(lines)

    def _collect_network_context(
        self,
        entity_type: str,
        entity_value: str,
        observable: dict,
    ) -> tuple[list[dict], list[dict], list[stix2.Note]]:
        """For IPv4/IPv6 seeds, derive announcing-ASN context.

        Returns (extra_nodes, extra_edges, notes). The Autonomous-System SCO
        is synthesized from the ASN node returned by the supplementary
        query (Whisper nodeId preserved for idempotent dedup), and an
        IP→AS `related-to` edge with ``description="ANNOUNCED_BY"`` ties
        them together. Prefix-level details (announced prefix, BGP flags,
        ANNOUNCED_PREFIX threat score) collapse into a single Note attached
        to the seed — there's no clean STIX SCO for a CIDR network.

        Best-effort: caller wraps in try/except so a transport failure
        here can't kill the main bundle or the other supplementary Notes.
        """
        query = get_network_context_query(entity_type, entity_value)
        if query is None:
            return [], [], []

        result = self.client.execute_cypher(query)
        if not result.rows:
            return [], [], []

        seed_stix_id = self._seed_stix_id(entity_type, entity_value, observable)
        # Aggregate by ASN Whisper nodeId so MOAS rows for the same ASN
        # collapse into a single announcer entry — keeps the Note clean
        # when Whisper has multiple ANNOUNCED_PREFIXes that share an AS.
        announcers_by_id: dict[str, dict] = {}
        static_prefixes: set[str] = set()
        seed_whisper_id: str | None = None
        seed_whisper_name: str | None = None
        seed_whisper_label: str | None = None

        for row in result.rows:
            seed_cell = row.get("seed")
            asn_cell = row.get("asn")
            if isinstance(seed_cell, dict) and seed_whisper_id is None:
                seed_whisper_id = seed_cell.get("nodeId")
                seed_whisper_name = seed_cell.get("name")
                seed_whisper_label = seed_cell.get("label")
            if not isinstance(asn_cell, dict):
                continue
            asn_id = asn_cell.get("nodeId")
            asn_name_str = asn_cell.get("name")  # "AS15169"
            if not asn_id or not asn_name_str:
                continue
            match = _ASN_NAME_RE.match(str(asn_name_str))
            if not match:
                continue
            asn_number = int(match.group(1))
            announcer = announcers_by_id.setdefault(
                asn_id,
                {
                    "asn_id": asn_id,
                    "asn_name": asn_name_str,
                    "asn_number": asn_number,
                    "description": row.get("asnDescription"),
                    "prefix": row.get("announcedPrefix"),
                    "score": row.get("apThreatScore"),
                    "level": row.get("apThreatLevel"),
                    "anycast": row.get("isAnycast"),
                    "moas": row.get("isMoas"),
                    "withdrawn": row.get("isWithdrawn"),
                },
            )
            if not announcer.get("description") and row.get("asnDescription"):
                announcer["description"] = row.get("asnDescription")
            if row.get("prefix"):
                static_prefixes.add(row.get("prefix"))

        if not announcers_by_id:
            return [], [], []

        # Synthesize the seed IP node so any edge we emit has a matching
        # entry in `nodes` — covers the case where the main query returned
        # no rows for this IP (e.g. an IP with only ANNOUNCED_PREFIX/PREFIX
        # neighbours, all of which the parser drops).
        extra_nodes: list[dict] = []
        if seed_whisper_id and seed_whisper_name:
            stix_type = "ipv4-addr" if seed_whisper_label == "IPV4" else "ipv6-addr"
            extra_nodes.append(
                {
                    "id": seed_whisper_id,
                    "type": stix_type,
                    "properties": {"value": seed_whisper_name},
                }
            )

        extra_edges: list[dict] = []
        for announcer in announcers_by_id.values():
            # The AS SCO's `name` is the human-readable label (ASN_NAME via
            # HAS_NAME) when Whisper has one, otherwise the AS<number> form.
            asn_props: dict = {"number": announcer["asn_number"]}
            if announcer.get("description"):
                asn_props["name"] = announcer["description"]
            extra_nodes.append(
                {
                    "id": announcer["asn_id"],
                    "type": "autonomous-system",
                    "properties": asn_props,
                }
            )
            if seed_whisper_id:
                extra_edges.append(
                    {
                        "source_id": seed_whisper_id,
                        "target_id": announcer["asn_id"],
                        "type": "related-to",
                        "properties": {"description": "ANNOUNCED_BY"},
                    }
                )

        notes: list[stix2.Note] = []
        content = self._format_network_content(
            list(announcers_by_id.values()), static_prefixes
        )
        if seed_stix_id and content:
            notes.append(
                build_note(
                    seed_stix_id=seed_stix_id,
                    content=content,
                    abstract="Whisper network context",
                )
            )

        return extra_nodes, extra_edges, notes

    # STIX relationship type per direct-fact category. A/AAAA are genuine DNS
    # resolutions → "resolves-to" (keeps idempotency with the IP path's
    # RESOLVES_TO edges). Everything else collapses to "related-to" with the
    # category as the description, since OpenCTI's fixed SRO vocabulary
    # rejects custom relationship types (issue #31).
    _DOMAIN_FACT_REL_TYPE: dict[str, str] = {
        "a-record": "resolves-to",
        "aaaa-record": "resolves-to",
    }

    # Human-readable phrasing for each capped-pivot overflow Note (AC #61).
    _PIVOT_OVERFLOW_PHRASE: dict[str, str] = {
        "nameserver-for-domain": "domains for which {seed} is a nameserver",
        "mail-server-for-domain": "domains for which {seed} is a mail server",
        "subdomain": "subdomains of {seed}",
        "cname-pointing-to-seed": "domains with a CNAME pointing to {seed}",
    }

    @staticmethod
    def _stat_ms(result: object) -> int:
        """Best-effort executionTimeMs from a CypherResult, 0 if unavailable."""
        try:
            v = result.statistics.get("executionTimeMs", 0)  # type: ignore[attr-defined]
        except (AttributeError, TypeError):
            return 0
        return int(v) if isinstance(v, (int, float)) else 0

    @staticmethod
    def _format_spf_content(rows: list) -> str:
        """Render the SPF-policy Note grouped by mechanism (include/ip4/a/…)."""
        mechanisms: dict[str, list[str]] = {}
        for row in rows:
            if not isinstance(row, dict):
                continue
            spf_type = row.get("spfType")
            target = row.get("target")
            if not spf_type or not target:
                continue
            mechanisms.setdefault(str(spf_type), []).append(str(target))
        if not mechanisms:
            return ""
        lines = ["Whisper SPF policy mechanisms for this domain:"]
        for spf_type in sorted(mechanisms):
            targets = sorted(set(mechanisms[spf_type]))
            shown = targets[:20]
            label = spf_type.replace("SPF_", "").lower()
            suffix = (
                f"  (+{len(targets) - len(shown)} more)"
                if len(targets) > len(shown)
                else ""
            )
            lines.append(f"  {label}: {', '.join(shown)}{suffix}")
        return "\n".join(lines)

    def _collect_domain_variants(
        self,
        entity_value: str,
        seed_stix_id: str | None,
    ) -> list[stix2.Note]:
        """Generate typosquat candidates, confirm which exist in Whisper, and
        emit a ``Whisper domain variants`` Note (issue #61 AC #15).

        Existence in the graph means registered/observed, NOT malicious — the
        Note says so. Best-effort: a query failure yields no Note.
        """
        if not seed_stix_id:
            return []
        candidates = generate_domain_variants(entity_value)
        if not candidates:
            return []
        by_name = {c["variant"]: c for c in candidates}
        query = get_variant_existence_query(list(by_name.keys()))
        if not query:
            return []
        try:
            result = self.client.execute_cypher(query)
        except WhisperClientError as exc:
            self.helper.connector_logger.error(
                "Whisper variant-existence query failed (continuing)",
                {"value": entity_value, "error": str(exc)},
            )
            return []
        existing = sorted(
            {
                row.get("name")
                for row in result.rows
                if isinstance(row, dict) and row.get("name") in by_name
            }
        )
        if not existing:
            return []
        lines = [
            "Whisper found the following registered lookalike domains "
            "(existence only — registration is not a malice verdict; pivot "
            "each through threat intel before acting):",
            "",
        ]
        for name in existing:
            info = by_name[name]
            lines.append(
                f"  - {name}  (method: {info['method']}, "
                f"confidence: {info['confidence']:.1f})"
            )
        return [
            build_note(
                seed_stix_id=seed_stix_id,
                content="\n".join(lines),
                abstract="Whisper domain variants",
            )
        ]

    def _collect_domain_enrichment(
        self,
        entity_value: str,
        observable: dict,
    ) -> tuple[list[dict], list[dict], list[stix2.Note], int]:
        """Run the targeted directional category queries for a Domain-Name seed.

        Returns ``(nodes, edges, notes, total_execution_ms)``. Each category is
        independently best-effort — one failing query logs and is skipped
        rather than sinking the whole enrichment.
        """
        nodes_by_id: dict[str, dict] = {}
        edges: list[dict] = []
        seen_edge_keys: set[tuple[str, str, str]] = set()
        notes: list[stix2.Note] = []
        dropped: list[dict] = []
        total_ms = 0
        seed_stix_id = self._seed_stix_id("Domain-Name", entity_value, observable)

        def add_node(translated: dict | None) -> None:
            if translated and translated["id"] not in nodes_by_id:
                nodes_by_id[translated["id"]] = translated

        def add_edge(
            source_id: str, target_id: str, rel_type: str, description: str
        ) -> None:
            # The converter keys relationships off (source, target, type) —
            # description is intentionally excluded so re-enrichment is
            # idempotent. That means two categories pointing a `related-to`
            # edge at the SAME node (e.g. a registrar that is both the current
            # `registrar` and a `previous-registrar`) would collide and the
            # last writer's description would silently win. Dedupe here with
            # first-writer-wins: categories are processed in precedence order
            # (direct facts before pivots; within direct facts `registrar`
            # before `previous-registrar`), so the more specific/current
            # description is kept. This ordering is load-bearing — see
            # DOMAIN_DIRECT_FACT_QUERIES.
            key = (source_id, target_id, rel_type)
            if key in seen_edge_keys:
                return
            seen_edge_keys.add(key)
            edges.append(
                {
                    "source_id": source_id,
                    "target_id": target_id,
                    "type": rel_type,
                    "properties": {"description": description},
                }
            )

        def run(query: str, category: str) -> object | None:
            nonlocal total_ms
            try:
                result = self.client.execute_cypher(query)
            except WhisperClientError as exc:
                self.helper.connector_logger.error(
                    "Whisper domain query failed (continuing)",
                    {"category": category, "value": entity_value, "error": str(exc)},
                )
                return None
            total_ms += self._stat_ms(result)
            return result

        # --- Direct facts: deterministic seed -> neighbour relationships. ---
        for desc, query in get_domain_direct_fact_queries(entity_value).items():
            result = run(query, desc)
            if result is None:
                continue
            dropped.extend(collect_dropped_hostnames(result))
            rel_type = self._DOMAIN_FACT_REL_TYPE.get(desc, "related-to")
            for row in result.rows:
                if not isinstance(row, dict):
                    continue
                h = translate_node_cell(row.get("h"))
                m = translate_node_cell(row.get("m"))
                if h is None or m is None:
                    continue
                add_node(h)
                add_node(m)
                add_edge(h["id"], m["id"], rel_type, desc)

        # --- Capped pivots: capped relationships + overflow Note per category.
        for desc, q in get_domain_pivot_queries(entity_value).items():
            result = run(q["rows"], desc)
            if result is None:
                continue
            dropped.extend(collect_dropped_hostnames(result))
            for row in result.rows:
                if not isinstance(row, dict):
                    continue
                h = translate_node_cell(row.get("h"))
                m = translate_node_cell(row.get("m"))
                if h is None or m is None:
                    continue
                add_node(h)
                add_node(m)
                add_edge(h["id"], m["id"], "related-to", desc)
            count_result = run(q["count"], f"{desc}-count")
            count = (
                count_result.rows[0].get("c")
                if count_result
                and count_result.rows
                and isinstance(count_result.rows[0], dict)
                else 0
            )
            if seed_stix_id and isinstance(count, int) and count > DOMAIN_PIVOT_CAP:
                phrase = self._PIVOT_OVERFLOW_PHRASE[desc].format(seed=entity_value)
                notes.append(
                    build_note(
                        seed_stix_id=seed_stix_id,
                        content=(
                            f"Whisper found {count:,} {phrase}; "
                            f"showing first {DOMAIN_PIVOT_CAP}."
                        ),
                        abstract=f"Whisper {desc} overflow",
                    )
                )

        # --- Outbound/inbound web links (existing collector, AC descriptions).
        try:
            lt_nodes, lt_edges, lt_notes = self._collect_links_to(
                "Domain-Name", entity_value, observable
            )
        except WhisperClientError as exc:
            self.helper.connector_logger.error(
                "Whisper LINKS_TO supplementary query failed (continuing)",
                {"value": entity_value, "error": str(exc)},
            )
            lt_nodes, lt_edges, lt_notes = [], [], []
        for node in lt_nodes:
            add_node(node)
        for lt_edge in lt_edges:
            add_edge(
                lt_edge["source_id"],
                lt_edge["target_id"],
                lt_edge["type"],
                (lt_edge.get("properties") or {}).get("description", ""),
            )
        notes.extend(lt_notes)

        # --- SPF policy Note. ---
        spf_result = run(get_spf_policy_query(entity_value), "spf")
        if seed_stix_id and spf_result and spf_result.rows:
            content = self._format_spf_content(spf_result.rows)
            if content:
                notes.append(
                    build_note(
                        seed_stix_id=seed_stix_id,
                        content=content,
                        abstract="Whisper SPF policy",
                    )
                )

        # --- WHOIS phone Note. ---
        phone_result = run(get_whois_phone_query(entity_value), "whois-phone")
        if seed_stix_id and phone_result and phone_result.rows:
            phones = sorted(
                {
                    str(row.get("phone"))
                    for row in phone_result.rows
                    if isinstance(row, dict) and row.get("phone")
                }
            )
            if phones:
                content = "Whisper WHOIS phone contacts for this domain:\n" + "\n".join(
                    f"  - {p}" for p in phones
                )
                notes.append(
                    build_note(
                        seed_stix_id=seed_stix_id,
                        content=content,
                        abstract="Whisper WHOIS phone contacts",
                    )
                )

        # --- Threat feed evidence Note (AC #12: renamed abstract + caveat). ---
        try:
            notes.extend(
                self._collect_threat_context(
                    "Domain-Name",
                    entity_value,
                    observable,
                    abstract="Whisper threat feed evidence",
                    caveat=(
                        "Note: the Whisper threat score is supporting evidence, "
                        "not an authoritative verdict — corroborate before acting."
                    ),
                )
            )
        except WhisperClientError as exc:
            self.helper.connector_logger.error(
                "Whisper threat-context query failed (continuing)",
                {"value": entity_value, "error": str(exc)},
            )

        # --- Lookalikes Note. ---
        notes.extend(self._collect_domain_variants(entity_value, seed_stix_id))

        # --- Dropped non-RFC-1035 DNS records Note (aggregated across queries).
        if dropped and seed_stix_id:
            notes.append(
                build_note(
                    seed_stix_id=seed_stix_id,
                    content=self._format_dropped_hostnames_content(dropped),
                    abstract="Whisper dropped non-RFC-1035 DNS records",
                )
            )

        return list(nodes_by_id.values()), edges, notes, total_ms

    def _enrich_domain(self, observable: dict, entity_value: str) -> str:
        """Targeted Domain-Name enrichment entrypoint (issue #61)."""
        self.helper.connector_logger.info(
            "Enriching domain via Whisper (targeted)",
            {"entity_id": observable.get("id"), "value": entity_value},
        )
        nodes, edges, notes, total_ms = self._collect_domain_enrichment(
            entity_value, observable
        )
        return self._ship_enrichment(
            observable, entity_value, nodes, edges, notes, total_ms
        )

    def _enrich_observable(self, observable: dict) -> str:
        entity_type = observable.get("entity_type")
        entity_value = observable.get("observable_value") or observable.get("value")

        # Autonomous-System: OpenCTI exposes the human-readable AS name as
        # `observable_value` (e.g. "Google LLC") and the AS number as a
        # separate `number` field. Whisper's ASN nodes are keyed by the
        # canonical `AS<number>` string, so we have to convert here. Issue #48.
        if entity_type == "Autonomous-System":
            asn_number = observable.get("number")
            if asn_number is not None:
                entity_value = f"AS{asn_number}"

        if not entity_value:
            return f"observable {observable.get('id')!r} has no value to enrich"

        # Domain-Name uses targeted directional category queries rather than
        # the broad one-hop template (issue #61) — deterministic output, stable
        # relationship descriptions. IP/ASN seeds keep the broad path below.
        if entity_type == "Domain-Name":
            return self._enrich_domain(observable, entity_value)

        query = get_query_for_entity_type(
            entity_type, value=entity_value, limit=DEFAULT_LIMIT
        )
        if query is None:
            return f"entity type {entity_type!r} not supported by Whisper enrichment"

        self.helper.connector_logger.info(
            "Enriching via Whisper",
            {
                "entity_id": observable.get("id"),
                "entity_type": entity_type,
                "value": entity_value,
            },
        )

        try:
            result = self.client.execute_cypher(query)
        except WhisperClientError as exc:
            self.helper.connector_logger.error(
                "Whisper query failed",
                {"entity_id": observable.get("id"), "error": str(exc)},
            )
            raise

        nodes, edges = parse_cypher_result(result)

        # Capture HOSTNAME records the parser silently dropped for failing
        # the RFC 1035 check (issue #51, builds on #47). Surfaced as a Note
        # attached to the seed so the analyst sees what Whisper had even
        # though we can't ship it as a domain-name SCO.
        dropped_hostnames = collect_dropped_hostnames(result)

        # Supplementary LINKS_TO enrichment for Domain-Name seeds.
        try:
            extra_nodes, extra_edges, extra_notes = self._collect_links_to(
                entity_type, entity_value, observable
            )
        except WhisperClientError as exc:
            # LINKS_TO is a nice-to-have — don't fail the whole enrichment
            # if just the supplementary queries fall over.
            self.helper.connector_logger.error(
                "Whisper LINKS_TO supplementary query failed (continuing)",
                {"entity_id": observable.get("id"), "error": str(exc)},
            )
            extra_nodes, extra_edges, extra_notes = [], [], []

        # Supplementary threat-context Note for HOSTNAME/IPV4/IPV6 seeds.
        # Independently best-effort: a failure here must not block the main
        # bundle or the LINKS_TO Notes from shipping.
        try:
            threat_notes = self._collect_threat_context(
                entity_type, entity_value, observable
            )
        except WhisperClientError as exc:
            self.helper.connector_logger.error(
                "Whisper threat-context query failed (continuing)",
                {"entity_id": observable.get("id"), "error": str(exc)},
            )
            threat_notes = []
        extra_notes.extend(threat_notes)

        # Dropped-HOSTNAME Note (issue #51). Independent of any
        # supplementary query: built from the main result we already have.
        if dropped_hostnames:
            seed_stix_id = self._seed_stix_id(entity_type, entity_value, observable)
            if seed_stix_id:
                content = self._format_dropped_hostnames_content(dropped_hostnames)
                extra_notes.append(
                    build_note(
                        seed_stix_id=seed_stix_id,
                        content=content,
                        abstract="Whisper dropped non-RFC-1035 DNS records",
                    )
                )

        # Supplementary network context for IPv4/IPv6 seeds — emits the
        # announcing-ASN as a real Autonomous-System SCO + related-to edge
        # plus a Note for the prefix/BGP/ANNOUNCED_PREFIX threat detail.
        # Same best-effort posture as the other supplementary passes.
        try:
            net_nodes, net_edges, net_notes = self._collect_network_context(
                entity_type, entity_value, observable
            )
        except WhisperClientError as exc:
            self.helper.connector_logger.error(
                "Whisper network-context query failed (continuing)",
                {"entity_id": observable.get("id"), "error": str(exc)},
            )
            net_nodes, net_edges, net_notes = [], [], []
        extra_nodes.extend(net_nodes)
        extra_edges.extend(net_edges)
        extra_notes.extend(net_notes)

        if extra_nodes or extra_edges:
            seen_node_ids = {n["id"] for n in nodes}
            for new_node in extra_nodes:
                if new_node["id"] not in seen_node_ids:
                    nodes.append(new_node)
                    seen_node_ids.add(new_node["id"])
            edges.extend(extra_edges)

        elapsed = result.statistics.get("executionTimeMs", "?")
        return self._ship_enrichment(
            observable, entity_value, nodes, edges, extra_notes, elapsed
        )

    def _ship_enrichment(
        self,
        observable: dict,
        entity_value: str,
        nodes: list[dict],
        edges: list[dict],
        extra_notes: list,
        elapsed: object,
    ) -> str:
        """Shared bundle-build / send / status tail for both enrichment paths.

        Applies the "don't ship a seed-only bundle with no new context" guard,
        builds the STIX bundle, ships it via the helper, and returns the
        work-item status string shown in the OpenCTI UI.
        """
        if not nodes and not extra_notes:
            self.helper.connector_logger.info(
                "No Whisper data for entity",
                {"entity_id": observable.get("id"), "value": entity_value},
            )
            return f"No Whisper data for {entity_value}"

        # If every neighbour was dropped by the parser (unmappable labels like
        # PREFIX, CITY, COUNTRY) we end up with just the seed and no edges.
        # Sending a bundle that only re-asserts the seed observable adds no
        # new information to OpenCTI and produces a misleading "Enriched"
        # status — UNLESS we also have supplementary Notes (LINKS_TO overflow
        # or Whisper threat intelligence) to attach, in which case the
        # bundle carries genuinely new analyst-visible context.
        if not edges and not extra_notes:
            self.helper.connector_logger.info(
                "No mappable Whisper relationships for entity",
                {
                    "entity_id": observable.get("id"),
                    "value": entity_value,
                    "nodes_returned": len(nodes),
                },
            )
            return f"No mappable Whisper relationships for {entity_value}"

        try:
            bundle = build_bundle(nodes, edges, extra_objects=extra_notes)
        except StixMappingError as exc:
            self.helper.connector_logger.error(
                "STIX mapping failed",
                {"entity_id": observable.get("id"), "error": str(exc)},
            )
            raise

        objects = getattr(bundle, "objects", None) or []
        if not objects:
            return f"No mappable Whisper data for {entity_value}"

        # v7 / upstream convention: build the bundle via the helper rather
        # than serializing the stix2.Bundle ourselves. ``build_bundle``
        # still produces a ``stix2.Bundle`` for the unit tests' sake;
        # ``helper.stix2_create_bundle`` consumes the object list.
        stix_bundle = self.helper.stix2_create_bundle(objects)
        self.helper.send_stix2_bundle(stix_bundle, cleanup_inconsistent_bundle=True)
        self.helper.connector_logger.info(
            "Sent STIX bundle",
            {
                "entity_id": observable.get("id"),
                "object_count": len(objects),
                "execution_time_ms": elapsed,
            },
        )
        return f"Enriched {entity_value} with {len(objects)} STIX objects (query: {elapsed}ms)"

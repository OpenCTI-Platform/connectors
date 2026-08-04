import json

import pytest
from conftest import _v7_payload
from connector.connector import WhisperConnector
from connector.exceptions import WhisperTransportError
from connector.whisper_client import CypherResult


def test_process_message_no_enrichment_entity_returns_status(connector, helper):
    # v7 callback shape: the worker hands us the entity directly via
    # data["enrichment_entity"]. Empty payload is an upstream-side bug
    # — return a clear status, don't try to enrich.
    result = connector._process_message({})
    assert "missing enrichment_entity" in result
    helper.send_stix2_bundle.assert_not_called()


def test_process_message_unsupported_entity_type(connector, helper, client):
    observable = {
        "id": "url--x",
        "entity_type": "Url",
        "value": "https://example.test/",
    }
    result = connector._process_message(_v7_payload(observable))
    assert "not supported" in result
    client.execute_cypher.assert_not_called()
    helper.send_stix2_bundle.assert_not_called()


def test_process_message_observable_without_value(connector, helper):
    observable = {
        "id": "ipv4--x",
        "entity_type": "IPv4-Addr",
    }
    result = connector._process_message(_v7_payload(observable))
    assert "no value to enrich" in result
    helper.send_stix2_bundle.assert_not_called()


def test_process_message_no_whisper_data(connector, helper, client):
    observable = {
        "id": "ipv4--x",
        "entity_type": "IPv4-Addr",
        "observable_value": "1.2.3.4",
    }
    client.execute_cypher.return_value = CypherResult(
        columns=["n", "r", "m"], rows=[], statistics={}
    )
    result = connector._process_message(_v7_payload(observable))
    assert "No Whisper data" in result
    helper.send_stix2_bundle.assert_not_called()


def test_process_message_enriches_ipv4_with_resolves_to_hostname(
    connector, helper, client
):
    observable = {
        "id": "ipv4--x",
        "entity_type": "IPv4-Addr",
        "observable_value": "8.8.8.8",
    }
    client.execute_cypher.return_value = CypherResult(
        columns=["n", "r", "m"],
        rows=[
            {
                "n": {"nodeId": "1", "label": "IPV4", "name": "8.8.8.8"},
                "r": {"type": "RESOLVES_TO"},
                "m": {"nodeId": "2", "label": "HOSTNAME", "name": "dns.google"},
            }
        ],
        statistics={"rowCount": 1, "executionTimeMs": 3},
    )

    result = connector._process_message(_v7_payload(observable))
    assert "Enriched 8.8.8.8" in result

    helper.send_stix2_bundle.assert_called_once()
    bundle = json.loads(helper.send_stix2_bundle.call_args[0][0])
    types_by_id = {o["id"]: o["type"] for o in bundle["objects"]}
    assert "ipv4-addr" in types_by_id.values()
    assert "domain-name" in types_by_id.values()
    rels = [o for o in bundle["objects"] if o["type"] == "relationship"]
    assert len(rels) == 1
    rel = rels[0]
    assert rel["relationship_type"] == "resolves-to"
    assert rel["source_ref"].startswith("domain-name--")
    assert rel["target_ref"].startswith("ipv4-addr--")


def test_process_message_inlines_value_and_limit_into_query(connector, helper, client):
    # Whisper rejects parameterised queries entirely — both $value and $limit
    # are substituted client-side as Cypher literals.
    observable = {
        "id": "ipv4--x",
        "entity_type": "IPv4-Addr",
        "observable_value": "8.8.8.8",
    }
    client.execute_cypher.return_value = CypherResult(
        columns=["n", "r", "m"], rows=[], statistics={}
    )
    connector._process_message(_v7_payload(observable))
    args, _kwargs = client.execute_cypher.call_args
    query = args[0]
    assert "$value" not in query
    assert "$limit" not in query
    assert '"8.8.8.8"' in query
    assert "LIMIT " in query
    # execute_cypher called with no params dict (single positional arg).
    assert len(args) == 1


def test_process_message_returns_no_mappable_rels_when_only_seed_remains(
    connector, helper, client
):
    # Issue #44: when the parser drops every neighbour (unmappable labels
    # like CITY / PREFIX / COUNTRY / FEED_SOURCE) and leaves only the seed
    # observable plus no edges, the connector must NOT report success.
    # Sending a bundle with just the seed adds no new info to OpenCTI and
    # produces a misleading green status. The correct outcome is a clear
    # "No mappable Whisper relationships for X" status with no bundle sent.
    observable = {
        "id": "ipv4--x",
        "entity_type": "IPv4-Addr",
        "observable_value": "8.8.8.8",
    }
    client.execute_cypher.return_value = CypherResult(
        columns=["n", "r", "m"],
        rows=[
            {
                "n": {"nodeId": "1", "label": "IPV4", "name": "8.8.8.8"},
                "r": {"type": "BELONGS_TO"},
                "m": {"nodeId": "2", "label": "PREFIX", "name": "8.8.8.0/24"},
            }
        ],
        statistics={},
    )

    result = connector._process_message(_v7_payload(observable))

    assert result == "No mappable Whisper relationships for 8.8.8.8"
    helper.send_stix2_bundle.assert_not_called()


def test_process_message_whisper_transport_error_propagates_and_logs(
    connector, helper, client
):
    observable = {
        "id": "ipv4--x",
        "entity_type": "IPv4-Addr",
        "observable_value": "1.2.3.4",
    }
    client.execute_cypher.side_effect = WhisperTransportError("connection refused")
    with pytest.raises(WhisperTransportError):
        connector._process_message(_v7_payload(observable))
    helper.send_stix2_bundle.assert_not_called()
    helper.connector_logger.error.assert_called()


def test_process_message_accepts_observable_value_or_value_field(
    connector, helper, client
):
    # pycti returns different field names across versions — handle both.
    observable = {
        "id": "domain-name--x",
        "entity_type": "Domain-Name",
        "value": "example.test",  # not observable_value
    }
    client.execute_cypher.return_value = CypherResult(
        columns=["n", "r", "m"], rows=[], statistics={}
    )
    result = connector._process_message(_v7_payload(observable))
    # Should have inlined the "value" field's value as a Cypher literal.
    assert "No Whisper data for example.test" in result
    # Domain-Name seeds now trigger LINKS_TO supplementary queries (issue
    # #48 Phase A), so we don't assert call-count — just that the main
    # template's value substitution happened in the first call.
    first_query = client.execute_cypher.call_args_list[0][0][0]
    assert '"example.test"' in first_query


def test_process_message_enriches_autonomous_system_via_asn_anchor(
    connector, helper, client
):
    # Issue #48: Autonomous-System is now an in-scope entity type. The
    # connector must derive the Whisper-anchor value from the observable's
    # `number` field (OpenCTI's `observable_value` for autonomous-system
    # is the AS *name* like "Google LLC", not the canonical "AS<number>"
    # form Whisper uses), then issue an ASN-anchored Cypher query.
    observable = {
        "id": "autonomous-system--x",
        "entity_type": "Autonomous-System",
        "observable_value": "Google LLC",  # human-readable name
        "number": 15169,
        "name": "Google LLC",
    }
    client.execute_cypher.return_value = CypherResult(
        columns=["n", "r", "m"],
        rows=[
            {
                "n": {"nodeId": "1", "label": "ASN", "name": "AS15169"},
                "r": {"type": "BELONGS_TO"},
                "m": {"nodeId": "2", "label": "IPV4", "name": "8.8.8.8"},
            }
        ],
        statistics={"rowCount": 1, "executionTimeMs": 5},
    )

    result = connector._process_message(_v7_payload(observable))
    assert "Enriched AS15169" in result

    # Cypher template fired with the ASN anchor + AS-number-derived value,
    # not the human-readable AS name.
    query = client.execute_cypher.call_args[0][0]
    assert ":ASN" in query
    assert '"AS15169"' in query
    assert "Google LLC" not in query

    helper.send_stix2_bundle.assert_called_once()
    bundle = json.loads(helper.send_stix2_bundle.call_args[0][0])
    types = [o["type"] for o in bundle["objects"]]
    assert "autonomous-system" in types
    assert "ipv4-addr" in types


def test_process_message_autonomous_system_without_number_falls_back(
    connector, helper, client
):
    # Edge case: if the observable somehow lacks a `number` field (older
    # OpenCTI versions, manual STIX import, etc.), we fall back to whatever
    # observable_value / value carries — even if it likely won't match a
    # Whisper ASN node. Better to issue the query and return "No Whisper
    # data" than crash.
    observable = {
        "id": "autonomous-system--x",
        "entity_type": "Autonomous-System",
        "observable_value": "Some-Network",
    }
    client.execute_cypher.return_value = CypherResult(
        columns=["n", "r", "m"], rows=[], statistics={}
    )
    result = connector._process_message(_v7_payload(observable))
    assert "No Whisper data for Some-Network" in result


# --- LINKS_TO supplementary enrichment (issue #48 Phase A) -----------------


# Substring fingerprints that pick a query out of the targeted Domain-Name
# flow (issue #61). Direction-bearing arrows distinguish a domain's OWN
# records (direct facts) from the reverse-direction pivots.
_DIRECT_FACT_NEEDLE = {
    "a-record": "-[:RESOLVES_TO]->(m:IPV4)",
    "aaaa-record": "-[:RESOLVES_TO]->(m:IPV6)",
    "cname": "-[:ALIAS_OF]->(m:HOSTNAME)",
    "name-server": "<-[:NAMESERVER_FOR]-(m:HOSTNAME)",
    "mx-server": "<-[:MAIL_FOR]-(m:HOSTNAME)",
    "registrar": "-[:HAS_REGISTRAR]->",
    "previous-registrar": "-[:PREV_REGISTRAR]->",
    "registered-by": "-[:REGISTERED_BY]->",
    "whois-email": "-[:HAS_EMAIL]->",
}
_PIVOT_NEEDLE = {
    "nameserver-for-domain": "-[:NAMESERVER_FOR]->(m:HOSTNAME)",
    "mail-server-for-domain": "-[:MAIL_FOR]->(m:HOSTNAME)",
    "subdomain": "<-[:CHILD_OF]-(m:HOSTNAME)",
    "cname-pointing-to-seed": "<-[:ALIAS_OF]-(m:HOSTNAME)",
}


def _hm_row(seed_name, seed_id, m_id, m_label, m_name):
    """One ``RETURN h, m`` row pairing the seed HOSTNAME with a neighbour."""
    return {
        "h": {"nodeId": seed_id, "label": "HOSTNAME", "name": seed_name},
        "m": {"nodeId": m_id, "label": m_label, "name": m_name},
    }


def _domain_side_effect(
    seed_name="example.test",
    direct=None,
    pivot=None,
    counts=None,
    links=None,
    threat_rows=None,
    variant_names=None,
    spf_rows=None,
    phone_rows=None,
):
    """execute_cypher side_effect for the targeted Domain-Name flow.

    ``direct``/``pivot`` map a category description to its ``RETURN h, m`` rows;
    ``counts`` maps a pivot description to its total count; ``links`` carries
    the LINKS_TO outbound/inbound rows + counts. Anything not supplied returns
    empty. By default ``direct`` seeds a single A record so the seed
    Domain-Name SCO is present in the bundle.
    """
    if direct is None:
        direct = {"a-record": [_hm_row(seed_name, "seed", "ip-a", "IPV4", "1.2.3.4")]}
    pivot = pivot or {}
    counts = counts or {}
    links = links or {}

    def _se(query, *_args, **_kwargs):
        # LINKS_TO directed rows + counts (handled by the existing collector).
        if "count(m)" in query and "-[r:LINKS_TO]->" in query:
            return CypherResult(
                columns=["c"],
                rows=[{"c": links.get("outbound_count", 0)}],
                statistics={},
            )
        if "count(m)" in query and "<-[r:LINKS_TO]-" in query:
            return CypherResult(
                columns=["c"],
                rows=[{"c": links.get("inbound_count", 0)}],
                statistics={},
            )
        if "-[r:LINKS_TO]->" in query:
            return CypherResult(
                columns=["n", "r", "m"], rows=links.get("outbound", []), statistics={}
            )
        if "<-[r:LINKS_TO]-" in query:
            return CypherResult(
                columns=["n", "r", "m"], rows=links.get("inbound", []), statistics={}
            )
        # Pivot count queries (check before pivot rows — both share the arrow).
        if "count(m) AS c" in query:
            for desc, needle in _PIVOT_NEEDLE.items():
                if needle in query:
                    return CypherResult(
                        columns=["c"], rows=[{"c": counts.get(desc, 0)}], statistics={}
                    )
            return CypherResult(columns=["c"], rows=[{"c": 0}], statistics={})
        # Direct-fact rows.
        for desc, needle in _DIRECT_FACT_NEEDLE.items():
            if needle in query:
                return CypherResult(
                    columns=["h", "m"],
                    rows=direct.get(desc, []),
                    statistics={"executionTimeMs": 1},
                )
        # Pivot rows.
        for desc, needle in _PIVOT_NEEDLE.items():
            if needle in query:
                return CypherResult(
                    columns=["h", "m"], rows=pivot.get(desc, []), statistics={}
                )
        # Supplementary Note sources.
        if "FEED_SOURCE" in query and "LISTED_IN" in query:
            return CypherResult(
                columns=["threatScore", "threatLevel", "feedName"],
                rows=threat_rows or [],
                statistics={},
            )
        if query.startswith("UNWIND ["):
            return CypherResult(
                columns=["name"],
                rows=[{"name": n} for n in (variant_names or [])],
                statistics={},
            )
        if 'STARTS WITH "SPF_"' in query:
            return CypherResult(
                columns=["spfType", "target"], rows=spf_rows or [], statistics={}
            )
        if "-[:HAS_PHONE]->" in query:
            return CypherResult(columns=["phone"], rows=phone_rows or [], statistics={})
        return CypherResult(columns=["h", "m"], rows=[], statistics={})

    return _se


def test_domain_seed_fires_targeted_category_queries_not_broad(
    connector, helper, client
):
    # AC #1: a Domain-Name seed drives category-specific directional queries,
    # NOT the broad one-hop template. Assert the direct-fact + pivot + LINKS_TO
    # shapes all fire and that no broad `type(r) <> "LINKS_TO"` query is sent.
    observable = {
        "id": "domain-name--x",
        "entity_type": "Domain-Name",
        "value": "example.test",
    }
    client.execute_cypher.side_effect = _domain_side_effect()
    connector._process_message(_v7_payload(observable))

    queries = [c.args[0] for c in client.execute_cypher.call_args_list]
    # No broad undirected one-hop query for the domain seed.
    assert not [q for q in queries if 'type(r) <> "LINKS_TO"' in q]
    # Every direct-fact and pivot category query was issued.
    for needle in _DIRECT_FACT_NEEDLE.values():
        assert any(needle in q for q in queries), needle
    for needle in _PIVOT_NEEDLE.values():
        assert any(needle in q for q in queries), needle
    # Four LINKS_TO queries (outbound, inbound, count_outbound, count_inbound).
    links_to_queries = [q for q in queries if ":LINKS_TO" in q]
    assert len(links_to_queries) == 4
    # SPF, WHOIS-phone, threat-feed and variant-existence passes all fire.
    assert any('STARTS WITH "SPF_"' in q for q in queries)
    assert any("-[:HAS_PHONE]->" in q for q in queries)
    assert any("FEED_SOURCE" in q and "LISTED_IN" in q for q in queries)
    assert any(q.startswith("UNWIND [") for q in queries)


def test_links_to_outbound_edge_tagged_and_oriented_seed_to_neighbour(
    connector, helper, client
):
    # Outbound LINKS_TO: seed → neighbour. The edge `description` must say
    # "links-to-outbound" (AC wording) so analysts can distinguish direction.
    observable = {
        "id": "domain-name--x",
        "entity_type": "Domain-Name",
        "value": "example.test",
    }
    client.execute_cypher.side_effect = _domain_side_effect(
        direct={},  # suppress the default A record so only the link edge remains
        links={
            "outbound": [
                {
                    "n": {
                        "nodeId": "seed",
                        "label": "HOSTNAME",
                        "name": "example.test",
                    },
                    "r": {"type": "LINKS_TO"},
                    "m": {
                        "nodeId": "out1",
                        "label": "HOSTNAME",
                        "name": "neighbour.test",
                    },
                }
            ],
            "outbound_count": 1,
        },
    )
    connector._process_message(_v7_payload(observable))

    helper.send_stix2_bundle.assert_called_once()
    bundle = json.loads(helper.send_stix2_bundle.call_args[0][0])
    rels = [o for o in bundle["objects"] if o["type"] == "relationship"]
    assert len(rels) == 1
    # Edge collapses to related-to with the direction tag in description.
    assert rels[0]["relationship_type"] == "related-to"
    assert rels[0]["description"] == "links-to-outbound"


def test_links_to_inbound_edge_source_target_swapped(connector, helper, client):
    # Inbound LINKS_TO: neighbour → seed semantically. The Whisper query
    # uses the seed-anchored MATCH pattern that puts the seed in column `n`
    # regardless of direction, so the parser's column-position default
    # gives us (seed → neighbour). The connector must swap source/target
    # before emitting so the STIX relationship correctly reads
    # neighbour → seed.
    observable = {
        "id": "domain-name--x",
        "entity_type": "Domain-Name",
        "value": "example.test",
    }
    client.execute_cypher.side_effect = _domain_side_effect(
        direct={},  # suppress the default A record so only the link edge remains
        links={
            "inbound": [
                {
                    "n": {
                        "nodeId": "seed",
                        "label": "HOSTNAME",
                        "name": "example.test",
                    },
                    "r": {"type": "LINKS_TO"},
                    "m": {
                        "nodeId": "in1",
                        "label": "HOSTNAME",
                        "name": "referrer.test",
                    },
                }
            ],
            "inbound_count": 1,
        },
    )
    connector._process_message(_v7_payload(observable))

    bundle = json.loads(helper.send_stix2_bundle.call_args[0][0])
    rels = [o for o in bundle["objects"] if o["type"] == "relationship"]
    assert len(rels) == 1
    rel = rels[0]
    assert rel["description"] == "links-to-inbound"
    # Resolve refs back to SCO values to assert direction.
    by_id = {o["id"]: o for o in bundle["objects"]}
    source = by_id[rel["source_ref"]]
    target = by_id[rel["target_ref"]]
    assert source["value"] == "referrer.test"
    assert target["value"] == "example.test"


def test_links_to_cap_overflow_emits_note_attached_to_seed(connector, helper, client):
    # When Whisper has more than LINKS_TO_CAP (25) neighbours in either
    # direction, the connector must emit a STIX Note attached to the seed
    # so the analyst sees "showing first 25" instead of being misled into
    # thinking 25 is the full picture. Both directions overflow here.
    observable = {
        "id": "domain-name--x",
        "entity_type": "Domain-Name",
        "value": "example.test",
    }
    client.execute_cypher.side_effect = _domain_side_effect(
        links={"outbound_count": 42, "inbound_count": 12_800_000},
    )
    connector._process_message(_v7_payload(observable))

    bundle = json.loads(helper.send_stix2_bundle.call_args[0][0])
    notes = [o for o in bundle["objects"] if o["type"] == "note"]
    assert len(notes) == 1
    note = notes[0]
    assert note["abstract"] == "LINKS_TO neighbour overflow"
    assert "42 outbound" in note["content"]
    assert "12800000 inbound" in note["content"]
    assert "showing first 25" in note["content"]
    # Note must be attached to the seed Domain-Name SCO.
    seed_id = next(
        o["id"]
        for o in bundle["objects"]
        if o["type"] == "domain-name" and o["value"] == "example.test"
    )
    assert note["object_refs"] == [seed_id]


def test_links_to_no_overflow_omits_note(connector, helper, client):
    # Counts at-or-below the cap should NOT generate a Note. Only emit the
    # overflow notice when it's actually informative.
    observable = {
        "id": "domain-name--x",
        "entity_type": "Domain-Name",
        "value": "example.test",
    }
    client.execute_cypher.side_effect = _domain_side_effect(
        links={"outbound_count": 3, "inbound_count": 25},  # 25 == cap, not over
    )
    connector._process_message(_v7_payload(observable))

    bundle = json.loads(helper.send_stix2_bundle.call_args[0][0])
    assert not any(o["type"] == "note" for o in bundle["objects"])


def test_links_to_supplementary_skipped_for_non_domain_seeds(connector, helper, client):
    # IPv4, IPv6, and Autonomous-System seeds must NOT trigger directed
    # LINKS_TO queries — that edge type only exists between HOSTNAME nodes
    # in Whisper's schema. (Threat-context Phase B does fire for IPv4/IPv6
    # but that's a different supplementary query; we assert "no LINKS_TO
    # directed/count templates" rather than "exactly one query".)
    for entity_id, entity_type, extra in (
        ("ipv4--x", "IPv4-Addr", {"observable_value": "1.2.3.4"}),
        ("ipv6--x", "IPv6-Addr", {"observable_value": "::1"}),
        (
            "autonomous-system--x",
            "Autonomous-System",
            {"observable_value": "Google LLC", "number": 15169},
        ),
    ):
        client.reset_mock()
        observable = {
            "id": entity_id,
            "entity_type": entity_type,
            **extra,
        }
        client.execute_cypher.return_value = CypherResult(
            columns=["n", "r", "m"], rows=[], statistics={}
        )
        connector._process_message(_v7_payload(observable))
        queries = [c.args[0] for c in client.execute_cypher.call_args_list]
        # Zero directed/count LINKS_TO queries for non-Domain-Name seeds.
        for q in queries:
            assert (
                "-[r:LINKS_TO]" not in q
            ), f"{entity_type}: unexpected LINKS_TO query: {q}"
            assert (
                "<-[r:LINKS_TO]" not in q
            ), f"{entity_type}: unexpected LINKS_TO query: {q}"


def test_links_to_supplementary_failure_does_not_fail_enrichment(
    connector, helper, client
):
    # The LINKS_TO supplementary pass is nice-to-have. If it raises a
    # transport error mid-flight, the main enrichment result still gets
    # delivered — we don't punish the seed because of a flaky follow-up.
    from connector.exceptions import WhisperTransportError

    observable = {
        "id": "domain-name--x",
        "entity_type": "Domain-Name",
        "value": "example.test",
    }

    base = _domain_side_effect()  # default A record keeps the seed bundle alive

    def _flaky(query, *_args, **_kwargs):
        if ":LINKS_TO" in query:
            raise WhisperTransportError("connection reset")
        return base(query)

    client.execute_cypher.side_effect = _flaky

    result = connector._process_message(_v7_payload(observable))
    assert "Enriched example.test" in result
    helper.send_stix2_bundle.assert_called_once()
    helper.connector_logger.error.assert_called()


# --- Threat-context Note (issue #48 Phase B) -------------------------------


def _threat_context_side_effect(main_rows, threat_rows):
    """Dispatch helper: ignore LINKS_TO supplementary queries (return empty),
    return ``threat_rows`` for the threat-context query, ``main_rows`` for
    the main template. Keeps Phase B tests independent of Phase A wiring.
    """

    def _side_effect(query, *_args, **_kwargs):
        if "FEED_SOURCE" in query and "LISTED_IN" in query:
            return CypherResult(
                columns=["threatScore", "threatLevel", "feedName"],
                rows=threat_rows,
                statistics={},
            )
        if ":LINKS_TO" in query:
            cols = ["c"] if "count(m)" in query else ["n", "r", "m"]
            return CypherResult(columns=cols, rows=[], statistics={})
        return CypherResult(columns=["n", "r", "m"], rows=main_rows, statistics={})

    return _side_effect


def test_threat_context_emits_note_with_score_level_flags_and_feeds(
    connector, helper, client
):
    observable = {
        "id": "domain-name--x",
        "entity_type": "Domain-Name",
        "value": "malware-traffic-analysis.net",
    }
    client.execute_cypher.side_effect = _domain_side_effect(
        seed_name="malware-traffic-analysis.net",
        threat_rows=[
            {
                "threatScore": 3.169,
                "threatLevel": "MEDIUM",
                "isMalware": True,
                "isC2": False,
                "isPhishing": False,
                "isThreat": True,
                "threatFirstSeen": 1779849886074,
                "threatLastSeen": 1779849886718,
                "feedName": "tranco-top1m",
                "feedFirstSeen": 1779849886074,
                "feedLastSeen": 1779849886074,
                "feedWeight": 1.0,
            },
            {
                "threatScore": 3.169,
                "threatLevel": "MEDIUM",
                "isMalware": True,
                "isThreat": True,
                "threatFirstSeen": 1779849886074,
                "threatLastSeen": 1779849886718,
                "feedName": "cloudflare-radar-top1m",
                "feedFirstSeen": None,
                "feedLastSeen": None,
                "feedWeight": None,
            },
        ],
    )
    connector._process_message(_v7_payload(observable))

    bundle = json.loads(helper.send_stix2_bundle.call_args[0][0])
    # AC #12: domain threat data ships under the "feed evidence" abstract with
    # the not-an-authoritative-verdict caveat.
    threat_notes = [
        o
        for o in bundle["objects"]
        if o["type"] == "note" and o.get("abstract") == "Whisper threat feed evidence"
    ]
    assert len(threat_notes) == 1
    note = threat_notes[0]
    content = note["content"]
    assert "not an authoritative verdict" in content
    assert "Threat assessment: MEDIUM (score 3.169)" in content
    # ISO-formatted timestamps for first/last seen — epoch ms 1779849886074
    # is 2026-05-27 UTC. Asserting the prefix exactly catches regressions
    # where the formatter forgets the UTC conversion.
    assert "First seen: 2026-05-27T02:44:46Z" in content
    assert "Last seen: 2026-05-27T02:44:46Z" in content
    # Only true flags should be listed.
    assert "isMalware" in content
    assert "isThreat" in content
    assert "isC2" not in content
    # Feed listings.
    assert "Listed in 2 source(s):" in content
    assert "tranco-top1m" in content
    assert "cloudflare-radar-top1m" in content
    # Note must be attached to the seed Domain-Name SCO.
    seed_id = next(
        o["id"]
        for o in bundle["objects"]
        if o["type"] == "domain-name" and o["value"] == "malware-traffic-analysis.net"
    )
    assert note["object_refs"] == [seed_id]


def test_threat_context_omits_note_when_no_threat_data(connector, helper, client):
    # Whisper has the seed but no threat properties / no feed listings.
    # Emitting a Note that says "no threat data" would be noise — skip it.
    observable = {
        "id": "domain-name--x",
        "entity_type": "Domain-Name",
        "value": "boring.test",
    }
    client.execute_cypher.side_effect = _domain_side_effect(
        seed_name="boring.test",
        threat_rows=[
            {
                "threatScore": 0.0,
                "threatLevel": "NONE",
                "isMalware": False,
                "isThreat": False,
                "threatFirstSeen": None,
                "threatLastSeen": None,
                "feedName": None,
            }
        ],
    )
    connector._process_message(_v7_payload(observable))

    bundle = json.loads(helper.send_stix2_bundle.call_args[0][0])
    assert not any(
        o.get("abstract") == "Whisper threat feed evidence"
        for o in bundle["objects"]
        if o["type"] == "note"
    )


def test_threat_context_note_emitted_with_score_only_no_feeds(
    connector, helper, client
):
    # Seed has a score and level but isn't on any FEED_SOURCE — still
    # produces a Note. The Note is the only analyst-visible breadcrumb that
    # Whisper has any threat opinion on this seed.
    observable = {
        "id": "ipv4--x",
        "entity_type": "IPv4-Addr",
        "observable_value": "203.0.113.42",
    }
    client.execute_cypher.side_effect = _threat_context_side_effect(
        main_rows=[
            {
                "n": {"nodeId": "seed", "label": "IPV4", "name": "203.0.113.42"},
                "r": {"type": "RESOLVES_TO"},
                "m": {"nodeId": "h1", "label": "HOSTNAME", "name": "example.test"},
            }
        ],
        threat_rows=[
            {
                "threatScore": 1.5,
                "threatLevel": "LOW",
                "feedName": None,
            }
        ],
    )
    connector._process_message(_v7_payload(observable))

    bundle = json.loads(helper.send_stix2_bundle.call_args[0][0])
    note = next(
        o
        for o in bundle["objects"]
        if o["type"] == "note" and o.get("abstract") == "Whisper threat intelligence"
    )
    assert "Threat assessment: LOW (score 1.5)" in note["content"]
    assert "Listed in" not in note["content"]


def test_threat_context_query_failure_does_not_fail_enrichment(
    connector, helper, client
):
    # Threat-context Phase B is best-effort — a transport error there must
    # still let the main bundle ship. Mirrors the Phase A LINKS_TO failure
    # path.
    from connector.exceptions import WhisperTransportError

    observable = {
        "id": "ipv4--x",
        "entity_type": "IPv4-Addr",
        "observable_value": "8.8.8.8",
    }
    main_result = CypherResult(
        columns=["n", "r", "m"],
        rows=[
            {
                "n": {"nodeId": "seed", "label": "IPV4", "name": "8.8.8.8"},
                "r": {"type": "RESOLVES_TO"},
                "m": {"nodeId": "h1", "label": "HOSTNAME", "name": "dns.google"},
            }
        ],
        statistics={"executionTimeMs": 2},
    )

    def _flaky(query, *_args, **_kwargs):
        if "FEED_SOURCE" in query and "LISTED_IN" in query:
            raise WhisperTransportError("threat-context timeout")
        return main_result

    client.execute_cypher.side_effect = _flaky

    result = connector._process_message(_v7_payload(observable))
    assert "Enriched 8.8.8.8" in result
    helper.send_stix2_bundle.assert_called_once()
    helper.connector_logger.error.assert_called()
    bundle = json.loads(helper.send_stix2_bundle.call_args[0][0])
    assert not any(
        o.get("abstract") == "Whisper threat intelligence"
        for o in bundle["objects"]
        if o["type"] == "note"
    )


def test_threat_context_skipped_for_autonomous_system_seed(connector, helper, client):
    # ASN nodes don't carry threat properties in Whisper's schema, so no
    # threat-context query should fire for Autonomous-System seeds.
    observable = {
        "id": "autonomous-system--x",
        "entity_type": "Autonomous-System",
        "observable_value": "Google LLC",
        "number": 15169,
    }
    client.execute_cypher.return_value = CypherResult(
        columns=["n", "r", "m"], rows=[], statistics={}
    )
    connector._process_message(_v7_payload(observable))

    queries = [c.args[0] for c in client.execute_cypher.call_args_list]
    for q in queries:
        assert not (
            "FEED_SOURCE" in q and "LISTED_IN" in q
        ), f"threat-context query unexpectedly fired for ASN: {q}"


def test_threat_context_note_ships_even_when_no_mappable_relationships(
    connector, helper, client
):
    # Seed has threat data but every main-query neighbour is a dropped
    # label (PREFIX). Without Phase B that's "No mappable Whisper
    # relationships" — but the threat Note IS meaningful, so the bundle
    # ships and the status is the regular "Enriched" line.
    observable = {
        "id": "ipv4--x",
        "entity_type": "IPv4-Addr",
        "observable_value": "192.0.2.7",
    }
    client.execute_cypher.side_effect = _threat_context_side_effect(
        main_rows=[
            {
                "n": {"nodeId": "seed", "label": "IPV4", "name": "192.0.2.7"},
                "r": {"type": "BELONGS_TO"},
                "m": {"nodeId": "p1", "label": "PREFIX", "name": "192.0.2.0/24"},
            }
        ],
        threat_rows=[
            {
                "threatScore": 7.2,
                "threatLevel": "HIGH",
                "isMalware": True,
                "feedName": "abuse-ch-feodo",
            }
        ],
    )
    result = connector._process_message(_v7_payload(observable))
    assert "Enriched 192.0.2.7" in result
    helper.send_stix2_bundle.assert_called_once()
    bundle = json.loads(helper.send_stix2_bundle.call_args[0][0])
    assert any(
        o.get("abstract") == "Whisper threat intelligence"
        for o in bundle["objects"]
        if o["type"] == "note"
    )


# --- Network-context Phase C (issue #48) -----------------------------------


def _network_context_side_effect(main_rows, network_rows, threat_rows=None):
    """Dispatch helper for Phase C tests.

    - LINKS_TO queries → empty (Phase A is independently tested).
    - threat-context query → ``threat_rows`` or empty.
    - network-context query (matches by "ANNOUNCED_BY" + "ROUTES") → ``network_rows``.
    - everything else → main template result.
    """
    threat_rows = threat_rows or []

    def _side_effect(query, *_args, **_kwargs):
        if "ANNOUNCED_BY" in query and "ROUTES" in query:
            return CypherResult(
                columns=[
                    "seed",
                    "asn",
                    "asnDescription",
                    "announcedPrefix",
                    "apThreatScore",
                    "apThreatLevel",
                    "isAnycast",
                    "isMoas",
                    "isWithdrawn",
                    "prefix",
                ],
                rows=network_rows,
                statistics={},
            )
        if "FEED_SOURCE" in query and "LISTED_IN" in query:
            return CypherResult(
                columns=["threatScore", "threatLevel", "feedName"],
                rows=threat_rows,
                statistics={},
            )
        if ":LINKS_TO" in query:
            cols = ["c"] if "count(m)" in query else ["n", "r", "m"]
            return CypherResult(columns=cols, rows=[], statistics={})
        return CypherResult(columns=["n", "r", "m"], rows=main_rows, statistics={})

    return _side_effect


def _ip_seed_row(value="8.8.8.8"):
    return {
        "n": {"nodeId": "seed", "label": "IPV4", "name": value},
        "r": {"type": "RESOLVES_TO"},
        "m": {"nodeId": "h1", "label": "HOSTNAME", "name": "dns.google"},
    }


def _network_row(
    *,
    seed_id="seed",
    seed_name="8.8.8.8",
    seed_label="IPV4",
    asn_id="asn1",
    asn_name="AS15169",
    asn_desc="GOOGLE - Google LLC",
    prefix_announced="8.8.8.0/24",
    score=1.0,
    level="LOW",
    anycast=True,
    moas=False,
    withdrawn=False,
    static_prefix="8.8.8.8/32",
):
    return {
        "seed": {"nodeId": seed_id, "label": seed_label, "name": seed_name},
        "asn": {"nodeId": asn_id, "label": "ASN", "name": asn_name},
        "asnDescription": asn_desc,
        "announcedPrefix": prefix_announced,
        "apThreatScore": score,
        "apThreatLevel": level,
        "isAnycast": anycast,
        "isMoas": moas,
        "isWithdrawn": withdrawn,
        "prefix": static_prefix,
    }


def test_network_context_emits_as_sco_edge_and_note(connector, helper, client):
    observable = {
        "id": "ipv4--x",
        "entity_type": "IPv4-Addr",
        "observable_value": "8.8.8.8",
    }
    client.execute_cypher.side_effect = _network_context_side_effect(
        main_rows=[_ip_seed_row()],
        network_rows=[_network_row()],
    )
    connector._process_message(_v7_payload(observable))

    bundle = json.loads(helper.send_stix2_bundle.call_args[0][0])

    as_sco = next(o for o in bundle["objects"] if o["type"] == "autonomous-system")
    assert as_sco["number"] == 15169
    # ASN_NAME human label should win over the bare "AS15169" string.
    assert as_sco["name"] == "GOOGLE - Google LLC"

    rels = [o for o in bundle["objects"] if o["type"] == "relationship"]
    announced_by = [r for r in rels if r.get("description") == "ANNOUNCED_BY"]
    assert len(announced_by) == 1
    rel = announced_by[0]
    assert rel["relationship_type"] == "related-to"
    assert rel["source_ref"].startswith("ipv4-addr--")
    assert rel["target_ref"] == as_sco["id"]

    notes = [
        o
        for o in bundle["objects"]
        if o["type"] == "note" and o.get("abstract") == "Whisper network context"
    ]
    assert len(notes) == 1
    content = notes[0]["content"]
    assert "Announced by: AS15169 (GOOGLE - Google LLC)" in content
    assert "Announced prefix: 8.8.8.0/24" in content
    assert "BGP flags: anycast" in content
    assert "ANNOUNCED_PREFIX threat: LOW (score 1)" in content
    assert "Static allocation: 8.8.8.8/32" in content


def test_network_context_falls_back_to_as_number_label_without_has_name(
    connector, helper, client
):
    observable = {
        "id": "ipv4--x",
        "entity_type": "IPv4-Addr",
        "observable_value": "203.0.113.5",
    }
    client.execute_cypher.side_effect = _network_context_side_effect(
        main_rows=[_ip_seed_row(value="203.0.113.5")],
        network_rows=[
            _network_row(
                seed_name="203.0.113.5",
                asn_id="asn99",
                asn_name="AS64500",
                asn_desc=None,
                prefix_announced="203.0.113.0/24",
                static_prefix=None,
                level="NONE",
            )
        ],
    )
    connector._process_message(_v7_payload(observable))

    bundle = json.loads(helper.send_stix2_bundle.call_args[0][0])
    as_sco = next(o for o in bundle["objects"] if o["type"] == "autonomous-system")
    assert as_sco["number"] == 64500
    # No HAS_NAME → name is omitted, so the SCO has just `number`.
    assert "name" not in as_sco

    note = next(
        o
        for o in bundle["objects"]
        if o["type"] == "note" and o.get("abstract") == "Whisper network context"
    )
    # Without a description the announcer line is just "AS64500".
    assert "Announced by: AS64500\n" in note["content"] or note["content"].endswith(
        "Announced by: AS64500"
    )
    # NONE-level threat line should be omitted.
    assert "ANNOUNCED_PREFIX threat" not in note["content"]


def test_network_context_handles_moas_multiple_announcers(connector, helper, client):
    observable = {
        "id": "ipv4--x",
        "entity_type": "IPv4-Addr",
        "observable_value": "1.2.3.4",
    }
    client.execute_cypher.side_effect = _network_context_side_effect(
        main_rows=[_ip_seed_row(value="1.2.3.4")],
        network_rows=[
            _network_row(
                seed_name="1.2.3.4",
                asn_id="asn-a",
                asn_name="AS100",
                asn_desc="ASN A Inc",
                prefix_announced="1.2.3.0/24",
                moas=True,
            ),
            _network_row(
                seed_name="1.2.3.4",
                asn_id="asn-b",
                asn_name="AS200",
                asn_desc="ASN B Corp",
                prefix_announced="1.2.0.0/16",
                moas=True,
                score=None,
                level=None,
                anycast=False,
            ),
        ],
    )
    connector._process_message(_v7_payload(observable))

    bundle = json.loads(helper.send_stix2_bundle.call_args[0][0])
    as_numbers = sorted(
        o["number"] for o in bundle["objects"] if o["type"] == "autonomous-system"
    )
    assert as_numbers == [100, 200]

    rels = [
        o
        for o in bundle["objects"]
        if o["type"] == "relationship" and o.get("description") == "ANNOUNCED_BY"
    ]
    assert len(rels) == 2

    note = next(
        o
        for o in bundle["objects"]
        if o["type"] == "note" and o.get("abstract") == "Whisper network context"
    )
    assert "Announced by 2 ASN(s) — multi-origin (MOAS):" in note["content"]
    assert "AS100 (ASN A Inc)" in note["content"]
    assert "AS200 (ASN B Corp)" in note["content"]


def test_network_context_dedups_repeated_asn_rows(connector, helper, client):
    # Whisper can emit multiple rows for the same ASN when the OPTIONAL
    # MATCHes cross-join (e.g. the IP has multiple BELONGS_TO PREFIXes).
    # The connector must dedup by ASN nodeId — otherwise we get duplicate
    # AS SCOs and edges.
    observable = {
        "id": "ipv4--x",
        "entity_type": "IPv4-Addr",
        "observable_value": "8.8.8.8",
    }
    client.execute_cypher.side_effect = _network_context_side_effect(
        main_rows=[_ip_seed_row()],
        network_rows=[
            _network_row(static_prefix="8.8.8.0/24"),
            _network_row(static_prefix="8.8.0.0/16"),  # same ASN, different PREFIX
        ],
    )
    connector._process_message(_v7_payload(observable))

    bundle = json.loads(helper.send_stix2_bundle.call_args[0][0])
    as_scos = [o for o in bundle["objects"] if o["type"] == "autonomous-system"]
    assert len(as_scos) == 1
    rels = [
        o
        for o in bundle["objects"]
        if o["type"] == "relationship" and o.get("description") == "ANNOUNCED_BY"
    ]
    assert len(rels) == 1


def test_network_context_skipped_for_domain_seed(connector, helper, client):
    observable = {
        "id": "domain-name--x",
        "entity_type": "Domain-Name",
        "value": "example.test",
    }
    client.execute_cypher.return_value = CypherResult(
        columns=["n", "r", "m"], rows=[], statistics={}
    )
    connector._process_message(_v7_payload(observable))

    queries = [c.args[0] for c in client.execute_cypher.call_args_list]
    for q in queries:
        assert not (
            "ANNOUNCED_BY" in q and "ROUTES" in q
        ), f"network-context query unexpectedly fired for Domain-Name: {q}"


def test_network_context_skipped_for_asn_seed(connector, helper, client):
    observable = {
        "id": "autonomous-system--x",
        "entity_type": "Autonomous-System",
        "observable_value": "Google LLC",
        "number": 15169,
    }
    client.execute_cypher.return_value = CypherResult(
        columns=["n", "r", "m"], rows=[], statistics={}
    )
    connector._process_message(_v7_payload(observable))

    queries = [c.args[0] for c in client.execute_cypher.call_args_list]
    for q in queries:
        assert not (
            "ANNOUNCED_BY" in q and "ROUTES" in q
        ), f"network-context query unexpectedly fired for ASN: {q}"


def test_network_context_query_failure_does_not_fail_enrichment(
    connector, helper, client
):
    from connector.exceptions import WhisperTransportError

    observable = {
        "id": "ipv4--x",
        "entity_type": "IPv4-Addr",
        "observable_value": "8.8.8.8",
    }
    main_result = CypherResult(
        columns=["n", "r", "m"],
        rows=[_ip_seed_row()],
        statistics={"executionTimeMs": 2},
    )

    def _flaky(query, *_args, **_kwargs):
        if "ANNOUNCED_BY" in query and "ROUTES" in query:
            raise WhisperTransportError("network-context timeout")
        return main_result

    client.execute_cypher.side_effect = _flaky

    result = connector._process_message(_v7_payload(observable))
    assert "Enriched 8.8.8.8" in result
    helper.send_stix2_bundle.assert_called_once()
    helper.connector_logger.error.assert_called()
    bundle = json.loads(helper.send_stix2_bundle.call_args[0][0])
    assert not any(o["type"] == "autonomous-system" for o in bundle["objects"])


def test_network_context_omits_static_allocation_when_same_as_announced(
    connector, helper, client
):
    # Issue #48 follow-up sanity: if Whisper returns a static PREFIX that
    # already matches the ANNOUNCED_PREFIX, the Note shouldn't repeat it
    # under a separate "Static allocation" line — that's pure noise.
    observable = {
        "id": "ipv4--x",
        "entity_type": "IPv4-Addr",
        "observable_value": "8.8.8.8",
    }
    client.execute_cypher.side_effect = _network_context_side_effect(
        main_rows=[_ip_seed_row()],
        network_rows=[_network_row(static_prefix="8.8.8.0/24")],  # same as announced
    )
    connector._process_message(_v7_payload(observable))

    bundle = json.loads(helper.send_stix2_bundle.call_args[0][0])
    note = next(
        o
        for o in bundle["objects"]
        if o["type"] == "note" and o.get("abstract") == "Whisper network context"
    )
    assert "Static allocation" not in note["content"]


# --- Dropped-HOSTNAME Note (issue #51) -------------------------------------


def test_dropped_hostnames_note_emitted_with_seed_attachment(connector, helper, client):
    # Main query has a NAMESERVER_FOR edge to an SPF-style invalid HOSTNAME.
    # The parser drops it (per #47); the connector now ALSO surfaces it
    # via a Note attached to the seed.
    observable = {
        "id": "domain-name--x",
        "entity_type": "Domain-Name",
        "value": "telus.ca",
    }
    client.execute_cypher.return_value = CypherResult(
        columns=["n", "r", "m"],
        rows=[
            {
                "n": {"nodeId": "seed", "label": "HOSTNAME", "name": "telus.ca"},
                "r": {"type": "NAMESERVER_FOR"},
                "m": {
                    "nodeId": "ns-invalid",
                    "label": "HOSTNAME",
                    "name": "_spf_telus_com.nssi.telus.com",
                },
            },
            {
                "n": {"nodeId": "seed", "label": "HOSTNAME", "name": "telus.ca"},
                "r": {"type": "NAMESERVER_FOR"},
                "m": {
                    "nodeId": "ns-valid",
                    "label": "HOSTNAME",
                    "name": "ns.telus.com",
                },
            },
        ],
        statistics={"executionTimeMs": 2},
    )
    connector._process_message(_v7_payload(observable))

    bundle = json.loads(helper.send_stix2_bundle.call_args[0][0])
    notes = [
        o
        for o in bundle["objects"]
        if o["type"] == "note"
        and o.get("abstract") == "Whisper dropped non-RFC-1035 DNS records"
    ]
    assert len(notes) == 1
    note = notes[0]
    assert "_spf_telus_com.nssi.telus.com" in note["content"]
    assert "Whisper edge: NAMESERVER_FOR" in note["content"]
    # Sanity: the VALID neighbour must not appear in the dropped list.
    assert "ns.telus.com" not in note["content"]
    # Note attached to the seed Domain-Name SCO.
    seed_id = next(
        o["id"]
        for o in bundle["objects"]
        if o["type"] == "domain-name" and o["value"] == "telus.ca"
    )
    assert note["object_refs"] == [seed_id]


def test_dropped_hostnames_note_skipped_when_nothing_dropped(connector, helper, client):
    # Clean enrichment with no underscore-bearing neighbours must not
    # produce a dropped-records Note — bundle shape unchanged from
    # pre-#51 behaviour.
    observable = {
        "id": "domain-name--x",
        "entity_type": "Domain-Name",
        "value": "telus.ca",
    }
    client.execute_cypher.return_value = CypherResult(
        columns=["n", "r", "m"],
        rows=[
            {
                "n": {"nodeId": "seed", "label": "HOSTNAME", "name": "telus.ca"},
                "r": {"type": "RESOLVES_TO"},
                "m": {"nodeId": "ip1", "label": "IPV4", "name": "1.2.3.4"},
            }
        ],
        statistics={},
    )
    connector._process_message(_v7_payload(observable))

    bundle = json.loads(helper.send_stix2_bundle.call_args[0][0])
    assert not any(
        o.get("abstract") == "Whisper dropped non-RFC-1035 DNS records"
        for o in bundle["objects"]
        if o["type"] == "note"
    )


def test_dropped_hostnames_note_dedupes_same_name_across_rows(
    connector, helper, client
):
    # The same invalid HOSTNAME may appear in multiple rows (e.g. once
    # via NAMESERVER_FOR, once via MAIL_FOR). The Note must list it
    # exactly once — the first edge type wins so the content is stable.
    observable = {
        "id": "domain-name--x",
        "entity_type": "Domain-Name",
        "value": "example.com",
    }
    client.execute_cypher.return_value = CypherResult(
        columns=["n", "r", "m"],
        rows=[
            {
                "n": {"nodeId": "seed", "label": "HOSTNAME", "name": "example.com"},
                "r": {"type": "NAMESERVER_FOR"},
                "m": {"nodeId": "bad", "label": "HOSTNAME", "name": "_spf.example.com"},
            },
            {
                "n": {"nodeId": "seed", "label": "HOSTNAME", "name": "example.com"},
                "r": {"type": "MAIL_FOR"},
                "m": {"nodeId": "bad", "label": "HOSTNAME", "name": "_spf.example.com"},
            },
        ],
        statistics={},
    )
    connector._process_message(_v7_payload(observable))

    bundle = json.loads(helper.send_stix2_bundle.call_args[0][0])
    note = next(
        o
        for o in bundle["objects"]
        if o["type"] == "note"
        and o.get("abstract") == "Whisper dropped non-RFC-1035 DNS records"
    )
    # The dropped name must appear exactly once in the body.
    assert note["content"].count("_spf.example.com") == 1


# --- v7 callback shape: TLP marking check (issue #65) ----------------------


def test_tlp_check_refuses_when_marking_exceeds_max_tlp(helper, client, make_config):
    # WhisperSettings is frozen, so we can't mutate the default fixture's
    # max_tlp — build a fresh instance via the make_config factory with
    # the lowered TLP ceiling, then feed it a TLP:RED observable. The
    # connector must refuse to enrich, log a warning, and NOT call Whisper.
    config = make_config(max_tlp="TLP:AMBER")
    connector = WhisperConnector(helper=helper, config=config, client=client)
    observable = {
        "id": "ipv4--x",
        "entity_type": "IPv4-Addr",
        "observable_value": "8.8.8.8",
        "objectMarking": [{"definition_type": "TLP", "definition": "TLP:RED"}],
    }
    result = connector._process_message(_v7_payload(observable))
    assert "exceeds whisper.max_tlp" in result
    helper.send_stix2_bundle.assert_not_called()
    helper.connector_logger.warning.assert_called()


def test_tlp_check_allows_marking_at_or_below_max_tlp(connector, client):
    # An AMBER observable under a TLP:RED ceiling must proceed to the
    # normal enrichment flow (cypher fired, bundle sent / not sent based
    # on whether Whisper has data).
    observable = {
        "id": "ipv4--x",
        "entity_type": "IPv4-Addr",
        "observable_value": "8.8.8.8",
        "objectMarking": [{"definition_type": "TLP", "definition": "TLP:AMBER"}],
    }
    client.execute_cypher.return_value = CypherResult(
        columns=["n", "r", "m"], rows=[], statistics={}
    )
    result = connector._process_message(_v7_payload(observable))
    assert "No Whisper data" in result  # ran the query, got nothing
    client.execute_cypher.assert_called()


def test_tlp_check_ignores_non_tlp_markings(connector, client):
    # Other marking definition types (e.g. statements, PAP) shouldn't
    # trigger the TLP-ceiling check — only `definition_type == "TLP"`.
    observable = {
        "id": "ipv4--x",
        "entity_type": "IPv4-Addr",
        "observable_value": "8.8.8.8",
        "objectMarking": [
            {"definition_type": "statement", "definition": "Some statement"},
        ],
    }
    client.execute_cypher.return_value = CypherResult(
        columns=["n", "r", "m"], rows=[], statistics={}
    )
    result = connector._process_message(_v7_payload(observable))
    # Got through the TLP gate to the enrichment path.
    assert "No Whisper data" in result
    client.execute_cypher.assert_called()


# --- v7 callback shape: playbook pass-through (issue #65) -----------------


def test_unsupported_entity_with_event_type_returns_not_supported(
    connector, helper, client
):
    # Real-time event for an out-of-scope entity: return the clear
    # "not supported" status; do NOT ship a bundle, do NOT call Whisper.
    observable = {
        "id": "url--x",
        "entity_type": "Url",
        "value": "https://example.test/",
    }
    result = connector._process_message(_v7_payload(observable, event_type="create"))
    assert "not supported" in result
    client.execute_cypher.assert_not_called()
    helper.send_stix2_bundle.assert_not_called()


def test_unsupported_entity_in_playbook_chain_passes_bundle_through(
    connector, helper, client
):
    # No event_type means the worker handed this to us via a playbook
    # chain. The v7 playbook_compatible=True contract: out-of-scope
    # entities still get their original stix_objects bundle shipped
    # downstream, unchanged. Critical so playbook chains don't lose
    # data when they pass through this connector.
    observable = {
        "id": "url--x",
        "entity_type": "Url",
        "value": "https://example.test/",
    }
    playbook_objects = [
        {
            "type": "url",
            "id": "url--00000000-0000-0000-0000-000000000001",
            "value": "https://example.test/",
        },
        {
            "type": "marking-definition",
            "id": "marking-definition--00000000-0000-0000-0000-000000000002",
        },
    ]
    result = connector._process_message(
        _v7_payload(observable, event_type=None, stix_objects=playbook_objects)
    )
    assert "playbook pass-through" in result
    client.execute_cypher.assert_not_called()
    helper.stix2_create_bundle.assert_called_once_with(playbook_objects)
    helper.send_stix2_bundle.assert_called_once()


def test_playbook_chain_with_no_stix_objects_returns_status_no_send(
    connector, helper, client
):
    # Defensive: playbook chain delivered an out-of-scope entity with no
    # supporting stix_objects. We have nothing to forward, so don't call
    # send_stix2_bundle — just return a status string.
    observable = {
        "id": "url--x",
        "entity_type": "Url",
        "value": "https://example.test/",
    }
    result = connector._process_message(
        _v7_payload(observable, event_type=None, stix_objects=[])
    )
    assert "playbook pass-through" in result
    assert "no stix_objects" in result
    helper.send_stix2_bundle.assert_not_called()


# --- Targeted Domain-Name enrichment: acceptance-criteria coverage (#61) ----


def _domain_obs(value="example.test"):
    return {"id": "domain-name--x", "entity_type": "Domain-Name", "value": value}


def test_domain_direct_facts_emit_stable_descriptions(connector, helper, client):
    # AC #4: relationship descriptions are stable, human-readable category
    # names (a-record, mx-server, name-server, registrar, whois-email) — not
    # raw Whisper edge types. A/AAAA stay native resolves-to.
    client.execute_cypher.side_effect = _domain_side_effect(
        direct={
            "a-record": [_hm_row("example.test", "seed", "ip-a", "IPV4", "1.2.3.4")],
            "mx-server": [
                _hm_row("example.test", "seed", "mx1", "HOSTNAME", "mx.example.test")
            ],
            "name-server": [
                _hm_row("example.test", "seed", "ns1", "HOSTNAME", "ns.example.test")
            ],
            "registrar": [
                _hm_row("example.test", "seed", "reg1", "REGISTRAR", "MarkMonitor Inc.")
            ],
            "whois-email": [
                _hm_row("example.test", "seed", "em1", "EMAIL", "abuse@example.test")
            ],
        },
    )
    connector._process_message(_v7_payload(_domain_obs()))

    bundle = json.loads(helper.send_stix2_bundle.call_args[0][0])
    rels = [o for o in bundle["objects"] if o["type"] == "relationship"]
    by_desc = {r.get("description"): r for r in rels}
    assert {"a-record", "mx-server", "name-server", "registrar", "whois-email"} <= set(
        by_desc
    )
    assert by_desc["a-record"]["relationship_type"] == "resolves-to"
    assert by_desc["mx-server"]["relationship_type"] == "related-to"
    assert by_desc["registrar"]["relationship_type"] == "related-to"


def test_domain_spf_and_phone_summarized_as_notes(connector, helper, client):
    # AC #5: data without a clean SCO (SPF policy, WHOIS phone) is summarized
    # in Notes rather than silently dropped.
    client.execute_cypher.side_effect = _domain_side_effect(
        spf_rows=[
            {"spfType": "SPF_INCLUDE", "target": "_spf.google.com"},
            {"spfType": "SPF_IP", "target": "192.0.2.0/24"},
        ],
        phone_rows=[{"phone": "+1.5555550100"}],
    )
    connector._process_message(_v7_payload(_domain_obs()))

    bundle = json.loads(helper.send_stix2_bundle.call_args[0][0])
    abstracts = {o.get("abstract") for o in bundle["objects"] if o["type"] == "note"}
    assert "Whisper SPF policy" in abstracts
    assert "Whisper WHOIS phone contacts" in abstracts
    spf = next(
        o
        for o in bundle["objects"]
        if o["type"] == "note" and o["abstract"] == "Whisper SPF policy"
    )
    assert "_spf.google.com" in spf["content"]
    phone = next(
        o
        for o in bundle["objects"]
        if o["type"] == "note" and o["abstract"] == "Whisper WHOIS phone contacts"
    )
    assert "+1.5555550100" in phone["content"]


def test_domain_pivot_overflow_note_reports_total_and_displayed(
    connector, helper, client
):
    # AC #6: a capped pivot whose true count exceeds the cap produces a Note
    # carrying the total and the displayed count.
    client.execute_cypher.side_effect = _domain_side_effect(
        counts={"subdomain": 20_957_725},
    )
    connector._process_message(_v7_payload(_domain_obs()))

    bundle = json.loads(helper.send_stix2_bundle.call_args[0][0])
    note = next(
        o
        for o in bundle["objects"]
        if o["type"] == "note" and o.get("abstract") == "Whisper subdomain overflow"
    )
    assert "20,957,725" in note["content"]
    assert "showing first 25" in note["content"]
    assert "subdomains of example.test" in note["content"]


def test_domain_lookalikes_note_lists_existing_variants(connector, helper, client):
    # AC #15: registered lookalikes surface in a "Whisper domain variants"
    # Note with method + confidence, flagged as existence-not-malice.
    client.execute_cypher.side_effect = _domain_side_effect(
        variant_names=["example.com"],  # a TLD-swap variant that "exists"
    )
    connector._process_message(_v7_payload(_domain_obs()))

    bundle = json.loads(helper.send_stix2_bundle.call_args[0][0])
    note = next(
        o
        for o in bundle["objects"]
        if o["type"] == "note" and o.get("abstract") == "Whisper domain variants"
    )
    assert "example.com" in note["content"]
    assert "tld-swap" in note["content"]
    assert "not a malice verdict" in note["content"]


def test_domain_enrichment_is_idempotent(connector, helper, client):
    # AC #7: re-running the same enrichment produces the same STIX object IDs
    # and no duplicates.
    def fresh_side_effect():
        return _domain_side_effect(
            direct={
                "a-record": [
                    _hm_row("example.test", "seed", "ip-a", "IPV4", "1.2.3.4")
                ],
                "mx-server": [
                    _hm_row(
                        "example.test", "seed", "mx1", "HOSTNAME", "mx.example.test"
                    )
                ],
            },
            counts={"subdomain": 100},
            threat_rows=[{"threatScore": 2.0, "threatLevel": "LOW", "feedName": None}],
            variant_names=["example.com"],
        )

    client.execute_cypher.side_effect = fresh_side_effect()
    connector._process_message(_v7_payload(_domain_obs()))
    first = json.loads(helper.send_stix2_bundle.call_args[0][0])
    first_ids = sorted(o["id"] for o in first["objects"])

    helper.send_stix2_bundle.reset_mock()
    client.execute_cypher.side_effect = fresh_side_effect()
    connector._process_message(_v7_payload(_domain_obs()))
    second = json.loads(helper.send_stix2_bundle.call_args[0][0])
    second_ids = sorted(o["id"] for o in second["objects"])

    assert first_ids == second_ids
    # No duplicate IDs within a single bundle.
    assert len(first_ids) == len(set(first_ids))


def test_current_registrar_wins_when_node_is_also_previous_registrar(
    connector, helper, client
):
    # Regression: a registrar that is BOTH the current registrar and a
    # historical one is the SAME Whisper REGISTRAR node under HAS_REGISTRAR
    # and PREV_REGISTRAR. Both emit a related-to edge to that node; the
    # converter keys relationships off (source, target, type) — description
    # excluded — so without dedup they collide and `previous-registrar`
    # (emitted later) silently overwrites `registrar`. The connector must
    # keep the current-state `registrar` description and still emit the
    # genuinely-previous-only registrar separately.
    shared = _hm_row(
        "example.test", "seed", "reg-shared", "REGISTRAR", "registrar:MarkMonitor Inc."
    )
    prev_only = _hm_row(
        "example.test", "seed", "reg-old", "REGISTRAR", "registrar:Gandi SAS"
    )
    client.execute_cypher.side_effect = _domain_side_effect(
        direct={
            "registrar": [shared],
            "previous-registrar": [shared, prev_only],
        },
    )
    connector._process_message(_v7_payload(_domain_obs()))

    bundle = json.loads(helper.send_stix2_bundle.call_args[0][0])
    rels = [o for o in bundle["objects"] if o["type"] == "relationship"]
    by_target = {}
    id_by_whisper = {  # identity SCO id is UUIDv5; map via name to assert target
        o["name"]: o["id"] for o in bundle["objects"] if o["type"] == "identity"
    }
    for r in rels:
        by_target.setdefault(r["target_ref"], []).append(r.get("description"))
    shared_descs = by_target.get(id_by_whisper["MarkMonitor Inc."], [])
    prev_descs = by_target.get(id_by_whisper["Gandi SAS"], [])
    # Exactly one edge to the shared node, described as current registrar.
    assert shared_descs == ["registrar"]
    # The previous-only registrar still surfaces as previous-registrar.
    assert prev_descs == ["previous-registrar"]

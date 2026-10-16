import json

import pytest
from conftest import CERT_SUBJECT, JARM, RULE
from connectors_sdk.connectors.internal_hunt import HuntTranslationError
from infrastructure_tracker.rule import (
    build_plan,
    load_plan,
    parse_rule,
    render_plan,
    source_queries,
)


def test_parse_rule_reads_yaml():
    rule = parse_rule(RULE)
    assert [(fp.kind, fp.value) for fp in rule.fingerprints] == [
        ("jarm", JARM),
        ("certificate_subject", CERT_SUBJECT),
    ]
    assert rule.sources is None and rule.queries == {}


def test_parse_rule_reads_json_and_numeric_asns():
    rule = parse_rule(json.dumps({"fingerprints": [{"kind": "asn", "value": 20473}]}))
    assert rule.fingerprints[0].value == "20473"
    assert rule.fingerprints[0].asn == 20473


def test_parse_rule_accepts_queries_only():
    rule = parse_rule("queries:\n  urlscan: 'page.domain:example.com'\n")
    assert rule.fingerprints == []


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("fingerprints: [", "not valid YAML"),
        ("- jarm", "must be a YAML mapping"),
        ("fingerprints:\n  - kind: md5\n    value: x\n", "fingerprints.0.kind"),
        ("fingerprints:\n  - kind: asn\n    value: ASX\n", "is not an ASN"),
        ("fingerprints: []\nextra: 1\n", "extra"),
        ("sources: [censys]\n", "no fingerprint and no query"),
        ("queries:\n  censys: '  '\n", "no fingerprint and no query"),
    ],
)
def test_parse_rule_rejects_invalid_rules(text, message):
    with pytest.raises(HuntTranslationError, match=message):
        parse_rule(text)


def test_censys_queries_match_any_fingerprint():
    rule = parse_rule("""
fingerprints:
  - {kind: jarm, value: abc}
  - {kind: ja4x, value: def}
  - {kind: ja4s, value: ghi}
  - {kind: certificate_sha256, value: AA}
  - {kind: certificate_issuer, value: 'CN="Evil" CA'}
  - {kind: http_title, value: Login}
  - {kind: http_body_sha256, value: BB}
  - {kind: http_server, value: nginx}
  - {kind: banner_sha256, value: CC}
  - {kind: asn, value: AS20473}
""")
    (query,) = source_queries(rule, "censys")
    assert query == " or ".join(
        [
            '(host.services.jarm.fingerprint = "abc")',
            '(host.services.cert.parsed.ja4x = "def")',
            '(host.services.tls.ja4s = "ghi")',
            '(host.services.cert.fingerprint_sha256 = "AA")',
            '(host.services.cert.parsed.issuer_dn = "CN=\\"Evil\\" CA")',
            '(host.services.endpoints.http.html_title = "Login")',
            '(host.services.endpoints.http.body_hash_sha256 = "BB")',
            '(host.services.endpoints.http.headers: (key = "Server" and value = "nginx"))',
            '(host.services.banner_hash_sha256 = "CC")',
            '(host.autonomous_system.asn = "20473")',
        ]
    )


def test_source_queries_per_source():
    rule = parse_rule("""
fingerprints:
  - {kind: jarm, value: abc}
  - {kind: http_title, value: Login}
  - {kind: http_body_sha256, value: BB}
  - {kind: asn, value: '13335'}
queries:
  urlscan: 'page.domain:example.com'
""")
    assert source_queries(rule, "silentpush") == [
        '(jarm = "abc") OR (htmltitle = "Login") OR (html_body_sha256 = "BB")'
    ]
    assert source_queries(rule, "urlscan") == [
        '(page.title:"Login") OR (hash:bb) OR (page.asn:AS13335)',
        "page.domain:example.com",
    ]
    assert source_queries(rule, "cymru_scout") == ["abc"]


def test_source_queries_single_match_is_not_parenthesized():
    rule = parse_rule("fingerprints:\n  - {kind: http_server, value: nginx}\n")
    assert source_queries(rule, "silentpush") == ['header.server = "nginx"']
    assert source_queries(rule, "urlscan") == ['page.server:"nginx"']
    assert source_queries(rule, "cymru_scout") == []


def test_build_plan_keeps_the_selected_configured_sources():
    rule = parse_rule(RULE + "sources: [censys, cymru_scout]\n")
    plan = build_plan(rule, ["cymru_scout", "silentpush", "censys"])
    assert list(plan) == ["censys", "cymru_scout"]
    assert plan["cymru_scout"] == [JARM]


def test_build_plan_drops_sources_without_queries():
    rule = parse_rule(RULE)
    plan = build_plan(rule, ["censys", "urlscan"])
    assert list(plan) == ["censys"]


def test_build_plan_requires_a_configured_source():
    rule = parse_rule(RULE + "sources: [urlscan]\n")
    with pytest.raises(HuntTranslationError, match=r"\(urlscan\) is configured"):
        build_plan(rule, ["censys"])


def test_build_plan_requires_a_source_searching_the_fingerprints():
    rule = parse_rule("fingerprints:\n  - {kind: ja4x, value: x}\n")
    with pytest.raises(
        HuntTranslationError, match="fingerprints of the rule \\(ja4x\\)"
    ):
        build_plan(rule, ["urlscan", "silentpush"])


def test_plans_round_trip():
    plan = {"censys": ['jarm = "abc"'], "urlscan": ['page.title:"caf\u00e9"']}
    text = render_plan(plan)
    assert "caf\u00e9" in text
    assert load_plan(text) == plan


@pytest.mark.parametrize(
    "text", ["not json", "[]", '{"shodan": []}', '{"censys": "q"}', '{"censys": [1]}']
)
def test_load_plan_rejects_invalid_plans(text):
    with pytest.raises(HuntTranslationError, match="plan is invalid"):
        load_plan(text)

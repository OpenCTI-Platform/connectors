# pragma: no cover
# type: ignore
"""Tests of the fingerprint documents of infrastructure hunts."""

import json

import pytest
from connectors_sdk.connectors.internal_hunt import (
    FingerprintRule,
    HuntTranslationError,
    describe_fingerprints,
    join_matches,
    load_queries,
    parse_fingerprint_rule,
    quote_value,
    render_queries,
)

JARM = "07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1"
DOCUMENT = f"""
fingerprints:
  - kind: jarm
    value: {JARM}
  - kind: certificate_subject
    value: '  CN=Major Cobalt Strike, O=cobaltstrike  '
"""


def test_a_yaml_document_lists_its_fingerprints():
    # Given/When a YAML document is parsed
    rule = parse_fingerprint_rule(DOCUMENT)

    # Then its fingerprints are kept in order, values stripped
    assert [(fp.kind, fp.value) for fp in rule.fingerprints] == [
        ("jarm", JARM),
        ("certificate_subject", "CN=Major Cobalt Strike, O=cobaltstrike"),
    ]
    assert rule.queries == {}
    assert rule.raw_query("censys") == ""


def test_a_json_document_takes_numeric_asns():
    # Given/When a JSON document with a numeric ASN is parsed
    rule = parse_fingerprint_rule(
        json.dumps({"fingerprints": [{"kind": "asn", "value": 20473}]})
    )

    # Then the ASN reads as a number
    assert rule.fingerprints[0].value == "20473"
    assert rule.fingerprints[0].asn == 20473


def test_a_document_may_hold_raw_queries_only():
    # Given/When a document holds a raw query and no fingerprint
    rule = parse_fingerprint_rule("queries:\n  urlscan: '  page.domain:example.com '\n")

    # Then the raw query of the platform is kept, stripped
    assert rule.fingerprints == []
    assert rule.raw_query("urlscan") == "page.domain:example.com"
    assert rule.raw_query("shodan") == ""


def test_fingerprints_of_some_kinds_keep_the_document_order():
    # Given a document with three fingerprints
    rule = parse_fingerprint_rule(
        "fingerprints:\n"
        "  - {kind: http_title, value: Login}\n"
        "  - {kind: jarm, value: abc}\n"
        "  - {kind: asn, value: AS1}\n"
    )

    # When the fingerprints of two kinds are selected
    selected = rule.of_kinds(("asn", "http_title"))

    # Then they come in document order
    assert [fp.kind for fp in selected] == ["http_title", "asn"]


@pytest.mark.parametrize(
    ("text", "message"),
    [
        pytest.param("fingerprints: [", "not valid YAML", id="invalid_yaml"),
        pytest.param("- jarm", "must be a YAML mapping", id="not_a_mapping"),
        pytest.param(
            "fingerprints:\n  - kind: md5\n    value: x\n",
            "fingerprints.0.kind",
            id="unknown_kind",
        ),
        pytest.param(
            "fingerprints:\n  - kind: asn\n    value: ASX\n",
            "is not an ASN",
            id="invalid_asn",
        ),
        pytest.param(
            "fingerprints:\n  - kind: jarm\n    value: true\n",
            "fingerprints.0.value",
            id="boolean_value",
        ),
        pytest.param("fingerprints: []\nextra: 1\n", "extra", id="extra_key"),
        pytest.param(
            "queries:\n  internet: 'x'\n",
            "unknown platform",
            id="unknown_platform",
        ),
        pytest.param("queries:\n  censys: '  '\n", "no fingerprint", id="empty"),
    ],
)
def test_invalid_documents_are_rejected(text, message):
    # Given/When an invalid document is parsed
    # Then the hunt cannot be translated
    with pytest.raises(HuntTranslationError, match=message):
        parse_fingerprint_rule(text)


def test_a_description_names_the_first_fingerprints_and_the_raw_queries():
    # Given a document with seven fingerprints and two raw queries
    fingerprints = [{"kind": "http_title", "value": f"title {i}"} for i in range(7)]
    rule = FingerprintRule.model_validate(
        {"fingerprints": fingerprints, "queries": {"shodan": "a", "censys": "b"}}
    )

    # When it is described
    description = describe_fingerprints(rule)

    # Then the first five fingerprints are named, then the rest is counted
    assert description == (
        "http_title title 0, http_title title 1, http_title title 2, "
        "http_title title 3, http_title title 4, 2 more, queries on censys, shodan"
    )


def test_values_are_quoted_and_matches_joined():
    # Given/When values are quoted and matches joined
    # Then quotes and backslashes are escaped, and several matches are parenthesized
    assert quote_value('C:\\a "b"') == '"C:\\\\a \\"b\\""'
    assert join_matches(["a = 1"], " OR ") == "a = 1"
    assert join_matches(["a = 1", "b = 2"], " or ") == "(a = 1) or (b = 2)"


def test_queries_round_trip_through_json():
    # Given queries with a non ASCII character
    queries = ['jarm = "abc"', 'page.title:"caf\u00e9"']

    # When they are rendered then loaded
    text = render_queries(queries)

    # Then they are kept as written
    assert "caf\u00e9" in text
    assert load_queries(text) == queries


@pytest.mark.parametrize(
    "text",
    ["not json", "{}", '["q", 1]', '["  "]'],
)
def test_invalid_queries_are_rejected(text):
    # Given/When text that is not a list of queries is loaded
    # Then it is rejected
    with pytest.raises(HuntTranslationError, match="queries are invalid"):
        load_queries(text)

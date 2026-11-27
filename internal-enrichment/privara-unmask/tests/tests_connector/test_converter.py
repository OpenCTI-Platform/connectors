import json

import pytest
import stix2
from connector.converter_to_stix import C2Target, ConverterToStix, result_markdown
from stix2patterns.validator import run_validator

SAMPLE_REF = "artifact--6b6f6f6b-0000-4000-8000-000000000001"
MARKING = "marking-definition--826578e1-40ad-459f-bc73-ede076f81f37"
WEB_URL = "https://app.tajapps.com/dashboard/unmask/jobs/j_a"

LIVE_JOB = {
    "job_id": "j_a",
    "batch_id": "b_x",
    "filename": "a.apk",
    "sha256": "ab" * 32,
    "package": "com.x",
    "status": "done",
    "outcome": "live",
    "charge_cents": 2500,
    "created_at": 1764000000,
    "finished_at": 1764000900,
    "family": {"name": "Octo", "confidence": 0.55},
    "c2": [
        {
            "value": "http://1.2.3.4/x.php",
            "defanged": "hxxp://1.2.3[.]4/x.php",
            "kind": "url",
            "host": "1.2.3.4",
            "port": None,
            "live": True,
            "confidence": 0.89,
            "source": "runtime_traffic",
        },
        {
            "value": "evil.example:8443",
            "defanged": "evil[.]example:8443",
            "kind": "host_port",
            "host": "evil.example",
            "port": 8443,
            "live": False,
            "confidence": 0.8,
            "source": "decrypted_config",
        },
    ],
    "rejected_candidates": [
        {"defanged": "hxxps://cdn[.]example", "reason": "non_code_asset"}
    ],
    "android": {"tried": ["17", "14"], "ran_on": "14"},
    "report_url": "https://app.tajapps.com/api/unmask/v1/jobs/j_a/report.pdf",
    "web_url": WEB_URL,
}


def _parse(objects):
    """Serialize like the connector does, then parse back with the stix2 library."""
    serialized = [
        json.loads(o.serialize()) if hasattr(o, "serialize") else o for o in objects
    ]
    bundle = {
        "type": "bundle",
        "id": "bundle--00000000-0000-4000-8000-000000000000",
        "objects": serialized,
    }
    return stix2.parse(json.dumps(bundle), allow_custom=True)


@pytest.mark.parametrize(
    "entry,pattern,main_type",
    [
        (
            {"kind": "url", "value": "http://1.2.3.4/x.php", "host": "1.2.3.4"},
            "[url:value = 'http://1.2.3.4/x.php']",
            "Url",
        ),
        (
            {"kind": "ip", "value": "1.2.3.4", "host": "1.2.3.4"},
            "[ipv4-addr:value = '1.2.3.4']",
            "IPv4-Addr",
        ),
        (
            {"kind": "ip", "value": "2001:db8::1", "host": "2001:db8::1"},
            "[ipv6-addr:value = '2001:db8::1']",
            "IPv6-Addr",
        ),
        (
            {"kind": "domain", "value": "evil.example", "host": "evil.example"},
            "[domain-name:value = 'evil.example']",
            "Domain-Name",
        ),
        (
            {
                "kind": "host_port",
                "value": "1.2.3.4:7777",
                "host": "1.2.3.4",
                "port": 7777,
            },
            "[network-traffic:dst_ref.type = 'ipv4-addr' AND network-traffic:dst_ref.value = '1.2.3.4' AND network-traffic:dst_port = 7777]",
            "IPv4-Addr",
        ),
        (
            {
                "kind": "host_port",
                "value": "x.example:81",
                "host": "x.example",
                "port": 81,
            },
            "[network-traffic:dst_ref.type = 'domain-name' AND network-traffic:dst_ref.value = 'x.example' AND network-traffic:dst_port = 81]",
            "Domain-Name",
        ),
        (
            {"kind": "url", "value": "https://x.example/a'b"},
            "[url:value = 'https://x.example/a\\'b']",
            "Url",
        ),
    ],
)
def test_c2_target_patterns(entry, pattern, main_type):
    target = C2Target(entry)
    assert target.pattern == pattern
    assert target.main_observable_type == main_type
    assert run_validator(target.pattern, stix_version="2.1") == []


@pytest.mark.parametrize(
    "entry",
    [
        {"kind": "ip_port", "value": "1.2.3.4:1"},  # not in the enum
        {"kind": None, "value": "1.2.3.4"},  # no guessing from the value
        {"kind": "host_port", "value": "x:1", "host": "x", "port": None},
        {"kind": "ip", "value": "evil.example", "host": "evil.example"},
    ],
)
def test_c2_target_refuses_what_the_spec_does_not_define(entry):
    with pytest.raises(ValueError):
        C2Target(entry)


def test_live_result_is_a_valid_bundle():
    objects = ConverterToStix().build_result(LIVE_JOB, SAMPLE_REF, [MARKING])
    bundle = _parse(objects)
    by_type = {}
    for obj in bundle.objects:
        by_type.setdefault(obj.type, []).append(obj)

    indicators = by_type["indicator"]
    assert {i.name for i in indicators} == {"http://1.2.3.4/x.php", "evil.example:8443"}
    for indicator in indicators:
        assert indicator.object_marking_refs == [MARKING]
        assert indicator.created_by_ref == by_type["identity"][0].id
        assert indicator.external_references[0].external_id == "j_a"
        assert indicator.external_references[0].url == WEB_URL
    assert by_type["malware"][0].name == "Octo"
    rel_types = sorted(r.relationship_type for r in by_type["relationship"])
    # sample->malware, 2x sample->indicator, 2x indicates, 2x based-on
    assert rel_types == [
        "based-on",
        "based-on",
        "indicates",
        "indicates",
        "related-to",
        "related-to",
        "related-to",
    ]
    assert {o.type for o in bundle.objects} >= {"url", "domain-name"}
    note = by_type["note"][0]
    assert "charged $25.00" in note.abstract
    assert SAMPLE_REF in note.object_refs
    assert WEB_URL in note.content
    assert "report.pdf" not in note.content


def test_rejected_candidates_are_never_indicators():
    objects = ConverterToStix().build_result(LIVE_JOB, SAMPLE_REF, [])
    text = json.dumps([json.loads(o.serialize()) for o in objects])
    assert "cdn.example" not in text
    assert "1 candidate(s) were rejected" in result_markdown(LIVE_JOB)


def test_unknown_kind_is_listed_but_not_converted():
    job = {**LIVE_JOB, "c2": [{**LIVE_JOB["c2"][0], "kind": "onion"}]}
    objects = ConverterToStix().build_result(job, SAMPLE_REF, [])
    assert not [o for o in objects if o.type == "indicator"]
    assert "hxxp://1.2.3[.]4/x.php" in result_markdown(job)


def test_note_shows_defanged_values_only():
    body = result_markdown(LIVE_JOB)
    assert "hxxp://1.2.3[.]4/x.php" in body
    assert "http://1.2.3.4/x.php" not in body


def test_ids_are_deterministic():
    first = ConverterToStix().build_result(LIVE_JOB, SAMPLE_REF, [])
    second = ConverterToStix().build_result(LIVE_JOB, SAMPLE_REF, [])
    assert [o.id for o in first] == [o.id for o in second]


@pytest.mark.parametrize(
    "status,outcome,expected",
    [
        ("done", "none", "charged $0.00"),
        ("done", "void", "never charged"),
        ("failed", None, "failed (not charged)"),
        ("canceled", None, "canceled (not charged)"),
    ],
)
def test_no_c2_results_only_note(status, outcome, expected):
    job = {
        **LIVE_JOB,
        "status": status,
        "outcome": outcome,
        "charge_cents": 0,
        "c2": [],
        "family": None,
        "rejected_candidates": [],
    }
    bundle = _parse(ConverterToStix().build_result(job, SAMPLE_REF, []))
    assert sorted(o.type for o in bundle.objects) == ["identity", "note"]
    note = [o for o in bundle.objects if o.type == "note"][0]
    assert expected in note.abstract


def test_reused_result_says_no_new_charge():
    objects = ConverterToStix().build_result(LIVE_JOB, SAMPLE_REF, [], reused=True)
    note = [o for o in objects if o.type == "note"][0]
    assert "no new charge" in note.abstract


def test_without_observables():
    objects = ConverterToStix(create_observables=False).build_result(
        LIVE_JOB, SAMPLE_REF, []
    )
    assert not [o for o in objects if o.type in ("url", "domain-name", "ipv4-addr")]

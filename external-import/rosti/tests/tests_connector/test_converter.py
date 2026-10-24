"""Tests for the Rösti -> STIX conversion."""

import datetime as dt

import pytest
from conftest import load_fixture
from connector.converter import ConversionError, RostiConverter, report_stix_id
from connectors_sdk.models import Reference
from pycti import Indicator as PyctiIndicator
from rosti_client.models import IOC, Mitre, Report, Yara


def make_ioc(ioc_type: str, value: str, **kwargs) -> IOC:
    data = {
        "id": "test-ioc",
        "type": ioc_type,
        "value": value,
        "category": "network_activity",
        "date": "2026-10-02",
        "ids": True,
        "report": "r1xSdqAy",
        **kwargs,
    }
    return IOC.model_validate(data)


def by_type(objects, stix_type):
    return [o for o in objects if o["type"] == stix_type]


@pytest.fixture
def converter() -> RostiConverter:
    return RostiConverter()


# ---------------------------------------------------------------------------
# IOCs
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "ioc_type, value, pattern, observable_type",
    [
        (
            "domain",
            "evil.example",
            "[domain-name:value = 'evil.example']",
            "domain-name",
        ),
        ("ip", "45.129.0.192", "[ipv4-addr:value = '45.129.0.192']", "ipv4-addr"),
        ("ip", "2001:db8::1", "[ipv6-addr:value = '2001:db8::1']", "ipv6-addr"),
        ("cidr", "10.1.0.0/16", "[ipv4-addr:value = '10.1.0.0/16']", "ipv4-addr"),
        (
            "url",
            "https://evil.example/a?b=1",
            "[url:value = 'https://evil.example/a?b=1']",
            "url",
        ),
        (
            "email",
            "bad@evil.example",
            "[email-addr:value = 'bad@evil.example']",
            "email-addr",
        ),
        (
            "md5",
            "49a7156a7d043cc8f9f680579db22f86",
            "[file:hashes.'MD5' = '49a7156a7d043cc8f9f680579db22f86']",
            "file",
        ),
        ("sha1", "a" * 40, f"[file:hashes.'SHA-1' = '{'a' * 40}']", "file"),
        ("sha256", "b" * 64, f"[file:hashes.'SHA-256' = '{'b' * 64}']", "file"),
        ("sha512", "c" * 128, f"[file:hashes.'SHA-512' = '{'c' * 128}']", "file"),
        ("ssdeep", "3:abc:def", "[file:hashes.'SSDEEP' = '3:abc:def']", "file"),
        ("filename", "invoice.exe", "[file:name = 'invoice.exe']", "file"),
        ("filepath", "C:\\Users\\Public\\run.dll", "[file:name = 'run.dll']", "file"),
        ("mutex", "Global\\abc", "[mutex:name = 'Global\\\\abc']", "mutex"),
        (
            "user-agent",
            "Mozilla/5.0 (X)",
            "[user-agent:value = 'Mozilla/5.0 (X)']",
            "user-agent",
        ),
        (
            "blockchain",
            "bc1qxyz",
            "[cryptocurrency-wallet:value = 'bc1qxyz']",
            "cryptocurrency-wallet",
        ),
        (
            "ip:port",
            "45.129.0.192:8443",
            "[ipv4-addr:value = '45.129.0.192']",
            "ipv4-addr",
        ),
        (
            "domain:port",
            "evil.example:443",
            "[domain-name:value = 'evil.example']",
            "domain-name",
        ),
    ],
)
def test_ioc_types_map_to_pattern_and_observable(
    converter, ioc_type, value, pattern, observable_type
):
    objects = converter.convert_ioc(make_ioc(ioc_type, value))

    indicator = by_type(objects, "indicator")[0]
    assert indicator["pattern"] == pattern
    assert indicator["pattern_type"] == "stix"
    assert indicator["id"] == PyctiIndicator.generate_id(pattern)
    observables = by_type(objects, observable_type)
    assert len(observables) == 1
    based_on = by_type(objects, "relationship")[0]
    assert based_on["relationship_type"] == "based-on"
    assert based_on["source_ref"] == indicator["id"]
    assert based_on["target_ref"] == observables[0]["id"]


def test_port_is_kept_in_description(converter):
    objects = converter.convert_ioc(make_ioc("ip:port", "45.129.0.192:8443"))
    assert "port 8443" in by_type(objects, "indicator")[0]["description"]


def test_filepath_keeps_full_path_in_description(converter):
    objects = converter.convert_ioc(make_ioc("filepath", "C:\\Users\\Public\\run.dll"))
    assert (
        "C:\\Users\\Public\\run.dll" in by_type(objects, "indicator")[0]["description"]
    )


def test_domain_ip_creates_resolves_to(converter):
    objects = converter.convert_ioc(make_ioc("domain:ip", "evil.example:45.129.0.192"))
    indicator = by_type(objects, "indicator")[0]
    assert indicator["pattern"] == "[domain-name:value = 'evil.example']"
    rel_types = sorted(r["relationship_type"] for r in by_type(objects, "relationship"))
    assert rel_types == ["based-on", "resolves-to"]


def test_sha224_creates_indicator_only(converter):
    objects = converter.convert_ioc(make_ioc("sha224", "d" * 56))
    assert [o["type"] for o in objects] == ["indicator"]


def test_port_is_not_imported(converter):
    with pytest.raises(ConversionError):
        converter.convert_ioc(make_ioc("port", "4444"))


def test_invalid_ip_raises(converter):
    with pytest.raises(ConversionError):
        converter.convert_ioc(make_ioc("ip", "not-an-ip"))


def test_quotes_are_escaped(converter):
    objects = converter.convert_ioc(make_ioc("url", "http://x.example/it's"))
    assert (
        by_type(objects, "indicator")[0]["pattern"]
        == "[url:value = 'http://x.example/it\\'s']"
    )


@pytest.mark.parametrize(
    "risk_level, score",
    [(0, 80), (-1, 70), (1, 60), (2, 50), (3, 40), (4, 25), (5, 10)],
)
def test_risk_level_sets_score(converter, risk_level, score):
    ioc = make_ioc(
        "domain",
        "evil.example",
        risk={"level": risk_level, "meaning": "x", "msg": "Rank 4738 on Alexa"},
    )
    objects = converter.convert_ioc(ioc)
    assert by_type(objects, "indicator")[0]["x_opencti_score"] == score
    assert by_type(objects, "domain-name")[0]["x_opencti_score"] == score


def test_missing_risk_uses_default_score():
    converter = RostiConverter(default_score=42)
    objects = converter.convert_ioc(make_ioc("domain", "evil.example"))
    assert by_type(objects, "indicator")[0]["x_opencti_score"] == 42


def test_ids_flag_sets_detection(converter):
    ioc = make_ioc("domain", "evil.example", ids=False)
    assert (
        by_type(converter.convert_ioc(ioc), "indicator")[0]["x_opencti_detection"]
        is False
    )


def test_tags_become_labels_and_indicator_types(converter):
    ioc = make_ioc("domain", "evil.example", tags=["cnc", "proxy"])
    indicator = by_type(converter.convert_ioc(ioc), "indicator")[0]
    assert indicator["labels"] == ["cnc", "proxy"]
    assert indicator["indicator_types"] == ["anonymization", "malicious-activity"]


def test_every_object_has_author_and_tlp(converter):
    objects = converter.convert_ioc(make_ioc("domain:ip", "evil.example:45.129.0.192"))
    for obj in objects:
        assert converter.tlp_marking.id in obj["object_marking_refs"]
        author = obj.get("created_by_ref") or obj.get("x_opencti_created_by_ref")
        assert author == converter.author.id


def test_sample_report_iocs_all_convert(converter):
    for item in load_fixture("report_r1xSdqAy_iocs.json")["data"]:
        converter.convert_ioc(IOC.model_validate(item))


# ---------------------------------------------------------------------------
# YARA, MITRE, CVE, Report
# ---------------------------------------------------------------------------


def test_yara_rule_becomes_yara_indicator(converter):
    rule = Yara.model_validate(load_fixture("yara_rules.json")["data"][0])
    indicator = converter.convert_yara(rule, dt.date(2026, 9, 22))
    assert indicator["pattern_type"] == "yara"
    assert indicator["name"] == "PavokwiLoader_1"
    assert indicator["pattern"].startswith("rule PavokwiLoader_1")


def test_mitre_technique_uses_mitre_id_for_identity(converter):
    a = converter.convert_mitre(
        Mitre(id="T1003", description="OS Credential Dumping", object_type="techniques")
    )
    b = converter.convert_mitre(
        Mitre(id="T1003", description="Other name", object_type="techniques")
    )
    assert a.id == b.id
    assert a.id.startswith("attack-pattern--")


@pytest.mark.parametrize(
    "object_type, prefix",
    [
        ("mitigations", "course-of-action--"),
        ("groups", "intrusion-set--"),
        ("campaigns", "campaign--"),
    ],
)
def test_mitre_object_types(converter, object_type, prefix):
    entity = converter.convert_mitre(
        Mitre(id="X1", description="Name", object_type=object_type)
    )
    assert entity.id.startswith(prefix)


@pytest.mark.parametrize("object_type", ["tactics", "datasources"])
def test_mitre_tactics_and_datasources_are_skipped(converter, object_type):
    assert (
        converter.convert_mitre(
            Mitre(id="TA0001", description="x", object_type=object_type)
        )
        is None
    )


def test_mitre_software_uses_resolver():
    calls = []

    def resolver(entry):
        calls.append(entry.id)
        return Reference(id="malware--11111111-1111-4111-8111-111111111111")

    converter = RostiConverter(software_resolver=resolver)
    ref = converter.convert_mitre(
        Mitre(id="S0650", description="QakBot", object_type="software")
    )
    assert calls == ["S0650"]
    assert ref.id.startswith("malware--")


def test_report_conversion_from_sample(converter):
    report = Report.model_validate(load_fixture("report_r1xSdqAy.json"))
    vulnerabilities = [converter.convert_cve(c) for c in report.cve]
    stix_report = converter.convert_report(report, vulnerabilities)

    assert stix_report["name"] == report.title
    assert stix_report["published"].date() == dt.date(2026, 10, 2)
    assert stix_report["report_types"] == ["threat-report"]
    assert len(stix_report["object_refs"]) == 2
    urls = [ref.get("url") for ref in stix_report["external_references"]]
    assert report.url in urls
    assert "https://rosti.dev/reports/r1xSdqAy" in urls
    assert "Truesec" in stix_report["description"]


def test_report_id_depends_only_on_the_rosti_id(converter):
    """A corrected title or date must update the same OpenCTI report."""
    report = Report.model_validate(load_fixture("report_r1xSdqAy.json"))
    first = converter.convert_report(report, [])
    corrected = report.model_copy(
        update={"title": "Corrected title", "date": dt.date(2026, 9, 30)}
    )
    second = converter.convert_report(corrected, [])
    other = converter.convert_report(report.model_copy(update={"id": "other123"}), [])

    assert first["id"] == second["id"] == report_stix_id("r1xSdqAy")
    assert second["name"] == "Corrected title"
    assert other["id"] != first["id"]
    assert first["id"].startswith("report--")


def test_report_replaces_its_objects_on_update(converter):
    """IOCs removed from a Rösti report must disappear from the OpenCTI report."""
    report = Report.model_validate(load_fixture("report_r1xSdqAy.json"))
    vulnerabilities = [converter.convert_cve(c) for c in report.cve]
    stix_report = converter.convert_report(report, vulnerabilities)

    assert stix_report["opencti_upsert_operations"] == [
        {
            "key": "objects",
            "value": list(stix_report["object_refs"]),
            "operation": "replace",
        }
    ]


def test_empty_report_removes_all_objects(converter):
    report = Report.model_validate(load_fixture("report_r1xSdqAy.json"))
    stix_report = converter.convert_report(report, [])

    assert "object_refs" not in stix_report
    assert stix_report["opencti_upsert_operations"][0]["value"] == []


@pytest.mark.parametrize(
    "ioc_type, value",
    [
        # colon-separated fingerprint seen in live data under "ssdeep"
        ("ssdeep", "97:a3:28:9e:2a:64:b3:60:08:a7:c9:a9:2a:cb:d8:1c"),
        ("md5", "not-a-hash"),
        ("sha256", "a" * 63),
        ("sha224", "z" * 56),
        ("domain", "no spaces.example"),
        ("domain", "localhost"),
        ("email", "not an email"),
        ("domain:port", "bad domain:443"),
    ],
)
def test_values_opencti_would_reject_are_skipped(converter, ioc_type, value):
    with pytest.raises(ConversionError):
        converter.convert_ioc(make_ioc(ioc_type, value))


def test_real_ssdeep_is_accepted(converter):
    value = "96:s4Ud1Lj96kvYu1UYAVvbM7mBfrd4lwh3/Y6Hgn:SdL6kAUoNM7mBRB/Y6Ho"
    objects = converter.convert_ioc(make_ioc("ssdeep", value))
    assert by_type(objects, "file")[0]["hashes"]["SSDEEP"] == value


def test_onion_domain_is_accepted(converter):
    onion = "s5n2uyo6gb6dhirsm5pihwohi6e7ayrwojx4xjow4cqabmbowpezenid.onion"
    converter.convert_ioc(make_ioc("domain:port", f"{onion}:80"))


@pytest.mark.parametrize(
    "tags, expected",
    [
        (["proxy-tor"], ["anonymization"]),
        (["compromised-hacked"], ["compromised"]),
        (["payload-stage2", "redirect"], ["malicious-activity"]),
    ],
)
def test_sub_tags_map_by_main_tag(converter, tags, expected):
    ioc = make_ioc("domain", "evil.example", tags=tags)
    assert (
        by_type(converter.convert_ioc(ioc), "indicator")[0]["indicator_types"]
        == expected
    )

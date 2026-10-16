"""Tests for combining IOCs that share an entity_ref (RostiConverter.convert_ioc_group)."""

import json
import random

import pytest
import stix2
from conftest import load_fixture
from connector.converter import RostiConverter
from rosti_client.models import IOC, ReportBundle
from stix2patterns.validator import run_validator

MD5 = "0025f279b51b9cc083160b60dbd0fe7b"
SHA1 = "91bb4f5fcc0481f57d72231ccc7d5e8fb676401d"
SHA224 = "d" * 56
SHA256 = "f8b924fc4f4e72d9849ba73b37f9b228c189c21f3bd98142e9b094054c00d7c9"


def make_ioc(ioc_type: str, value: str, ref: str | None = "grp", **kwargs) -> IOC:
    data = {
        "id": f"{ioc_type}-{value}"[:40],
        "type": ioc_type,
        "value": value,
        "date": "2026-10-06",
        "ids": True,
        "report": "oGmTvDQn",
        "entity_ref": ref,
        **kwargs,
    }
    return IOC.model_validate(data)


def by_type(objects, stix_type):
    return [o for o in objects if o["type"] == stix_type]


def ids(objects):
    return [o.id for o in objects]


def relationships(objects, rel_type):
    return [
        o for o in by_type(objects, "relationship") if o.relationship_type == rel_type
    ]


@pytest.fixture
def converter() -> RostiConverter:
    return RostiConverter()


def assert_valid(objects):
    """Every pattern is valid for OpenCTI and the objects form a valid bundle."""
    for indicator in by_type(objects, "indicator"):
        assert run_validator(indicator.pattern) == [], indicator.pattern
    bundle = stix2.Bundle(objects=objects, allow_custom=True)
    json.loads(bundle.serialize())


# ---------------------------------------------------------------------------
# Files
# ---------------------------------------------------------------------------


def test_example_report_md5_and_sha1_become_one_file(converter):
    bundle = ReportBundle.model_validate(
        {
            "report": {
                "id": "oGmTvDQn",
                "title": "t",
                "date": "2026-10-06",
                "url": "https://example.com/r",
            },
            "iocs": load_fixture("report_oGmTvDQn_iocs.json")["data"],
        }
    )
    standalone, group = bundle.ioc_groups

    result = converter.convert_ioc_group(group)

    [file] = by_type(result.objects, "file")
    assert file.hashes == {"SHA-1": SHA1, "MD5": MD5}
    [indicator] = by_type(result.objects, "indicator")
    assert indicator.pattern == (
        f"[file:hashes.'MD5' = '{MD5}' OR file:hashes.'SHA-1' = '{SHA1}']"
    )
    assert indicator.name == SHA1
    assert indicator.x_opencti_main_observable_type == "StixFile"
    # first comment that is set
    assert indicator.description == f"md5: {MD5}"
    [based_on] = relationships(result.objects, "based-on")
    assert (based_on.source_ref, based_on.target_ref) == (indicator.id, file.id)
    assert result.combined == ["file"] and not result.skipped
    assert_valid(result.objects)

    # the IOC without entity_ref is converted as before
    single = converter.convert_ioc_group(standalone)
    assert ids(single.objects) == ids(converter.convert_ioc(standalone[0]))
    assert single.combined == []


def test_hashes_names_and_paths_make_one_file(converter):
    group = [
        make_ioc("sha256", SHA256),
        make_ioc("md5", MD5),
        make_ioc("filename", "invoice.exe"),
        make_ioc("filepath", "C:\\Users\\Public\\run.dll"),
        make_ioc("sha224", SHA224),
    ]
    result = converter.convert_ioc_group(group)

    [file] = by_type(result.objects, "file")
    # OpenCTI cannot store SHA-224 on a file: only in the pattern
    assert file.hashes == {"SHA-256": SHA256, "MD5": MD5}
    assert file.name == "invoice.exe"
    assert file.x_opencti_additional_names == ["run.dll"]
    [indicator] = by_type(result.objects, "indicator")
    assert indicator.pattern == (
        f"[file:hashes.'MD5' = '{MD5}' OR file:hashes.'SHA-224' = '{SHA224}' "
        f"OR file:hashes.'SHA-256' = '{SHA256}']"
    )
    assert indicator.name == SHA256
    assert "Full path: C:\\Users\\Public\\run.dll" in indicator.description
    assert_valid(result.objects)


def test_names_only_group(converter):
    group = [
        make_ioc("filepath", "/tmp/x/payload.bin"),
        make_ioc("filename", "payload.bin"),
        make_ioc("filename", "loader.sh"),
    ]
    result = converter.convert_ioc_group(group)
    [file] = by_type(result.objects, "file")
    assert file.name == "payload.bin"
    assert file.x_opencti_additional_names == ["loader.sh"]
    [indicator] = by_type(result.objects, "indicator")
    assert indicator.pattern == (
        "[file:name = 'loader.sh' OR file:name = 'payload.bin']"
    )
    assert_valid(result.objects)


def test_two_different_md5_cannot_be_one_file(converter):
    group = [
        make_ioc("md5", MD5),
        make_ioc("md5", "1" * 32),
        make_ioc("sha1", SHA1),
    ]
    result = converter.convert_ioc_group(group)
    assert len(by_type(result.objects, "indicator")) == 3
    assert len(by_type(result.objects, "file")) == 3
    assert result.combined == []
    assert "different MD5 hashes" in result.warnings[0]


def test_invalid_member_is_skipped_and_the_rest_combined(converter):
    group = [make_ioc("md5", "nothex"), make_ioc("md5", MD5), make_ioc("sha1", SHA1)]
    result = converter.convert_ioc_group(group)
    assert [(ioc.value, reason) for ioc, reason in result.skipped] == [
        ("nothex", "Invalid MD5 hash: 'nothex'")
    ]
    assert result.combined == ["file"]
    assert len(by_type(result.objects, "indicator")) == 1


def test_group_with_one_valid_member_is_a_normal_ioc(converter):
    group = [make_ioc("md5", "nothex"), make_ioc("sha1", SHA1)]
    result = converter.convert_ioc_group(group)
    assert ids(result.objects) == ids(converter.convert_ioc(group[1]))
    assert result.combined == []
    assert len(result.skipped) == 1


# ---------------------------------------------------------------------------
# Network
# ---------------------------------------------------------------------------


def test_url_domain_and_ip_make_one_indicator(converter):
    group = [
        make_ioc("ip", "45.129.0.192"),
        make_ioc("domain", "evil.example"),
        make_ioc("url", "https://evil.example/gate.php"),
    ]
    result = converter.convert_ioc_group(group)

    [indicator] = by_type(result.objects, "indicator")
    assert indicator.pattern == (
        "[url:value = 'https://evil.example/gate.php'] "
        "OR [domain-name:value = 'evil.example'] "
        "OR [ipv4-addr:value = '45.129.0.192']"
    )
    assert indicator.name == "https://evil.example/gate.php"
    assert indicator.x_opencti_main_observable_type == "Url"
    [domain] = by_type(result.objects, "domain-name")
    [ip] = by_type(result.objects, "ipv4-addr")
    [resolves] = relationships(result.objects, "resolves-to")
    assert (resolves.source_ref, resolves.target_ref) == (domain.id, ip.id)
    based_on_targets = {r.target_ref for r in relationships(result.objects, "based-on")}
    assert based_on_targets == {domain.id, ip.id, by_type(result.objects, "url")[0].id}
    assert result.combined == ["network"]
    assert_valid(result.objects)


def test_domain_with_port_and_domain_ip_are_deduplicated(converter):
    group = [
        make_ioc("domain:port", "evil.example:443"),
        make_ioc("domain:ip", "evil.example:45.129.0.192"),
        make_ioc("ip:port", "45.129.0.192:8443"),
    ]
    result = converter.convert_ioc_group(group)
    assert len(by_type(result.objects, "domain-name")) == 1
    assert len(by_type(result.objects, "ipv4-addr")) == 1
    assert len(relationships(result.objects, "resolves-to")) == 1
    [indicator] = by_type(result.objects, "indicator")
    assert indicator.pattern == (
        "[domain-name:value = 'evil.example'] OR [ipv4-addr:value = '45.129.0.192']"
    )
    assert "Seen on port 443." in indicator.description
    assert_valid(result.objects)


def test_several_domains_do_not_resolve_to_the_ip(converter):
    group = [
        make_ioc("domain", "a.example"),
        make_ioc("domain", "b.example"),
        make_ioc("ip", "45.129.0.192"),
        make_ioc("cidr", "10.0.0.0/8"),
    ]
    result = converter.convert_ioc_group(group)
    assert relationships(result.objects, "resolves-to") == []
    assert len(by_type(result.objects, "indicator")) == 1
    assert_valid(result.objects)


# ---------------------------------------------------------------------------
# Mixed groups and merging
# ---------------------------------------------------------------------------


def test_file_and_network_iocs_are_never_mixed(converter):
    group = [
        make_ioc("md5", MD5),
        make_ioc("domain", "evil.example"),
        make_ioc("sha1", SHA1),
        make_ioc("ip", "45.129.0.192"),
        make_ioc("mutex", "Global\\abc"),
        make_ioc("url", "https://other.example/"),
    ]
    result = converter.convert_ioc_group(group)
    assert sorted(result.combined) == ["file", "network"]
    patterns = sorted(i.pattern for i in by_type(result.objects, "indicator"))
    assert len(patterns) == 3  # file, network, mutex
    file_pattern = next(p for p in patterns if p.startswith("[file:"))
    assert "domain" not in file_pattern and "url" not in file_pattern
    assert any(p == "[mutex:name = 'Global\\\\abc']" for p in patterns)
    assert_valid(result.objects)


def test_file_part_with_one_ioc_is_not_combined(converter):
    group = [make_ioc("md5", MD5), make_ioc("domain", "evil.example")]
    result = converter.convert_ioc_group(group)
    assert result.combined == []
    assert len(by_type(result.objects, "indicator")) == 2


def test_merged_values_are_the_cautious_ones(converter):
    group = [
        make_ioc("md5", MD5, tags=["rat"], comment=None, date="2026-10-05"),
        make_ioc(
            "sha1",
            SHA1,
            tags=["loader"],
            comment="dropped by the loader",
            ids=False,
            risk={"level": 4, "meaning": "high"},
        ),
    ]
    result = converter.convert_ioc_group(group)
    [indicator] = by_type(result.objects, "indicator")
    assert indicator.labels == ["loader", "rat"]
    assert indicator.x_opencti_score == 25  # risk 4, lower than the default 50
    assert indicator.x_opencti_detection is False
    assert indicator.valid_from.date().isoformat() == "2026-10-05"
    assert indicator.description == (
        f"dropped by the loader\nFalse-positive risk of {SHA1}: high."
    )
    [file] = by_type(result.objects, "file")
    assert file.x_opencti_score == 25
    assert file.x_opencti_labels == ["loader", "rat"]


def test_ids_do_not_depend_on_the_order_of_the_iocs(converter):
    group = [
        make_ioc("sha256", SHA256),
        make_ioc("md5", MD5),
        make_ioc("sha1", SHA1),
        make_ioc("domain", "evil.example"),
        make_ioc("ip", "45.129.0.192"),
        make_ioc("url", "https://evil.example/x"),
    ]
    expected = sorted(o.id for o in converter.convert_ioc_group(group).objects)
    for seed in range(5):
        shuffled = group[:]
        random.Random(seed).shuffle(shuffled)
        ids = sorted(o.id for o in converter.convert_ioc_group(shuffled).objects)
        assert ids == expected

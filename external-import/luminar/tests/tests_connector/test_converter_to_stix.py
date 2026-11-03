import copy
from collections import Counter
from datetime import datetime, timezone

import pytest
import stix2
from conftest import EXT, TS, RecordingLogger, stix_id
from luminar_connector.converter_to_stix import (
    ConversionStats,
    ConverterToStix,
    _append_labels,
    _get_from_extensions,
    _render_value,
    mask_credential,
)
from luminar_connector.relationship_schema import RelationshipSchema
from pycti import Identity, Malware

NOW = datetime(2026, 10, 20, 12, tzinfo=timezone.utc)
NO_SCHEMA = RelationshipSchema(None)


def ext(**attributes):
    return {
        "extensions": {
            EXT: {
                "extension_type": "property-extension",
                "luminar_tenant_id": "t",
                **attributes,
            }
        }
    }


def malware(number=1, name="Lumma", **extra):
    return {
        "type": "malware",
        "spec_version": "2.1",
        "id": stix_id("malware", number),
        "created": TS,
        "modified": TS,
        "name": name,
        "is_family": True,
        **extra,
    }


def indicator(number=10, pattern="[ipv4-addr:value = '198.51.100.1']", **extra):
    return {
        "type": "indicator",
        "spec_version": "2.1",
        "id": stix_id("indicator", number),
        "created": TS,
        "modified": TS,
        "pattern": pattern,
        "pattern_type": "stix",
        "valid_from": TS,
        **extra,
    }


def relationship(number, source, target, rel_type="related-to"):
    return {
        "type": "relationship",
        "spec_version": "2.1",
        "id": stix_id("relationship", number),
        "created": TS,
        "modified": TS,
        "relationship_type": rel_type,
        "source_ref": source,
        "target_ref": target,
    }


def labels_of(obj):
    return obj.get("labels", []) + obj.get("x_opencti_labels", [])


@pytest.fixture
def converter():
    return ConverterToStix(RecordingLogger(), create_observable=True)


def convert(converter, objects, feed="cyberfeeds", schema=NO_SCHEMA, now=NOW):
    out, stats = converter.convert_batch(feed, copy.deepcopy(objects), schema, now)
    return {o["id"]: o for o in out}, out, stats


# ----- module helpers ------------------------------------------------------ #


def test_helpers():
    assert _get_from_extensions("x", {}) is None
    assert _get_from_extensions("x", {"extensions": "bad"}) is None
    assert (
        _get_from_extensions(
            "score", {"extensions": {"other": {"score": 1}, EXT: {"score": 5}}}
        )
        == 5
    )
    assert _render_value(True) == "true" and _render_value(False) == "false"
    assert _render_value({"b": 1, "a": 2}) == '{"a": 2, "b": 1}'
    assert _render_value(" x ") == "x"
    assert mask_credential("changeme") == "c******e"
    assert mask_credential("ab") == "**" and mask_credential("abc") == "a*c"
    obj = {"labels": ["a"]}
    _append_labels(obj, "labels", [])
    _append_labels(obj, "labels", ["a", "b"])
    assert obj["labels"] == ["a", "b"]


def test_conversion_stats_merge_and_dict():
    total = ConversionStats(received=1, unsupported=Counter({"x": 1}))
    total.merge(ConversionStats(received=2, unsupported=Counter({"x": 2})))
    assert total.received == 3
    assert total.as_dict()["unsupported"] == {"x": 3}


# ----- normalization / selection ------------------------------------------- #


def test_empty_batch(converter):
    out, stats = converter.convert_batch("iocs", [], NO_SCHEMA, NOW)
    assert out == [] and stats.received == 0


def test_malformed_and_unsupported_objects_are_skipped(converter):
    raw = [
        "not-a-dict",
        {"type": "malware", "id": "not-an-id"},
        {"type": "malware", "id": stix_id("tool", 1)},
        {"type": "extension-definition", "id": stix_id("extension-definition", 1)},
        malware(),
    ]
    by_id, _, stats = convert(converter, raw)
    assert stats.malformed == 3
    assert stats.unsupported == Counter({"extension-definition": 1})
    assert stix_id("malware", 1) in by_id


def test_newest_valid_version_wins(converter):
    old = malware(name="Old", modified="2026-01-01T00:00:00.000Z")
    new = malware(name="New", modified="2026-02-01T00:00:00.000Z")
    newer_broken = malware(name="Broken", modified="2026-03-01T00:00:00.000Z")
    del newer_broken["is_family"]

    by_id, _, stats = convert(converter, [old, newer_broken, new])

    assert by_id[stix_id("malware", 1)]["name"] == "New"
    assert stats.duplicates == 2


def test_all_versions_malformed(converter):
    broken = malware()
    del broken["is_family"]
    by_id, out, stats = convert(converter, [broken])
    assert out == [] and stats.malformed == 1
    assert converter.logger.messages("warning")


def test_expired_indicator_and_its_relationship_are_excluded(converter):
    expired = indicator(valid_until="2026-10-20T11:00:00.000Z")
    unparseable = indicator(number=11, valid_until="soon")
    rel = relationship(1, expired["id"], stix_id("malware", 1), "indicates")
    by_id, _, stats = convert(
        converter, [expired, unparseable, malware(), rel], feed="iocs"
    )

    assert stats.expired == 1 and stats.malformed == 1
    assert expired["id"] not in by_id and rel["id"] not in by_id
    assert stats.dropped_dangling == 1


def test_identical_objects_are_collapsed_and_references_rewritten(converter):
    loc_a = {
        "type": "location",
        "spec_version": "2.1",
        "id": stix_id("location", 1),
        "created": TS,
        "modified": "2026-01-01T00:00:01.000Z",
        "country": "US",
    }
    loc_b = dict(loc_a, id=stix_id("location", 2), modified="2026-01-01T00:00:02.000Z")
    actor = {
        "type": "threat-actor",
        "spec_version": "2.1",
        "id": stix_id("threat-actor", 1),
        "created": TS,
        "modified": TS,
        "name": "APT",
        "custom_refs": [{"not": "a ref"}],
    }
    rel_a = relationship(1, actor["id"], loc_a["id"], "targets")
    rel_b = relationship(2, actor["id"], loc_b["id"], "targets")
    report = {
        "type": "report",
        "spec_version": "2.1",
        "id": stix_id("report", 1),
        "created": TS,
        "modified": TS,
        "name": "R",
        "published": TS,
        "object_refs": [loc_a["id"], loc_b["id"]],
    }

    by_id, _, stats = convert(converter, [loc_a, loc_b, actor, rel_a, rel_b, report])

    assert stats.identical_objects_collapsed == 1
    assert loc_b["id"] not in by_id
    assert by_id[rel_b["id"]]["target_ref"] == loc_a["id"]
    assert by_id[report["id"]]["object_refs"] == [loc_a["id"]]
    assert by_id[actor["id"]]["custom_refs"] == [{"not": "a ref"}]


# ----- enrichment ---------------------------------------------------------- #


@pytest.mark.parametrize(
    "extra, expected",
    [
        ({}, 80),
        ({"name": "Known Malicious IPs"}, 90),
        ({**ext(score=54)}, 54),
        ({**ext(score=1000)}, 80),
        ({"x_opencti_score": 12, **ext(score=54)}, 12),
    ],
)
def test_indicator_score(converter, extra, expected):
    by_id, _, _ = convert(converter, [indicator(**extra)], feed="iocs")
    assert by_id[stix_id("indicator", 10)]["x_opencti_score"] == expected


def test_indicator_enrichment(converter):
    ind = indicator(
        name="Bad IP",
        valid_from="2027-06-01T00:00:00.000Z",
        valid_until="2027-03-01T00:00:00.000Z",
    )
    by_id, _, _ = convert(converter, [ind], feed="iocs")
    result = by_id[ind["id"]]
    assert result["description"] == "Bad IP"
    assert "valid_until" not in result
    assert "luminar.feed:iocs" in result["labels"]


def test_vulnerability_cvss_and_flags(converter):
    vuln = {
        "type": "vulnerability",
        "spec_version": "2.1",
        "id": stix_id("vulnerability", 1),
        "created": TS,
        "modified": TS,
        "name": "CVE-2026-0001",
        **ext(
            x_cvss={
                "V3_1": {
                    "baseScore": "7.8",
                    "baseSeverity": "HIGH",
                    "vectorString": "CVSS:3.1/AV:L",
                }
            },
            luminar_is_exploitable=True,
            luminar_patching_priority=3,
        ),
    }
    bad = dict(
        vuln,
        id=stix_id("vulnerability", 2),
        name="CVE-2026-0002",
        **ext(x_cvss={"V3_0": {"baseScore": "n/a"}})
    )
    by_id, _, _ = convert(converter, [vuln, bad])

    result = by_id[vuln["id"]]
    assert result["x_opencti_cvss_base_score"] == 7.8
    assert result["x_opencti_cvss_base_severity"] == "HIGH"
    assert result["x_opencti_cvss_vector_string"] == "CVSS:3.1/AV:L"
    assert {"luminar.is_exploitable:true", "luminar.patching_priority:3"} <= set(
        result["labels"]
    )
    assert not any(label.startswith("luminar.x_cvss") for label in result["labels"])
    assert "x_opencti_cvss_base_score" not in by_id[bad["id"]]


def test_leaked_incident_and_user_account(converter):
    incident = {
        "type": "incident",
        "spec_version": "2.1",
        "id": stix_id("incident", 1),
        "created": TS,
        "modified": TS,
        "name": "Leak",
        **ext(
            luminar_threat_score=71,
            collection_date="2026-01-01T00:00:00Z",
            computer_name="DESKTOP-1",
        ),
    }
    account = {
        "type": "user-account",
        "spec_version": "2.1",
        "id": stix_id("user-account", 1),
        "account_login": "[unknown]",
        "credential": "changeme",
        **ext(
            url="https://site.test/login",
            source="ATO feed",
            monitoring_plan_terms=["site.test", "site.test"],
            credential_is_fresh=False,
        ),
    }
    masking = ConverterToStix(
        RecordingLogger(), create_observable=False, mask_credentials=True
    )

    by_id, _, _ = convert(masking, [incident, account], feed="leakedrecords")

    inc = by_id[incident["id"]]
    assert (inc["source"], inc["incident_type"], inc["severity"]) == (
        "Cognyte Luminar",
        "compromise",
        "high",
    )
    assert "luminar.threat_score:71" in inc["labels"]
    assert "- luminar.collection_date: 2026-01-01T00:00:00Z" in inc["description"]
    assert "- luminar.computer_name: DESKTOP-1" in inc["description"]
    user = by_id[account["id"]]
    assert user["user_id"] == account["id"]
    assert user["credential"] == "c******e"
    assert user["x_opencti_score"] == 100
    assert user["x_opencti_created_by_ref"] == masking.author["id"]
    assert set(user["x_opencti_labels"]) == {
        "luminar.source:ATO feed",
        "luminar.monitoring_plan_terms:site.test",
        "luminar.credential_is_fresh:false",
        "luminar.feed:leakedrecords",
    }
    assert "- luminar.url: https://site.test/login" in user["x_opencti_description"]
    assert not any("tenant" in label for label in labels_of(user))

    plain, _, _ = convert(converter, [account], feed="leakedrecords")
    assert plain[account["id"]]["credential"] == "changeme"


def test_attribute_export_edge_cases(converter):
    software = {
        "type": "software",
        "spec_version": "2.1",
        "id": stix_id("software", 1),
        "name": "App",
        **ext(empty="", nothing=None, nested={"a": 1}, long="x" * 200),
    }
    observed = {
        "type": "observed-data",
        "spec_version": "2.1",
        "id": stix_id("observed-data", 1),
        "created": TS,
        "modified": TS,
        "first_observed": TS,
        "last_observed": TS,
        "number_observed": 1,
        "object_refs": [software["id"]],
        **ext(collection_date="2026"),
    }
    by_id, _, _ = convert(converter, [software, observed])

    sw = by_id[software["id"]]
    assert sw["x_opencti_score"] == 80
    assert sw["x_opencti_description"].startswith(
        "Luminar Cyberfeeds\n\nLuminar attributes:"
    )
    assert '- luminar.nested: {"a": 1}' in sw["x_opencti_description"]
    assert "- luminar.long: " + "x" * 200 in sw["x_opencti_description"]
    assert "description" not in by_id[observed["id"]]


def test_cyberfeeds_sdos_and_reports_get_default_score(converter):
    report = {
        "type": "report",
        "spec_version": "2.1",
        "id": stix_id("report", 1),
        "created": TS,
        "modified": TS,
        "name": "R",
        "published": TS,
        "object_refs": [stix_id("malware", 1)],
    }
    by_id, _, _ = convert(converter, [report, malware()], feed="cyberfeeds")
    assert by_id[report["id"]]["x_opencti_score"] == 80
    assert by_id[stix_id("malware", 1)]["x_opencti_score"] == 80
    assert by_id[stix_id("malware", 1)]["description"] == "Luminar Cyberfeeds"


# ----- observables derived from patterns ----------------------------------- #


def test_observables_from_pattern(converter):
    pattern = (
        "[ipv4-addr:value = '198.51.100.7'] OR [domain-name:value != 'skip.test'] OR "
        "[file:hashes.'SHA-256' = 'aec070645fe53ee3b3763059376134f058cc337247c978add178b6ccdfb0019f'] OR "
        "[file:name = 'evil\\'s.exe'] OR [mutex:name = 'm'] OR [directory:path = '/tmp'] OR "
        "[windows-registry-key:key = 'HKLM\\\\Run'] OR [url:value NOT = 'http://x.test']"
    )
    ind = indicator(pattern=pattern, object_marking_refs=[stix2.TLP_AMBER.id])

    by_id, out, stats = convert(converter, [ind], feed="iocs")

    assert ind["id"] in by_id
    types = Counter(o["type"] for o in out)
    assert types["ipv4-addr"] == 1 and types["domain-name"] == 0
    assert types["file"] == 2 and types["mutex"] == 1 and types["directory"] == 1
    assert types["windows-registry-key"] == 1 and types["url"] == 0
    assert stats.observables_created == 6
    based_on = [o for o in out if o.get("relationship_type") == "based-on"]
    assert len(based_on) == 6 and all(r["source_ref"] == ind["id"] for r in based_on)
    ip = next(o for o in out if o["type"] == "ipv4-addr")
    assert ip["object_marking_refs"] == [stix2.TLP_AMBER.id]
    assert stix2.TLP_AMBER.id in by_id  # standard TLP definition added to the bundle
    assert any(o["type"] == "file" and o.get("name") == "evil's.exe" for o in out)


def test_observable_builder_edge_cases(converter):
    """Branches reached only through patterns stix2 itself would reject."""
    pattern = (
        "[file:size = '10'] OR [file:size = 'big'] OR [file:mime_type = 'x'] OR "
        "[process:pid = '1'] OR [file:hashes.MD5 = 'not-a-hash']"
    )
    derived = converter._observables_from_indicator("iocs", indicator(pattern=pattern))
    # stix2 rejects a File with only a size (it needs a name or hashes), so the
    # size branch ends in the logged "could not build" path like the bad hash.
    assert [o for o in derived if o["type"] == "file"] == []
    assert (
        "[CONVERTER] Could not build observable from pattern"
        in converter.logger.messages("debug")
    )


def test_no_observables_for_non_stix_patterns():
    converter = ConverterToStix(RecordingLogger(), create_observable=True)
    ind = indicator(pattern="rule x { condition: true }", pattern_type="yara")
    out, stats = converter.convert_batch("iocs", [ind], NO_SCHEMA, NOW)
    assert stats.observables_created == 0
    assert (
        converter._observables_from_indicator(
            "iocs", {"pattern_type": "stix", "pattern": None}
        )
        == []
    )


# ----- reference integrity ------------------------------------------------- #


def test_reference_integrity(converter):
    identity = {
        "type": "identity",
        "spec_version": "2.1",
        "id": stix_id("identity", 1),
        "created": TS,
        "modified": TS,
        "name": "Luminar",
        "identity_class": "organization",
    }
    marking = {
        "type": "marking-definition",
        "spec_version": "2.1",
        "id": stix_id("marking-definition", 1),
        "created": TS,
        "definition_type": "statement",
        "definition": {"statement": "internal"},
        "created_by_ref": stix_id("identity", 99),
    }
    mal = malware(
        created_by_ref=identity["id"],
        object_marking_refs=[
            marking["id"],
            stix2.TLP_GREEN.id,
            stix_id("marking-definition", 77),
        ],
        granular_markings=[
            {"marking_ref": stix_id("marking-definition", 78), "selectors": ["name"]},
            {"lang": "en", "selectors": ["name"]},
        ],
        sample_refs=[stix_id("file", 1)],
    )
    mal2 = malware(
        number=2,
        name="Other",
        created_by_ref=stix_id("identity", 99),
        granular_markings=[
            {"marking_ref": stix_id("marking-definition", 78), "selectors": ["name"]}
        ],
    )
    directory_obj = {
        "type": "file",
        "spec_version": "2.1",
        "id": stix_id("file", 2),
        "name": "a.exe",
        "parent_directory_ref": stix_id("directory", 9),
        "created_by_ref": stix_id("identity", 99),
    }
    self_loop = relationship(1, mal["id"], mal["id"])
    dangling = relationship(2, mal["id"], stix_id("malware", 99))
    to_author = relationship(3, mal["id"], converter.author["id"])
    sighting_ok = {
        "type": "sighting",
        "spec_version": "2.1",
        "id": stix_id("sighting", 1),
        "created": TS,
        "modified": TS,
        "sighting_of_ref": mal["id"],
        "where_sighted_refs": [identity["id"], stix_id("identity", 98)],
        "observed_data_refs": [stix_id("observed-data", 98)],
    }
    sighting_bad = dict(
        sighting_ok,
        id=stix_id("sighting", 2),
        where_sighted_refs=[stix_id("identity", 98)],
    )
    report_empty = {
        "type": "report",
        "spec_version": "2.1",
        "id": stix_id("report", 1),
        "created": TS,
        "modified": TS,
        "name": "R",
        "published": TS,
        "object_refs": [stix_id("malware", 99)],
    }
    note_empty = {
        "type": "note",
        "spec_version": "2.1",
        "id": stix_id("note", 1),
        "created": TS,
        "modified": TS,
        "content": "c",
        "object_refs": [stix_id("malware", 99)],
    }
    report_on_dropped = dict(
        report_empty, id=stix_id("report", 2), object_refs=[self_loop["id"], mal["id"]]
    )

    by_id, out, stats = convert(
        converter,
        [
            identity,
            marking,
            mal,
            mal2,
            directory_obj,
            self_loop,
            dangling,
            to_author,
            sighting_ok,
            sighting_bad,
            report_empty,
            note_empty,
            report_on_dropped,
        ],
    )

    assert self_loop["id"] not in by_id and dangling["id"] not in by_id
    assert to_author["id"] in by_id
    # Late-phase objects reference name-identified entities by standard id.
    assert by_id[sighting_ok["id"]]["where_sighted_refs"] == [
        Identity.generate_id("Luminar", "organization")
    ]
    assert "observed_data_refs" not in by_id[sighting_ok["id"]]
    assert sighting_bad["id"] not in by_id
    assert (
        "object_refs" not in by_id[report_empty["id"]] and stats.containers_emptied == 1
    )
    assert note_empty["id"] not in by_id
    assert by_id[report_on_dropped["id"]]["object_refs"] == [
        Malware.generate_id(mal["name"])
    ]
    m = by_id[mal["id"]]
    assert m["created_by_ref"] == identity["id"]
    assert m["object_marking_refs"] == [marking["id"], stix2.TLP_GREEN.id]
    assert m["granular_markings"] == [{"lang": "en", "selectors": ["name"]}]
    assert "sample_refs" not in m
    assert by_id[mal2["id"]]["created_by_ref"] == converter.author["id"]
    assert "granular_markings" not in by_id[mal2["id"]]
    assert "created_by_ref" not in by_id[marking["id"]]
    f = by_id[directory_obj["id"]]
    assert "parent_directory_ref" not in f and "created_by_ref" not in f
    assert f["x_opencti_created_by_ref"] == converter.author["id"]
    assert out[0] == converter.author
    assert stix2.TLP_GREEN.id in by_id


def test_sco_keeps_resolvable_creator(converter):
    identity = {
        "type": "identity",
        "spec_version": "2.1",
        "id": stix_id("identity", 1),
        "created": TS,
        "modified": TS,
        "name": "Luminar",
        "identity_class": "organization",
    }
    ip = {
        "type": "ipv4-addr",
        "spec_version": "2.1",
        "id": stix_id("ipv4-addr", 1),
        "value": "198.51.100.9",
        "created_by_ref": identity["id"],
    }
    by_id, _, _ = convert(converter, [identity, ip], feed="leakedrecords")
    assert by_id[ip["id"]]["x_opencti_created_by_ref"] == identity["id"]


def test_object_invalid_after_reference_cleanup_is_dropped(converter):
    traffic = {
        "type": "network-traffic",
        "spec_version": "2.1",
        "id": stix_id("network-traffic", 1),
        "protocols": ["tcp"],
        "src_ref": stix_id("ipv4-addr", 99),
    }
    by_id, _, stats = convert(converter, [traffic, malware()])
    assert traffic["id"] not in by_id
    assert stats.malformed == 1
    assert (
        "[CONVERTER] Skipping object invalid after reference cleanup"
        in converter.logger.messages("warning")
    )


# ----- relationship schema and feed label ---------------------------------- #


def test_relationship_schema_downgrades_disallowed_types(converter):
    software = {
        "type": "software",
        "spec_version": "2.1",
        "id": stix_id("software", 1),
        "name": "Android",
    }
    ind = indicator()
    actor = {
        "type": "threat-actor",
        "spec_version": "2.1",
        "id": stix_id("threat-actor", 1),
        "created": TS,
        "modified": TS,
        "name": "APT",
    }
    downgraded = relationship(1, ind["id"], software["id"], "indicates")
    allowed = relationship(2, ind["id"], actor["id"], "indicates")
    to_author = relationship(3, actor["id"], converter.author["id"], "impersonates")
    schema = RelationshipSchema(
        {
            "Indicator_Threat-Actor-Group": {"indicates"},
            "Indicator_IPv4-Addr": {"based-on"},
        }
    )

    by_id, _, stats = convert(
        converter,
        [software, ind, actor, downgraded, allowed, to_author],
        feed="iocs",
        schema=schema,
    )

    assert by_id[downgraded["id"]]["relationship_type"] == "related-to"
    assert by_id[allowed["id"]]["relationship_type"] == "indicates"
    assert by_id[to_author["id"]]["relationship_type"] == "related-to"
    assert stats.relationships_downgraded == 2


def test_relationship_schema_skips_unknown_endpoints(converter):
    rel = relationship(1, stix_id("malware", 1), stix_id("malware", 2), "variant-of")
    objects = {rel["id"]: dict(rel)}
    stats = ConversionStats()
    converter._apply_relationship_schema(objects, RelationshipSchema({}), stats)
    assert objects[rel["id"]]["relationship_type"] == "variant-of"


def test_every_object_gets_its_feed_label(converter):
    by_id, out, _ = convert(
        converter,
        [
            malware(),
            indicator(),
            relationship(
                1, stix_id("indicator", 10), stix_id("malware", 1), "indicates"
            ),
        ],
        feed="iocs",
    )
    for obj in out:
        if obj["id"] == converter.author["id"]:
            assert "luminar.feed:iocs" not in labels_of(obj)
        else:
            assert labels_of(obj).count("luminar.feed:iocs") == 1, obj["type"]


def test_late_phase_objects_reference_standard_ids(converter):
    # Same name, different content: not collapsed, but merged by OpenCTI.
    redline_a = malware(1, name="REDLINE")
    redline_b = malware(2, name="REDLINE", description="Stealer")
    unnamed_identity = {
        "type": "identity",
        "spec_version": "2.1",
        "id": stix_id("identity", 3),
        "created": TS,
        "modified": TS,
        "name": "No class",
    }
    ind = indicator()
    to_b = relationship(1, ind["id"], redline_b["id"], "indicates")
    between_merged = relationship(2, redline_a["id"], redline_b["id"])
    to_identity = relationship(3, redline_a["id"], unnamed_identity["id"])
    report = {
        "type": "report",
        "spec_version": "2.1",
        "id": stix_id("report", 4),
        "created": TS,
        "modified": TS,
        "name": "R",
        "published": TS,
        "object_refs": [redline_a["id"], redline_b["id"], ind["id"]],
    }
    by_id, _, stats = convert(
        converter,
        [
            redline_a,
            redline_b,
            unnamed_identity,
            ind,
            to_b,
            between_merged,
            to_identity,
            report,
        ],
    )

    standard = Malware.generate_id("REDLINE")
    # Entities keep their Luminar ids (OpenCTI keeps them as aliases).
    assert redline_a["id"] in by_id and redline_b["id"] in by_id
    assert by_id[to_b["id"]]["source_ref"] == ind["id"]
    assert by_id[to_b["id"]]["target_ref"] == standard
    assert between_merged["id"] not in by_id and stats.dropped_dangling == 1
    # Identity without identity_class keeps its Luminar id.
    assert by_id[to_identity["id"]]["target_ref"] == unnamed_identity["id"]
    assert by_id[report["id"]]["object_refs"] == [standard, ind["id"]]

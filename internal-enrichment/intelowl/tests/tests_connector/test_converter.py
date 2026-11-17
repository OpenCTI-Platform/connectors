import pytest
from connector.converter_to_stix import (
    ConverterToStix,
    intelowl_tlp,
    observable_to_intelowl,
    verdict_score,
)
from pycti import STIX_EXT_OCTI_SCO


@pytest.mark.parametrize(
    "stix_entity, expected",
    [
        ({"type": "ipv4-addr", "value": "198.51.100.7"}, ("ip", "198.51.100.7")),
        ({"type": "ipv6-addr", "value": "2001:db8::1"}, ("ip", "2001:db8::1")),
        ({"type": "domain-name", "value": "example.com"}, ("domain", "example.com")),
        (
            {"type": "hostname", "value": "mail.example.com"},
            ("domain", "mail.example.com"),
        ),
        (
            {"type": "url", "value": "https://example.com/a"},
            ("url", "https://example.com/a"),
        ),
        (
            {"type": "file", "hashes": {"MD5": "A" * 32, "SHA-256": "B" * 64}},
            ("hash", "b" * 64),
        ),
        (
            {"type": "file", "hashes": {"SHA-1": "c" * 40, "MD5": "d" * 32}},
            ("hash", "c" * 40),
        ),
        ({"type": "file", "name": "invoice.pdf"}, None),
        ({"type": "email-addr", "value": "a@example.com"}, None),
    ],
)
def test_observable_to_intelowl(stix_entity, expected):
    assert observable_to_intelowl(stix_entity) == expected


@pytest.mark.parametrize(
    "opencti_tlp, expected",
    [
        ("TLP:CLEAR", "CLEAR"),
        ("TLP:WHITE", "CLEAR"),
        ("TLP:GREEN", "GREEN"),
        ("TLP:AMBER", "AMBER"),
        ("TLP:AMBER+STRICT", "RED"),
        ("TLP:RED", "RED"),
        (None, "CLEAR"),
    ],
)
def test_intelowl_tlp(opencti_tlp, expected):
    assert intelowl_tlp(opencti_tlp) == expected


@pytest.mark.parametrize(
    "data_model, expected",
    [
        ({"evaluation": "malicious", "reliability": 8}, 80),
        ({"evaluation": "MALICIOUS", "reliability": 15}, 100),
        ({"evaluation": "malicious"}, 50),
        ({"evaluation": "trusted", "reliability": 9}, 0),
        ({"evaluation": None}, None),
        ({}, None),
    ],
)
def test_verdict_score(data_model, expected):
    assert verdict_score(data_model) == expected


def _by_type(objects, stix_type):
    return [o for o in objects if o["type"] == stix_type]


def test_convert_builds_note_malware_and_updates_the_observable(
    intelowl_job, ipv4_stix_entity
):
    converter = ConverterToStix.for_entity_tlp("TLP:AMBER")

    objects = converter.convert(
        stix_entity=ipv4_stix_entity,
        value="198.51.100.7",
        playbook="FREE_TO_USE_ANALYZERS",
        job=intelowl_job,
        job_url="https://intelowl.example.com/jobs/42",
    )

    [author] = _by_type(objects, "identity")
    [marking] = _by_type(objects, "marking-definition")
    assert author["name"] == "IntelOwl"
    assert marking["name"] == "TLP:AMBER"

    [note] = _by_type(objects, "note")
    assert note["object_refs"] == [ipv4_stix_entity["id"]]
    assert note["created_by_ref"] == author["id"]
    assert "**Verdict:** malicious" in note["content"]
    assert "**Reliability:** 8/10" in note["content"]
    assert "**Malware family:** mirai" in note["content"]
    assert "**Tags:** scanner, tor_exit_node" in note["content"]
    assert "| GreyNoiseCommunity | FAILED |  |" in note["content"]
    assert "| TorProject | SUCCESS | malicious |" in note["content"]
    assert (
        note["external_references"][0]["url"] == "https://intelowl.example.com/jobs/42"
    )

    [malware] = _by_type(objects, "malware")
    [relationship] = _by_type(objects, "relationship")
    assert malware["name"] == "mirai"
    assert malware["is_family"] is True
    assert relationship["relationship_type"] == "related-to"
    assert relationship["source_ref"] == ipv4_stix_entity["id"]
    assert relationship["target_ref"] == malware["id"]

    extension = ipv4_stix_entity["extensions"][STIX_EXT_OCTI_SCO]
    assert extension["score"] == 80
    assert extension["labels"] == ["scanner", "tor_exit_node", "mirai"]


def test_note_id_only_depends_on_the_results(intelowl_job, ipv4_stix_entity):
    """Re-running an analysis with the same results updates the note instead of adding one."""
    converter = ConverterToStix()

    def note_id(job, url):
        objects = converter.convert(
            dict(ipv4_stix_entity, extensions={}), "198.51.100.7", "PB", job, url
        )
        return _by_type(objects, "note")[0]["id"]

    first = note_id(intelowl_job, "https://intelowl.example.com/jobs/42")
    rerun = note_id(dict(intelowl_job, id=43), "https://intelowl.example.com/jobs/43")
    changed = note_id(
        dict(
            intelowl_job,
            data_model={**intelowl_job["data_model"], "evaluation": "trusted"},
        ),
        "https://intelowl.example.com/jobs/44",
    )

    assert first == rerun
    assert first != changed


def test_convert_without_verdict_leaves_score_and_labels_alone(
    intelowl_job, ipv4_stix_entity
):
    intelowl_job["data_model"] = {}

    objects = ConverterToStix().convert(
        ipv4_stix_entity,
        "198.51.100.7",
        "PB",
        intelowl_job,
        "https://intelowl.example.com/jobs/42",
    )

    assert "**Verdict:** no verdict" in _by_type(objects, "note")[0]["content"]
    assert not _by_type(objects, "malware")
    assert STIX_EXT_OCTI_SCO not in ipv4_stix_entity["extensions"]


def test_convert_respects_score_and_label_settings(intelowl_job, ipv4_stix_entity):
    ConverterToStix().convert(
        ipv4_stix_entity,
        "198.51.100.7",
        "PB",
        intelowl_job,
        "https://intelowl.example.com/jobs/42",
        update_score=False,
        create_labels=False,
    )
    assert STIX_EXT_OCTI_SCO not in ipv4_stix_entity["extensions"]

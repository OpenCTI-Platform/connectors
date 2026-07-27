"""Contracts for capability-gated technical analysis and explicit IOC policy."""

# pylint: disable=no-member,protected-access,wrong-import-order

import base64
from unittest.mock import MagicMock

import stix2
from connector.api_client import RansomLookAPIError, RansomLookCapabilityUnavailable
from connector.converter import RansomLookConverter
from connector.evidence import EvidenceBudget, EvidenceDecoder
from pycti import AttackPattern, OpenCTIConnectorHelper

from tests.test_connector import make_connector


def converter():
    return RansomLookConverter(
        "https://www.ransomlook.io/api", ["ransomware", "ransomlook"], "TLP:CLEAR"
    )


def test_only_explicit_malware_and_valid_attack_mappings_are_converted():
    conv = converter()
    malware = conv.create_analysis_malware(
        {"name": "ExampleCrypt", "aliases": ["EC"], "is_family": True}
    )
    technique = conv.create_analysis_attack_pattern(
        {"external_id": "t1486", "name": "Data Encrypted for Impact"}
    )

    assert malware.name == "ExampleCrypt"
    assert malware.is_family is True
    assert technique.external_references[0].external_id == "T1486"
    assert technique.x_mitre_id == "T1486"
    assert technique.id == AttackPattern.generate_id(
        name="Data Encrypted for Impact", x_mitre_id="T1486"
    )
    assert conv.create_analysis_malware("ExampleCrypt") is None
    assert conv.create_analysis_attack_pattern({"name": "guessed from note"}) is None
    assert (
        conv.create_analysis_attack_pattern(
            {"external_id": "T99999", "name": "Invalid"}
        )
        is None
    )


def test_observable_and_indicator_require_explicit_assertions():
    conv = converter()
    contextual = {"type": "domain", "value": "evil.example"}
    malicious = {**contextual, "malicious": True}
    detected = {**malicious, "detection_basis": "Matched analysis rule RL-1"}

    assert conv.create_analysis_observable(contextual) is None
    observable = conv.create_analysis_observable(malicious)
    assert observable.x_ransomlook_explicit_malicious is True
    assert conv.create_analysis_indicator(malicious, observable) is None
    indicator = conv.create_analysis_indicator(detected, observable)
    assert indicator.x_ransomlook_detection_basis == "Matched analysis rule RL-1"
    assert indicator.pattern == "[domain-name:value = 'evil.example']"


def test_supported_explicit_observable_shapes_are_strict():
    conv = converter()
    values = [
        {"type": "url", "value": "https://evil.example/a", "verdict": "malicious"},
        {"type": "ipv4", "value": "192.0.2.1", "classification": "malicious"},
        {
            "type": "file-hash",
            "value": "a" * 64,
            "hash_type": "sha256",
            "malicious": True,
        },
    ]
    assert [conv.create_analysis_observable(item).type for item in values] == [
        "url",
        "ipv4-addr",
        "file",
    ]
    assert (
        conv.create_analysis_observable(
            {"type": "file-hash", "value": "bad", "malicious": True}
        )
        is None
    )


def test_analysis_document_decoder_is_bounded_and_passive():
    logger = MagicMock()
    decoder = EvidenceDecoder(logger, 1024, EvidenceBudget(2, 2048))
    pdf = base64.b64encode(b"%PDF-1.4\nsynthetic\n%%EOF").decode()

    payload = decoder.decode_analysis_document(pdf, "application/pdf", "analysis-1")
    assert payload.kind == "technical-analysis"
    assert payload.mime_type == "application/pdf"
    assert decoder.decode_analysis_document(pdf, "text/html", "analysis-2") is None
    assert "analysis-2" not in str(logger.warning.call_args)


def test_analysis_document_supported_formats_and_rejections():
    logger = MagicMock()
    decoder = EvidenceDecoder(logger, 1024, EvidenceBudget(10, 4096))

    html = base64.b64encode(b"<!doctype html><html></html>").decode()
    text = base64.b64encode(b"synthetic analysis").decode()
    assert decoder.decode_analysis_document(html, "html", "a").mime_type == "text/html"
    assert (
        decoder.decode_analysis_document(
            f"data:text/plain;base64,{text}", None, "b"
        ).mime_type
        == "text/plain"
    )
    rejected = [
        (base64.b64encode(b"not pdf").decode(), "pdf"),
        (base64.b64encode(b"<fragment>").decode(), "html"),
        (base64.b64encode(b"text\x00").decode(), "txt"),
        (text, "application/zip"),
        (None, "text/plain"),
    ]
    for index, (carrier, mime) in enumerate(rejected):
        assert decoder.decode_analysis_document(carrier, mime, f"bad-{index}") is None

    exhausted = EvidenceDecoder(logger, 1024, EvidenceBudget(0, 4096))
    assert exhausted.decode_analysis_document(text, "text", "exhausted") is None


def explicit_analysis(post_id=None):
    record = {
        "id": "analysis-1",
        "title": "Synthetic technical analysis",
        "published": "2026-01-03T00:00:00Z",
        "malware": [{"name": "ExampleCrypt", "is_family": True}],
        "attack_patterns": [
            {"external_id": "T1486", "name": "Data Encrypted for Impact"},
            {"external_id": "invalid", "name": "Must be skipped"},
        ],
        "observables": [
            {
                "type": "domain",
                "value": "evil.example",
                "malicious": True,
                "detection": {"rule_id": "RL-1", "kind": "signature"},
            },
            {"type": "domain", "value": "context.example"},
        ],
        "document": base64.b64encode(b"%PDF-1.4\nsynthetic\n%%EOF").decode(),
        "document_mime_type": "application/pdf",
    }
    if post_id:
        record["post_id"] = post_id
    return record


def test_analysis_graph_is_profile_scoped_unless_explicitly_claim_linked():
    connector = make_connector(create_indicators=True)
    group = connector.converter.create_group("akira", {})
    posts = [
        {
            "id": "post-1",
            "group_name": "akira",
            "post_title": "Victim",
            "discovered": "2026-01-02T00:00:00Z",
        }
    ]
    connector.client.get_group_analyses = MagicMock(
        return_value=[explicit_analysis(), explicit_analysis("post-1")]
    )

    profile, claims, complete = connector._try_create_group_analysis_intelligence(
        "akira", group.id, posts
    )

    assert complete is True
    assert any(obj.type == "report" for obj in profile)
    claim_objects = claims[connector.converter.claim_identity(posts[0])]
    assert any(obj.type == "report" for obj in claim_objects)
    assert any(obj.type == "malware" for obj in claim_objects)
    assert any(obj.type == "attack-pattern" for obj in claim_objects)
    assert any(obj.type == "indicator" for obj in claim_objects)
    assert not any(
        getattr(obj, "value", None) == "context.example" for obj in claim_objects
    )


def test_capability_absence_is_clean_and_no_route_is_invented():
    connector = make_connector()
    group = connector.converter.create_group("akira", {})
    connector.client.get_group_analyses = MagicMock(
        side_effect=RansomLookCapabilityUnavailable("analyses")
    )
    assert connector._try_create_group_analysis_intelligence("akira", group.id, []) == (
        [],
        {},
        True,
    )
    connector.helper.connector_logger.info.assert_called()


def test_analysis_api_failure_retries_and_disabled_policy_makes_no_call():
    connector = make_connector()
    group = connector.converter.create_group("akira", {})
    connector.client.get_group_analyses = MagicMock(
        side_effect=RansomLookAPIError("temporary failure")
    )
    assert (
        connector._try_create_group_analysis_intelligence("akira", group.id, [])[2]
        is False
    )

    disabled = make_connector(import_analyses=False)
    disabled.client.get_group_analyses = MagicMock(
        side_effect=AssertionError("not called")
    )
    assert disabled._try_create_group_analysis_intelligence("akira", group.id, []) == (
        [],
        {},
        True,
    )
    disabled.client.get_group_analyses.assert_not_called()


def test_analysis_graph_serializes_through_pycti_and_stix():
    connector = make_connector(create_indicators=True)
    group = connector.converter.create_group("akira", {})
    graph = connector._create_analysis_graph(explicit_analysis(), group.id)
    complete = [group, *graph, connector.converter.author, connector.converter.marking]
    parsed = stix2.parse(
        OpenCTIConnectorHelper.stix2_create_bundle(complete.copy()),
        allow_custom=True,
        version="2.1",
    )
    types = {obj.type for obj in parsed.objects}
    assert {"report", "artifact", "malware", "attack-pattern", "indicator"} <= types
    report = next(obj for obj in parsed.objects if obj.type == "report")
    artifacts = [obj for obj in parsed.objects if obj.type == "artifact"]
    assert report.created_by_ref == connector.converter.author.id
    assert all(
        artifact.x_opencti_created_by_ref == connector.converter.author.id
        for artifact in artifacts
    )
    assert set(report.object_refs) <= {obj.id for obj in parsed.objects}


def test_analysis_converter_defensive_and_alternate_paths():
    conv = converter()
    assert conv.analysis_identity({"uuid": "u-1"}) == "u-1"
    assert conv.analysis_identity({"analysis_id": 7}) == "7"
    assert conv.analysis_identity({}) is None
    assert conv.create_analysis_malware({"name": "   "}) is None
    assert conv.create_analysis_attack_pattern("T1486") is None
    assert (
        conv.create_analysis_attack_pattern(
            {"attack_id": "T1003.001", "name": "LSASS Memory"}
        )
        .external_references[0]
        .external_id
        == "T1003.001"
    )
    assert conv._detection_basis({"detection": {}}) is None
    assert (
        conv.create_analysis_observable({"malicious": True, "type": "domain"}) is None
    )
    assert (
        conv.create_analysis_observable(
            {"malicious": True, "type": "domain", "value": "192.0.2.1"}
        )
        is None
    )
    assert (
        conv.create_analysis_observable(
            {"malicious": True, "type": "ip", "value": "not-an-ip"}
        )
        is None
    )
    assert (
        conv.create_analysis_observable(
            {"malicious": True, "type": "ipv6", "value": "192.0.2.1"}
        )
        is None
    )
    ipv6 = conv.create_analysis_observable(
        {"malicious": True, "type": "ip", "value": "2001:db8::1"}
    )
    file_observable = conv.create_analysis_observable(
        {"malicious": True, "type": "hash", "algorithm": "md5", "value": "a" * 32}
    )
    assert ipv6.type == "ipv6-addr"
    assert "file:hashes" in conv._indicator_pattern(file_observable)
    assert (
        conv.create_analysis_observable(
            {"malicious": True, "type": "email", "value": "x@example.test"}
        )
        is None
    )
    assert (
        conv._indicator_pattern(
            stix2.Identity(
                id="identity--00000000-0000-4000-8000-000000000001",
                name="x",
                identity_class="organization",
            )
        )
        is None
    )
    assert (
        conv.create_analysis_indicator(
            {"malicious": False, "detection_basis": "x"}, ipv6
        )
        is None
    )
    assert conv.create_analysis_report({}, [ipv6.id]) is None
    assert conv.create_analysis_report({"id": "x"}, []) is None


def test_analysis_orchestration_malformed_and_minimal_shapes():
    connector = make_connector(create_indicators=False)
    group = connector.converter.create_group("akira", {})
    post = {
        "id": "post-1",
        "group_name": "akira",
        "post_title": "Victim",
        "discovered": "2026-01-02T00:00:00Z",
    }
    connector.client.get_group_analyses = MagicMock(
        return_value=[{}, {"id": "minimal", "ttps": [None], "malware": [None]}]
    )
    profile, claims, complete = connector._try_create_group_analysis_intelligence(
        "akira", group.id, [post]
    )
    assert complete is False
    assert any(obj.type == "report" for obj in profile)
    assert not any(obj.type == "indicator" for obj in profile)
    assert claims[connector.converter.claim_identity(post)] == []

    connector.client.get_group_analyses = MagicMock(return_value=[{"id": "boom"}])
    connector._create_analysis_graph = MagicMock(side_effect=ValueError("bad shape"))
    assert (
        connector._try_create_group_analysis_intelligence("akira", group.id, [])[2]
        is False
    )

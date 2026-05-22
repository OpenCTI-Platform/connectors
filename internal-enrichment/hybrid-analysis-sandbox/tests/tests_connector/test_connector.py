import json
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest
import stix2
from connector import ConnectorSettings, HybridAnalysis
from connector.connector import HybridAnalysisReportError
from hybrid_analysis_client import HybridAnalysisAPIError
from pycti import OpenCTIConnectorHelper

DATA_DIR = Path(__file__).parent / "data"


def _load_message_data(file_name: str) -> dict:
    """Load one connector message fixture from disk."""
    with (DATA_DIR / file_name).open("r", encoding="utf-8") as f:
        return json.load(f)


def _stix_bundle_contains_exact(bundle: list, stix_id: str) -> bool:
    """Check if a STIX object with the given ID is present in the bundle."""
    return any(
        (
            obj.get("id") == stix_id
            if isinstance(obj, dict)
            else getattr(obj, "id", None) == stix_id
        )
        for obj in bundle
    )


def _stix_bundle_contains_any(bundle: list, stix_types: list[str]) -> bool:
    """Check if all STIX types exists in the bundle."""
    unique_stix_types = set(stix_types)

    unique_bundle_types = set(
        (obj.get("type") if isinstance(obj, dict) else getattr(obj, "type", None))
        for obj in bundle
    )

    return unique_stix_types.issubset(unique_bundle_types)


class StubConnectorSettings(ConnectorSettings):
    """Provide deterministic connector settings for tests."""

    @classmethod
    def _load_config_dict(cls, _, handler) -> dict[str, Any]:
        return handler(
            {
                "opencti": {
                    "url": "http://localhost:8080",
                    "token": "test-token",
                },
                "connector": {
                    "id": "connector-id",
                    "name": "Test Connector",
                    "scope": "StixFile, Artifact, Url, Domain-Name, Hostname",
                    "log_level": "error",
                    "auto": True,
                },
                "hybrid_analysis_sandbox": {
                    "token": "test-api-token",
                },
            }
        )


@pytest.fixture
def dummy_connector(mock_opencti_connector_helper):
    """
    Return a dummy connector with mocked/stubbed dependencies and methods.
    Mostly used for spying method calls (most methods are mocked and return nothing).
    """
    settings = StubConnectorSettings()

    helper = OpenCTIConnectorHelper(config=settings.to_helper_config())
    helper.send_stix2_bundle = MagicMock()

    connector = HybridAnalysis(config=settings, helper=helper)
    connector.client = MagicMock()
    connector._search_hash = MagicMock()
    connector._submit_url = MagicMock()
    connector._trigger_sandbox = MagicMock()
    connector._create_knowledge = MagicMock()
    connector._send_bundle = MagicMock()

    return connector


@pytest.fixture
def stub_connector(mock_opencti_connector_helper, hybrid_analysis_report):
    """
    Return a stub connector with mocked/stubbed dependencies and methods.
    Mostly used to assert the returned values of the connector's methods.
    Most methods are mocked to return a fake but valid value (e.g. a fake Hybrid Analysis report)
    to allow testing the creation of the enrichment bundle.
    """
    settings = StubConnectorSettings()

    helper = OpenCTIConnectorHelper(config=settings.to_helper_config())
    # Mock helper's methods that would make external calls during connector's run
    helper.send_stix2_bundle = MagicMock()

    connector = HybridAnalysis(config=settings, helper=helper)
    connector.identity = stix2.Identity(
        id="identity--4a9e7924-46a1-43f7-962b-e61f53f4b0ca",
        name="Test Identity",
        identity_class="organization",
    )
    connector.tlp = stix2.TLP_GREEN

    # Mock all methods that would make external calls
    connector.client = MagicMock()
    connector._search_hash = MagicMock(return_value=hybrid_analysis_report)
    connector._submit_url = MagicMock(return_value=hybrid_analysis_report)
    connector._trigger_sandbox = MagicMock(return_value=hybrid_analysis_report)

    return connector


@pytest.fixture
def file_message() -> dict:
    """Return a fake file enrichment message."""
    return _load_message_data("file_message.json")


@pytest.fixture
def artifact_message() -> dict:
    """Return a fake artifact enrichment message."""
    return _load_message_data("artifact_message.json")


@pytest.fixture
def url_message() -> dict:
    """Return a fake URL enrichment message."""
    return _load_message_data("url_message.json")


@pytest.fixture
def hybrid_analysis_report() -> dict:
    """Return a fake report dict as would be returned from the Hybrid Analysis API."""
    return {
        "md5": "d41d8cd98f00b204e9800998ecf8427e",
        "sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
        "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "submit_name": "malware.exe",
        "size": 1024,
        "threat_score": 75,
        "environment_id": 110,
        "environment_description": "Windows 7 32 bit",
        "type_short": ["trojan"],
        "mitre_attcks": [
            {
                "technique": "Process Injection",
                "attck_id": "T1055",
                "malicious_identifiers_count": 1,
                "suspicious_identifiers_count": 0,
            }
        ],
        "domains": ["evil.example.com"],
        "hosts": [
            "192.168.1.1",
            "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
        ],
        "extracted_files": [
            {
                "threat_level": 1,
                "md5": "d41d8cd98f00b204e9800998ecf8427e",
                "sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
                "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "size": 512,
                "name": "dropped.dll",
                "type_tags": ["dll"],
            }
        ],
        "analysis_start_time": "2024-01-01T12:00:00",
        "verdict": "malicious",
    }


def test_get_report_returns_summary_when_processing_completes(
    stub_connector, hybrid_analysis_report, monkeypatch
):
    """_get_report polls until completion and returns report summary."""
    # Given a report state sequence that requires polling before completion
    stub_connector.client.get_report_state = MagicMock(
        side_effect=[
            {"state": "IN_QUEUE"},
            {"state": "IN_PROGRESS"},
            {"state": "SUCCESS"},
        ]
    )
    stub_connector.client.get_report_summary = MagicMock(
        return_value=hybrid_analysis_report
    )

    sleep_calls = []
    monkeypatch.setattr(
        "connector.connector.time.sleep",
        lambda seconds: sleep_calls.append(seconds),
    )

    # When _get_report is called
    result = stub_connector._get_report("job-123")

    # Then polling happened until completion and summary is returned
    assert result == hybrid_analysis_report
    assert stub_connector.client.get_report_state.call_count == 3
    stub_connector.client.get_report_summary.assert_called_once_with("job-123")
    assert sleep_calls == [30, 30]


def test_get_report_raises_when_state_is_error(stub_connector):
    """_get_report raises HybridAnalysisReportError when API state is ERROR."""
    # Given the report state immediately returns ERROR
    stub_connector.client.get_report_state = MagicMock(
        return_value={"state": "ERROR", "error": "report processing failed"}
    )

    # When _get_report is called, then an explicit report-processing error is raised
    with pytest.raises(HybridAnalysisReportError, match="report processing failed"):
        stub_connector._get_report("job-err")

    stub_connector.client.get_report_summary.assert_not_called()


def test_process_message_ignores_entity_exceeding_max_tlp(
    dummy_connector, file_message
):
    """_process_message ignores entities with a TLP higher than the connector's max TLP."""
    # Given a StixFile message fixture
    data = file_message

    # And the connector's max TLP is set to CLEAR
    dummy_connector.max_tlp = "TLP:CLEAR"

    # When _process_message is called
    dummy_connector._process_message(data)

    # Then no enrichment methods are called since the entity's TLP is AMBER (higher than CLEAR)
    dummy_connector._search_hash.assert_not_called()
    dummy_connector._submit_url.assert_not_called()
    dummy_connector._trigger_sandbox.assert_not_called()
    dummy_connector._create_knowledge.assert_not_called()

    # Then the original bundle is still sent to OpenCTI (playbook compatibility)
    dummy_connector._send_bundle.assert_called_with(data["stix_objects"])


@pytest.mark.parametrize(
    "raised_exception",
    [
        HybridAnalysisAPIError("API error"),
        HybridAnalysisReportError("Report error"),
        Exception("Unexpected error"),
    ],
    ids=[
        "hybrid-analysis-api-error",
        "hybrid-analysis-report-error",
        "unexpected-exception",
    ],
)
def test_process_message_handles_exceptions(
    dummy_connector, file_message, raised_exception
):
    """_process_message sends original bundle and re-raises errors."""
    # Given a StixFile message fixture
    data = file_message

    # And _search_hash triggers an exception (simulating an API error or an error during report processing)
    dummy_connector._search_hash = MagicMock(side_effect=raised_exception)

    # When _process_message is called
    with pytest.raises(type(raised_exception)):
        dummy_connector._process_message(data)

    # Then the API call was attempted and no enrichment path continued
    dummy_connector._search_hash.assert_called_once()
    dummy_connector._submit_url.assert_not_called()
    dummy_connector._trigger_sandbox.assert_not_called()
    dummy_connector._create_knowledge.assert_not_called()

    # Then the original bundle is still sent to OpenCTI (playbook compatibility)
    dummy_connector._send_bundle.assert_called_with(data["stix_objects"])


def test_process_message_routes_to_expected_method_when_file_exists_on_hybrid_analysis(
    dummy_connector, file_message, hybrid_analysis_report
):
    """_process_message routes StixFile messages through hash-search enrichment."""
    # Given a StixFile message fixture
    data = file_message
    opencti_entity = data["enrichment_entity"]

    # Mock the hash search to return a report as if the file existed on Hybrid Analysis
    dummy_connector._search_hash.return_value = hybrid_analysis_report

    # When _process_message is called
    dummy_connector._process_message(data)

    # Then only the file path methods are called
    called_entity = dummy_connector._search_hash.call_args[0][0]
    assert called_entity["entity_type"] == opencti_entity["entity_type"]
    assert called_entity["observable_value"] == opencti_entity["observable_value"]

    dummy_connector._submit_url.assert_not_called()
    dummy_connector._trigger_sandbox.assert_not_called()
    dummy_connector._create_knowledge.assert_called_once()
    dummy_connector._send_bundle.assert_called_once()


def test_process_message_routes_to_expected_method_when_file_does_not_exist_on_hybrid_analysis(
    dummy_connector, file_message, hybrid_analysis_report
):
    """_process_message routes StixFile messages through hash-search enrichment."""
    # Mock the hash search to return a report as if the file did not exist on Hybrid Analysis
    dummy_connector._search_hash.return_value = None
    dummy_connector._trigger_sandbox.return_value = hybrid_analysis_report

    # Given a StixFile message fixture
    data = file_message
    opencti_entity = data["enrichment_entity"]

    # When _process_message is called
    dummy_connector._process_message(data)

    # Then only the file path methods are called
    called_entity = dummy_connector._search_hash.call_args[0][0]
    assert called_entity["entity_type"] == opencti_entity["entity_type"]
    assert called_entity["observable_value"] == opencti_entity["observable_value"]

    called_entity = dummy_connector._trigger_sandbox.call_args[0][0]
    assert called_entity["entity_type"] == opencti_entity["entity_type"]
    assert called_entity["observable_value"] == opencti_entity["observable_value"]

    dummy_connector._submit_url.assert_not_called()
    dummy_connector._create_knowledge.assert_called_once()
    dummy_connector._send_bundle.assert_called_once()


def test_process_message_routes_to_expected_method_when_artifact_exists_on_hybrid_analysis(
    dummy_connector, artifact_message, hybrid_analysis_report
):
    """_process_message routes Artifact messages through hash-search enrichment."""
    # Mock the hash search to return a report as if the artifact existed on Hybrid Analysis
    dummy_connector._search_hash.return_value = hybrid_analysis_report

    # Given a Artifact message fixture
    data = artifact_message
    opencti_entity = data["enrichment_entity"]

    # When _process_message is called
    dummy_connector._process_message(data)

    # Then only the artifact path methods are called
    called_entity = dummy_connector._search_hash.call_args[0][0]
    assert called_entity["entity_type"] == opencti_entity["entity_type"]
    assert called_entity["observable_value"] == opencti_entity["observable_value"]

    dummy_connector._submit_url.assert_not_called()
    dummy_connector._trigger_sandbox.assert_not_called()
    dummy_connector._create_knowledge.assert_called_once()
    dummy_connector._send_bundle.assert_called_once()


def test_process_message_routes_to_expected_method_when_artifact_does_not_exist_on_hybrid_analysis(
    dummy_connector, artifact_message, hybrid_analysis_report
):
    """_process_message routes Artifact messages through hash-search enrichment."""
    # Mock the hash search to return a report as if the artifact did not exist on Hybrid Analysis
    dummy_connector._search_hash.return_value = None
    dummy_connector._trigger_sandbox.return_value = hybrid_analysis_report

    # Given a Artifact message fixture
    data = artifact_message
    opencti_entity = data["enrichment_entity"]

    # When _process_message is called
    dummy_connector._process_message(data)

    # Then only the artifact path methods are called
    called_entity = dummy_connector._search_hash.call_args[0][0]
    assert called_entity["entity_type"] == opencti_entity["entity_type"]
    assert called_entity["observable_value"] == opencti_entity["observable_value"]

    called_entity = dummy_connector._trigger_sandbox.call_args[0][0]
    assert called_entity["entity_type"] == opencti_entity["entity_type"]
    assert called_entity["observable_value"] == opencti_entity["observable_value"]

    dummy_connector._submit_url.assert_not_called()
    dummy_connector._create_knowledge.assert_called_once()
    dummy_connector._send_bundle.assert_called_once()


def test_process_message_routes_to_expected_method_when_url(
    dummy_connector, url_message, hybrid_analysis_report
):
    """_process_message routes URL messages through URL submission enrichment."""
    # Mock the URL submission to return a report as if the URL was submitted to Hybrid Analysis
    dummy_connector._submit_url.return_value = hybrid_analysis_report

    # Given a URL message fixture
    data = url_message
    opencti_entity = data["enrichment_entity"]

    # When _process_message is called
    dummy_connector._process_message(data)

    # Then only the URL path methods are called
    called_entity = dummy_connector._submit_url.call_args[0][0]
    assert called_entity["entity_type"] == opencti_entity["entity_type"]
    assert called_entity["observable_value"] == opencti_entity["observable_value"]

    dummy_connector._search_hash.assert_not_called()
    dummy_connector._trigger_sandbox.assert_not_called()
    dummy_connector._create_knowledge.assert_called_once()
    dummy_connector._send_bundle.assert_called_once()


def test_create_knowledge_produces_expected_output_when_file(
    stub_connector, file_message, hybrid_analysis_report
):
    """_create_knowledge enriches file entities with hashes and size."""
    data = file_message
    stix_entity = data["stix_entity"]
    opencti_entity = data["enrichment_entity"]
    stub_connector.stix_objects = data["stix_objects"]

    # When _create_knowledge is called
    result = stub_connector._create_knowledge(
        stix_entity, opencti_entity, hybrid_analysis_report
    )

    # Then common output objects are present
    assert _stix_bundle_contains_exact(result, stub_connector.identity.id)
    assert _stix_bundle_contains_exact(result, stub_connector.tlp.id)
    assert _stix_bundle_contains_exact(result, stix_entity.get("id"))

    # Then report-derived STIX objects are present in the bundle
    assert _stix_bundle_contains_any(
        result,
        [
            "software",
            "malware-analysis",
            "attack-pattern",
            "domain-name",
            "ipv4-addr",
            "ipv6-addr",
            "file",
        ],
    )

    # Then file-specific enrichment is present
    enriched_entity = next(
        obj
        for obj in result
        if isinstance(obj, dict) and obj.get("id") == stix_entity.get("id")
    )
    assert enriched_entity["x_opencti_score"] == hybrid_analysis_report["threat_score"]
    assert "trojan" in enriched_entity["labels"]
    assert enriched_entity["hashes"]["MD5"] == hybrid_analysis_report["md5"]
    assert enriched_entity["hashes"]["SHA-1"] == hybrid_analysis_report["sha1"]
    assert enriched_entity["hashes"]["SHA-256"] == hybrid_analysis_report["sha256"]
    assert (
        enriched_entity["x_opencti_additional_names"]
        == hybrid_analysis_report["submit_name"]
    )
    assert enriched_entity["size"] == hybrid_analysis_report["size"]


def test_create_knowledge_produces_expected_output_when_artifact(
    stub_connector, artifact_message, hybrid_analysis_report
):
    """_create_knowledge enriches artifact entities with hashes but not size."""
    data = artifact_message
    stix_entity = data["stix_entity"]
    opencti_entity = data["enrichment_entity"]
    stub_connector.stix_objects = data["stix_objects"]

    # When _create_knowledge is called
    result = stub_connector._create_knowledge(
        stix_entity, opencti_entity, hybrid_analysis_report
    )

    # Then common output objects are present
    assert _stix_bundle_contains_exact(result, stub_connector.identity.id)
    assert _stix_bundle_contains_exact(result, stub_connector.tlp.id)
    assert _stix_bundle_contains_exact(result, stix_entity.get("id"))

    # Then report-derived STIX objects are present in the bundle
    assert _stix_bundle_contains_any(
        result,
        [
            "software",
            "malware-analysis",
            "attack-pattern",
            "domain-name",
            "ipv4-addr",
            "ipv6-addr",
            "file",
        ],
    )

    # Then artifact-specific enrichment is present
    enriched_entity = next(
        obj
        for obj in result
        if isinstance(obj, dict) and obj.get("id") == stix_entity.get("id")
    )
    assert enriched_entity["x_opencti_score"] == hybrid_analysis_report["threat_score"]
    assert "trojan" in enriched_entity["labels"]
    assert enriched_entity["hashes"]["MD5"] == hybrid_analysis_report["md5"]
    assert enriched_entity["hashes"]["SHA-1"] == hybrid_analysis_report["sha1"]
    assert enriched_entity["hashes"]["SHA-256"] == hybrid_analysis_report["sha256"]
    assert (
        enriched_entity["x_opencti_additional_names"]
        == hybrid_analysis_report["submit_name"]
    )
    assert "size" not in enriched_entity


def test_create_knowledge_produces_expected_output_when_url(
    stub_connector, url_message, hybrid_analysis_report
):
    """_create_knowledge enriches URL entities without file-specific fields."""
    data = url_message
    stix_entity = data["stix_entity"]
    opencti_entity = data["enrichment_entity"]
    stub_connector.stix_objects = data["stix_objects"]

    # When _create_knowledge is called
    result = stub_connector._create_knowledge(
        stix_entity, opencti_entity, hybrid_analysis_report
    )

    # Then common output objects are present
    assert _stix_bundle_contains_exact(result, stub_connector.identity.id)
    assert _stix_bundle_contains_exact(result, stub_connector.tlp.id)
    assert _stix_bundle_contains_exact(result, stix_entity.get("id"))

    # Then report-derived STIX objects are present in the bundle
    assert _stix_bundle_contains_any(
        result,
        [
            "software",
            "malware-analysis",
            "attack-pattern",
            "domain-name",
            "ipv4-addr",
            "ipv6-addr",
            "file",
        ],
    )

    # Then URL-specific enrichment excludes file-specific fields
    enriched_entity = next(
        obj
        for obj in result
        if isinstance(obj, dict) and obj.get("id") == stix_entity.get("id")
    )
    assert enriched_entity["x_opencti_score"] == hybrid_analysis_report["threat_score"]
    assert "trojan" in enriched_entity["labels"]
    assert "x_opencti_additional_names" not in enriched_entity
    assert "size" not in enriched_entity

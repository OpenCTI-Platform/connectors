import json
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest
import stix2
from connector import ConnectorSettings, PaloaltoWildfireConnector
from paloalto_wildfire_client import WildfireAPIError
from pycti import OpenCTIConnectorHelper

DATA_DIR = Path(__file__).parent / "data"

WILDFIRE_RESULT = {
    "verdict": 1,
    "hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "report": {
        "md5": "d41d8cd98f00b204e9800998ecf8427e",
        "sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
        "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "size": "1024",
        "filetype": "PE32",
        "malware": "yes",
    },
}


def _load(name: str) -> dict:
    with (DATA_DIR / name).open("r", encoding="utf-8") as f:
        return json.load(f)


def _settings_dict(submit_unknown: bool = False) -> dict:
    return {
        "opencti": {"url": "http://localhost:8080", "token": "test-token"},
        "connector": {
            "id": "connector-id",
            "name": "Test Connector",
            "scope": "StixFile,Artifact",
            "log_level": "error",
            "auto": True,
        },
        "paloalto_wildfire": {
            "api_key": "test-api-key",
            "submit_unknown": submit_unknown,
        },
    }


class StubConnectorSettings(ConnectorSettings):
    """Deterministic settings for tests (submission disabled)."""

    @classmethod
    def _load_config_dict(cls, _, handler) -> dict[str, Any]:
        return handler(_settings_dict())


class StubConnectorSettingsSubmit(ConnectorSettings):
    """Deterministic settings for tests (submission enabled)."""

    @classmethod
    def _load_config_dict(cls, _, handler) -> dict[str, Any]:
        return handler(_settings_dict(submit_unknown=True))


@pytest.fixture
def file_message() -> dict:
    return _load("file_message.json")


@pytest.fixture
def artifact_message() -> dict:
    return _load("artifact_message.json")


@pytest.fixture
def dummy_connector(mock_opencti_connector_helper):
    settings = StubConnectorSettings()
    helper = OpenCTIConnectorHelper(config=settings.to_helper_config())
    helper.send_stix2_bundle = MagicMock()

    connector = PaloaltoWildfireConnector(config=settings, helper=helper)
    connector.client = MagicMock()
    connector._search_hash = MagicMock()
    connector._submit = MagicMock()
    connector._create_knowledge = MagicMock()
    connector._send_bundle = MagicMock()
    return connector


@pytest.fixture
def submit_connector(mock_opencti_connector_helper):
    settings = StubConnectorSettingsSubmit()
    helper = OpenCTIConnectorHelper(config=settings.to_helper_config())
    helper.send_stix2_bundle = MagicMock()

    connector = PaloaltoWildfireConnector(config=settings, helper=helper)
    connector.client = MagicMock()
    connector._search_hash = MagicMock(return_value=None)
    connector._submit = MagicMock(return_value=WILDFIRE_RESULT)
    connector._create_knowledge = MagicMock(return_value=["bundle"])
    connector._send_bundle = MagicMock()
    return connector


@pytest.fixture
def stub_connector(mock_opencti_connector_helper):
    settings = StubConnectorSettings()
    helper = OpenCTIConnectorHelper(config=settings.to_helper_config())
    helper.send_stix2_bundle = MagicMock()

    connector = PaloaltoWildfireConnector(config=settings, helper=helper)
    connector.identity = stix2.Identity(
        id="identity--4a9e7924-46a1-43f7-962b-e61f53f4b0ca",
        name="WildFire",
        identity_class="organization",
    )
    connector.tlp = stix2.TLP_WHITE
    connector.client = MagicMock()
    return connector


def test_process_message_ignores_entity_exceeding_max_tlp(
    dummy_connector, file_message
):
    dummy_connector.max_tlp = "TLP:CLEAR"

    dummy_connector._process_message(file_message)

    dummy_connector._search_hash.assert_not_called()
    dummy_connector._create_knowledge.assert_not_called()
    dummy_connector._send_bundle.assert_called_with(file_message["stix_objects"])


@pytest.mark.parametrize(
    "raised",
    [WildfireAPIError("api error"), Exception("unexpected")],
    ids=["wildfire-api-error", "unexpected-exception"],
)
def test_process_message_handles_exceptions(dummy_connector, file_message, raised):
    dummy_connector._search_hash = MagicMock(side_effect=raised)

    with pytest.raises(type(raised)):
        dummy_connector._process_message(file_message)

    dummy_connector._search_hash.assert_called_once()
    dummy_connector._create_knowledge.assert_not_called()
    dummy_connector._send_bundle.assert_called_with(file_message["stix_objects"])


def test_process_message_routes_file_with_verdict(dummy_connector, file_message):
    dummy_connector._search_hash.return_value = WILDFIRE_RESULT

    dummy_connector._process_message(file_message)

    dummy_connector._search_hash.assert_called_once()
    dummy_connector._create_knowledge.assert_called_once()
    dummy_connector._send_bundle.assert_called_once()


def test_process_message_no_verdict_sends_original(dummy_connector, file_message):
    dummy_connector._search_hash.return_value = None

    dummy_connector._process_message(file_message)

    dummy_connector._submit.assert_not_called()  # submit_unknown is False
    dummy_connector._create_knowledge.assert_not_called()
    dummy_connector._send_bundle.assert_called_with(file_message["stix_objects"])


def test_process_message_submits_when_enabled(submit_connector, file_message):
    submit_connector._process_message(file_message)

    submit_connector._search_hash.assert_called_once()
    submit_connector._submit.assert_called_once()
    submit_connector._create_knowledge.assert_called_once()


def test_process_message_out_of_scope_returns_original_bundle(
    dummy_connector, file_message
):
    # Playbook trigger (no event_type): the original bundle must be returned
    # unchanged when the entity is not in the connector scope.
    file_message["enrichment_entity"]["entity_type"] = "Url"

    message = dummy_connector._process_message(file_message)

    assert "not in connector scope" in message
    dummy_connector._search_hash.assert_not_called()
    dummy_connector._send_bundle.assert_called_with(file_message["stix_objects"])


def test_process_message_out_of_scope_event_raises(dummy_connector, file_message):
    # Direct enrichment event (event_type set) on an unsupported entity type.
    file_message["enrichment_entity"]["entity_type"] = "Url"
    file_message["event_type"] = "INTERNAL_ENRICHMENT"

    with pytest.raises(ValueError, match="not a supported entity type"):
        dummy_connector._process_message(file_message)


def test_create_knowledge_file(stub_connector, file_message):
    data = file_message
    stub_connector.stix_objects = data["stix_objects"]

    result = stub_connector._create_knowledge(
        data["stix_entity"], data["enrichment_entity"], WILDFIRE_RESULT
    )

    types = {o["type"] if isinstance(o, dict) else o.type for o in result}
    assert "identity" in types
    assert "malware-analysis" in types

    enriched = next(
        o
        for o in result
        if isinstance(o, dict) and o.get("id") == data["stix_entity"]["id"]
    )
    assert enriched["x_opencti_score"] == 90
    assert "wildfire:malware" in enriched["labels"]
    assert enriched["hashes"]["MD5"] == WILDFIRE_RESULT["report"]["md5"]
    assert enriched["size"] == 1024
    # The WildFire report file type is mapped onto the STIX File mime_type.
    assert enriched["mime_type"] == WILDFIRE_RESULT["report"]["filetype"]

    # The Malware Analysis object must carry the SOURCE observable's marking
    # (TLP:AMBER from the message's objectMarking), and that marking object must be
    # included in the bundle so the SDO is correctly marked and self-contained -
    # not silently downgraded to the connector default.
    malware_analysis = next(
        o
        for o in result
        if not isinstance(o, dict) and getattr(o, "type", None) == "malware-analysis"
    )
    assert stix2.TLP_AMBER.id in malware_analysis["object_marking_refs"]
    marking_ids = {
        o.id for o in result if getattr(o, "type", None) == "marking-definition"
    }
    assert stix2.TLP_AMBER.id in marking_ids


def test_create_knowledge_artifact(stub_connector, artifact_message):
    data = artifact_message
    stub_connector.stix_objects = data["stix_objects"]

    result = stub_connector._create_knowledge(
        data["stix_entity"], data["enrichment_entity"], WILDFIRE_RESULT
    )

    enriched = next(
        o
        for o in result
        if isinstance(o, dict) and o.get("id") == data["stix_entity"]["id"]
    )
    assert enriched["x_opencti_score"] == 90
    assert "size" not in enriched


def test_extract_hash_priority():
    entity = {
        "hashes": [
            {"algorithm": "MD5", "hash": "m"},
            {"algorithm": "SHA-256", "hash": "s"},
        ]
    }
    assert PaloaltoWildfireConnector._extract_hash(entity) == "s"


def test_search_hash_no_hash_returns_none(stub_connector):
    assert stub_connector._search_hash({"hashes": []}) is None


def test_search_hash_unknown_verdict_returns_none(stub_connector):
    stub_connector.client.get_verdict.return_value = None

    result = stub_connector._search_hash(
        {"hashes": [{"algorithm": "SHA-256", "hash": "s"}]}
    )
    assert result is None


def test_search_hash_with_verdict(stub_connector):
    stub_connector.client.get_verdict.return_value = 1
    stub_connector.client.get_report.return_value = {"sha256": "s"}

    result = stub_connector._search_hash(
        {"hashes": [{"algorithm": "SHA-256", "hash": "s"}]}
    )
    assert result["verdict"] == 1
    assert result["hash"] == "s"


def test_download_file_no_import_files(stub_connector):
    name, content, error = stub_connector._download_file({"importFiles": []})
    assert content is None
    assert "No file attached" in error


def test_download_file_rejects_declared_oversize(stub_connector):
    entity = {
        "importFiles": [
            {"id": "f1", "name": "big.bin", "size": stub_connector.max_file_size + 1}
        ]
    }
    name, content, error = stub_connector._download_file(entity)
    assert content is None
    assert "limit" in error


def test_download_file_rejects_empty(stub_connector):
    stub_connector.helper.api.fetch_opencti_file = MagicMock(return_value=b"")
    entity = {"importFiles": [{"id": "f1", "name": "empty.bin"}]}

    name, content, error = stub_connector._download_file(entity)
    assert content is None
    assert "empty" in error


def test_download_file_success(stub_connector):
    stub_connector.helper.api.fetch_opencti_file = MagicMock(return_value=b"payload")
    entity = {"importFiles": [{"id": "f1", "name": "malware.exe"}]}

    name, content, error = stub_connector._download_file(entity)
    assert error is None
    assert name == "malware.exe"
    assert content == b"payload"
    file_url = stub_connector.helper.api.fetch_opencti_file.call_args[0][0]
    assert file_url == "http://localhost:8080/storage/get/f1"


def test_submit_returns_verdict(stub_connector):
    stub_connector.helper.api.fetch_opencti_file = MagicMock(return_value=b"data")
    stub_connector.client.submit_file = MagicMock(return_value="sha256-1")
    stub_connector.client.poll_verdict = MagicMock(return_value=1)
    stub_connector.client.get_report = MagicMock(return_value={"sha256": "sha256-1"})

    entity = {"importFiles": [{"id": "f1", "name": "malware.exe"}]}
    result = stub_connector._submit(entity)
    assert result["verdict"] == 1
    assert result["hash"] == "sha256-1"


def test_submit_skips_on_download_error(stub_connector):
    stub_connector.client.submit_file = MagicMock()
    stub_connector._download_file = MagicMock(return_value=(None, None, "boom"))

    assert stub_connector._submit({"importFiles": [{"id": "f1"}]}) is None
    stub_connector.client.submit_file.assert_not_called()


def test_submit_unknown_defaults_to_false():
    # File submission/detonation uploads the sample to WildFire, so it is opt-in:
    # it must stay disabled unless explicitly enabled (issue #6730 scopes the first
    # version to verdict-by-hash only).
    class _Settings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler):
            return handler(
                {
                    "opencti": {"url": "http://localhost:8080", "token": "t"},
                    "connector": {"id": "c", "scope": "StixFile,Artifact"},
                    "paloalto_wildfire": {"api_key": "k"},
                }
            )

    assert _Settings().paloalto_wildfire.submit_unknown is False

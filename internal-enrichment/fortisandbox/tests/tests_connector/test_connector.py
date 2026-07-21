import json
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest
import stix2
from connector import ConnectorSettings, FortisandboxConnector
from fortisandbox_client import FortiSandboxAPIError
from pycti import MarkingDefinition, OpenCTIConnectorHelper

DATA_DIR = Path(__file__).parent / "data"

FORTI_RESULT = {
    "rating": "Malicious",
    "score": 90,
    "malware_name": "W32/Agent",
    "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
    "md5": "d41d8cd98f00b204e9800998ecf8427e",
    "detail_url": "https://fsa.example.com/job/1",
    "category": "trojan",
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
        "fortisandbox": {
            "api_base_url": "https://fsa.example.com",
            "username": "api-user",
            "password": "api-pass",
            "submit_unknown": submit_unknown,
        },
    }


class StubConnectorSettings(ConnectorSettings):
    @classmethod
    def _load_config_dict(cls, _, handler) -> dict[str, Any]:
        return handler(_settings_dict())


class StubConnectorSettingsSubmit(ConnectorSettings):
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

    connector = FortisandboxConnector(config=settings, helper=helper)
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

    connector = FortisandboxConnector(config=settings, helper=helper)
    connector.client = MagicMock()
    connector._search_hash = MagicMock(return_value=None)
    connector._submit = MagicMock(return_value=FORTI_RESULT)
    connector._create_knowledge = MagicMock(return_value=["bundle"])
    connector._send_bundle = MagicMock()
    return connector


@pytest.fixture
def stub_connector(mock_opencti_connector_helper):
    settings = StubConnectorSettings()
    helper = OpenCTIConnectorHelper(config=settings.to_helper_config())
    helper.send_stix2_bundle = MagicMock()

    connector = FortisandboxConnector(config=settings, helper=helper)
    connector.identity = stix2.Identity(
        id="identity--4a9e7924-46a1-43f7-962b-e61f53f4b0ca",
        name="FortiSandbox",
        identity_class="organization",
    )
    # Keep the connector's real default marking (OpenCTI's custom TLP:CLEAR
    # statement marking) so tests exercise the runtime TLP handling.
    connector.client = MagicMock()
    return connector


def test_process_message_out_of_scope_playbook_returns_original(
    dummy_connector, file_message
):
    # No event_type in the message: the enrichment was triggered by a playbook,
    # so an out-of-scope entity must get the original bundle back unchanged.
    file_message["enrichment_entity"]["entity_type"] = "Url"

    dummy_connector._process_message(file_message)

    dummy_connector._search_hash.assert_not_called()
    dummy_connector._create_knowledge.assert_not_called()
    dummy_connector._send_bundle.assert_called_with(file_message["stix_objects"])


def test_process_message_out_of_scope_manual_raises(dummy_connector, file_message):
    # event_type present: manual enrichment of an unsupported entity type must fail.
    file_message["enrichment_entity"]["entity_type"] = "Url"
    file_message["event_type"] = "create"

    with pytest.raises(ValueError, match="not a supported entity type"):
        dummy_connector._process_message(file_message)

    dummy_connector._send_bundle.assert_not_called()


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
    [FortiSandboxAPIError("api error"), Exception("unexpected")],
    ids=["fortisandbox-api-error", "unexpected-exception"],
)
def test_process_message_handles_exceptions(dummy_connector, file_message, raised):
    dummy_connector._search_hash = MagicMock(side_effect=raised)

    with pytest.raises(type(raised)):
        dummy_connector._process_message(file_message)

    dummy_connector._search_hash.assert_called_once()
    dummy_connector._create_knowledge.assert_not_called()
    dummy_connector._send_bundle.assert_called_with(file_message["stix_objects"])


def test_process_message_routes_file_with_rating(dummy_connector, file_message):
    dummy_connector._search_hash.return_value = FORTI_RESULT

    dummy_connector._process_message(file_message)

    dummy_connector._search_hash.assert_called_once()
    dummy_connector._create_knowledge.assert_called_once()
    dummy_connector._send_bundle.assert_called_once()


def test_process_message_no_rating_sends_original(dummy_connector, file_message):
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


def test_create_knowledge_file(stub_connector, file_message):
    data = file_message
    stub_connector.stix_objects = data["stix_objects"]

    result = stub_connector._create_knowledge(
        data["stix_entity"], data["enrichment_entity"], FORTI_RESULT
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
    assert "fortisandbox:malicious" in enriched["labels"]
    assert "malware:W32/Agent" in enriched["labels"]
    assert enriched["hashes"]["MD5"] == FORTI_RESULT["md5"]

    # The Malware Analysis object must carry markings (inherited or default) so the
    # enrichment never produces an unmarked object.
    malware_analysis = next(
        o
        for o in result
        if not isinstance(o, dict) and getattr(o, "type", None) == "malware-analysis"
    )
    assert malware_analysis["object_marking_refs"]


def test_create_knowledge_inherits_observable_marking(stub_connector, file_message):
    # The observable carries TLP:AMBER; the Malware Analysis must inherit AMBER
    # rather than be downgraded to the connector default marking.
    data = file_message
    stub_connector.stix_objects = data["stix_objects"]

    result = stub_connector._create_knowledge(
        data["stix_entity"], data["enrichment_entity"], FORTI_RESULT
    )

    malware_analysis = next(
        o for o in result if getattr(o, "type", None) == "malware-analysis"
    )
    assert stix2.TLP_AMBER.id in malware_analysis["object_marking_refs"]
    # The marking object is included in the bundle so the ref resolves.
    assert any(getattr(o, "id", None) == stix2.TLP_AMBER.id for o in result)


def test_create_knowledge_falls_back_to_custom_tlp_clear(stub_connector, file_message):
    # Without markings on the observable, the Malware Analysis must carry the
    # connector default: OpenCTI's custom TLP:CLEAR statement marking (generated
    # via pycti's deterministic id), not the legacy stix2.TLP_WHITE.
    data = file_message
    data["enrichment_entity"]["objectMarking"] = []
    stub_connector.stix_objects = data["stix_objects"]

    result = stub_connector._create_knowledge(
        data["stix_entity"], data["enrichment_entity"], FORTI_RESULT
    )

    expected_id = MarkingDefinition.generate_id("TLP", "TLP:CLEAR")
    malware_analysis = next(
        o for o in result if getattr(o, "type", None) == "malware-analysis"
    )
    assert malware_analysis["object_marking_refs"] == [expected_id]
    tlp_clear = next(o for o in result if getattr(o, "id", None) == expected_id)
    assert tlp_clear["x_opencti_definition"] == "TLP:CLEAR"


def test_extract_hash_priority():
    entity = {
        "hashes": [
            {"algorithm": "MD5", "hash": "m"},
            {"algorithm": "SHA-256", "hash": "s"},
        ]
    }
    assert FortisandboxConnector._extract_hash(entity) == ("s", "sha256")


def test_extract_hash_sha1_fallback():
    entity = {"hashes": [{"algorithm": "SHA-1", "hash": "h1"}]}
    assert FortisandboxConnector._extract_hash(entity) == ("h1", "sha1")


def test_extract_hash_md5_fallback():
    entity = {"hashes": [{"algorithm": "MD5", "hash": "m1"}]}
    assert FortisandboxConnector._extract_hash(entity) == ("m1", "md5")


def test_extract_hash_none():
    assert FortisandboxConnector._extract_hash({"hashes": []}) == (None, None)


def test_process_observable_non_file_returns_none(stub_connector):
    result = stub_connector._process_observable(
        {"id": "url--1"}, {"entity_type": "Url", "observable_value": "http://x"}
    )
    assert result is None


def test_create_knowledge_artifact_without_detail_url(stub_connector, artifact_message):
    data = artifact_message
    stub_connector.stix_objects = data["stix_objects"]
    forti = dict(FORTI_RESULT)
    forti.pop("detail_url")

    result = stub_connector._create_knowledge(
        data["stix_entity"], data["enrichment_entity"], forti
    )

    enriched = next(
        o
        for o in result
        if isinstance(o, dict) and o.get("id") == data["stix_entity"]["id"]
    )
    assert enriched["x_opencti_score"] == 90
    malware_analysis = next(
        o for o in result if getattr(o, "type", None) == "malware-analysis"
    )
    assert malware_analysis["external_references"][0]["external_id"] == forti["sha256"]


def test_submit_returns_verdict(stub_connector):
    stub_connector.helper.api.api_url = "http://localhost:8080/graphql"
    stub_connector.helper.api.fetch_opencti_file = MagicMock(return_value=b"data")
    stub_connector.client.submit_file = MagicMock(return_value="sid-1")
    stub_connector.client.get_submission_verdict = MagicMock(return_value=FORTI_RESULT)

    opencti_entity = {"importFiles": [{"id": "storage-id", "name": "malware.exe"}]}
    result = stub_connector._submit(opencti_entity)
    assert result == FORTI_RESULT
    stub_connector.client.submit_file.assert_called_once()


def test_submit_no_import_files_returns_none(stub_connector):
    assert stub_connector._submit({"importFiles": []}) is None


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
    stub_connector.helper.api.api_url = "http://localhost:8080/graphql"
    stub_connector.helper.api.fetch_opencti_file = MagicMock(return_value=b"")
    entity = {"importFiles": [{"id": "f1", "name": "empty.bin"}]}

    name, content, error = stub_connector._download_file(entity)
    assert content is None
    assert "empty" in error


def test_download_file_success(stub_connector):
    stub_connector.helper.api.api_url = "http://localhost:8080/graphql"
    stub_connector.helper.api.fetch_opencti_file = MagicMock(return_value=b"payload")
    entity = {"importFiles": [{"id": "f1", "name": "malware.exe"}]}

    name, content, error = stub_connector._download_file(entity)
    assert error is None
    assert name == "malware.exe"
    assert content == b"payload"


def test_submit_skips_on_download_error(stub_connector):
    stub_connector.client.submit_file = MagicMock()
    stub_connector._download_file = MagicMock(return_value=(None, None, "boom"))

    assert stub_connector._submit({"importFiles": [{"id": "f1"}]}) is None
    stub_connector.client.submit_file.assert_not_called()


def test_submit_unknown_defaults_to_true():
    from connector import ConnectorSettings

    class _Settings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler):
            return handler(
                {
                    "opencti": {"url": "http://localhost:8080", "token": "t"},
                    "connector": {"id": "c", "scope": "StixFile,Artifact"},
                    "fortisandbox": {
                        "api_base_url": "https://fsa.example.com",
                        "username": "u",
                        "password": "p",
                    },
                }
            )

    assert _Settings().fortisandbox.submit_unknown is True


def test_search_hash_unknown_rating_returns_none(stub_connector):
    stub_connector.client.get_file_rating.return_value = {"rating": "Unknown"}

    result = stub_connector._search_hash(
        {"hashes": [{"algorithm": "SHA-256", "hash": "s"}]}
    )
    assert result is None


def test_search_hash_with_rating(stub_connector):
    stub_connector.client.get_file_rating.return_value = FORTI_RESULT

    result = stub_connector._search_hash(
        {"hashes": [{"algorithm": "SHA-256", "hash": "s"}]}
    )
    assert result["rating"] == "Malicious"

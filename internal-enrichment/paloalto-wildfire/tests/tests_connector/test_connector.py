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


class StubConnectorSettings(ConnectorSettings):
    """Deterministic settings for tests."""

    @classmethod
    def _load_config_dict(cls, _, handler) -> dict[str, Any]:
        return handler(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                "connector": {
                    "id": "connector-id",
                    "name": "Test Connector",
                    "scope": "StixFile,Artifact",
                    "log_level": "error",
                    "auto": True,
                },
                "paloalto_wildfire": {"api_key": "test-api-key"},
            }
        )


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
    connector._create_knowledge = MagicMock()
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

    dummy_connector._create_knowledge.assert_not_called()
    dummy_connector._send_bundle.assert_called_with(file_message["stix_objects"])


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

"""Unit tests for the XTM One mode of ``ImportDocumentAIClient``.

These tests focus on ``get_bundle_via_xtm_one``, which talks to the OpenCTI
``/chatbot/agent`` proxy. The proxy answers HTTP 200 even on upstream
failures (it relays them through an error envelope), so the connector must
both surface those errors and robustly parse the success payload.
"""

import json
import sys
import uuid
from io import BytesIO
from pathlib import Path
from unittest.mock import Mock

import pytest
import requests
import stix2
import stix2.exceptions

sys.path.append(str((Path(__file__).resolve().parent.parent / "src")))

from import_doc_ai.client_api import ImportDocumentAIClient


class FakeResponse:
    """Minimal ``requests.Response`` stand-in for the proxy reply."""

    def __init__(self, json_data, status_code: int = 200, text: str | None = None):
        self._json_data = json_data
        self.status_code = status_code
        self.text = text if text is not None else json.dumps(json_data)

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise requests.HTTPError(f"HTTP {self.status_code}")

    def json(self):
        if isinstance(self._json_data, Exception):
            raise self._json_data
        return self._json_data


@pytest.fixture(name="xtm_client")
def fixture_xtm_client() -> ImportDocumentAIClient:
    helper = Mock()
    helper.api.query.return_value = {"data": {"settings": {"id": "instance-id"}}}
    helper.opencti_url = "http://opencti.local"
    helper.api.api_token = "test-token"
    helper.connector_logger.info = Mock()
    helper.connector_logger.error = Mock()
    config = Mock()
    config.licence_key_base64 = None
    return ImportDocumentAIClient(helper, config)


def _call(xtm_client: ImportDocumentAIClient, agent_slug: str = "cti-stix-harvester"):
    return xtm_client.get_bundle_via_xtm_one(
        file_name="report.pdf",
        file_mime="application/pdf",
        file_data=BytesIO(b"%PDF-1.4 test"),
        agent_slug=agent_slug,
        allowed_relationship_triplets=set(),
    )


def _bundle_dict() -> dict:
    return {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": [
            {
                "type": "identity",
                "spec_version": "2.1",
                "id": f"identity--{uuid.uuid4()}",
                "name": "ACME Corp",
                "identity_class": "organization",
            }
        ],
    }


def _patch_post(monkeypatch, response: FakeResponse) -> None:
    monkeypatch.setattr(
        "import_doc_ai.client_api.requests.post",
        lambda *args, **kwargs: response,
    )


def test_success_assistant_message_bare_bundle(monkeypatch, xtm_client):
    # Given the multipart proxy relays a SendMessageResponse with a bare bundle
    bundle = _bundle_dict()
    _patch_post(
        monkeypatch,
        FakeResponse(
            {
                "user_message": {"content": "Extract STIX from the attached files"},
                "assistant_message": {"content": json.dumps(bundle)},
                "conversation_id": str(uuid.uuid4()),
            }
        ),
    )

    # When fetching the bundle
    result = _call(xtm_client)

    # Then the bundle is parsed and returned
    assert result["type"] == "bundle"
    assert len(result["objects"]) == 1
    assert result["objects"][0]["type"] == "identity"


def test_success_content_wrapped_in_code_fence_and_response_key(
    monkeypatch, xtm_client
):
    # Given an LLM agent that fenced its JSON and nested it under "response"
    bundle = _bundle_dict()
    fenced = "```json\n" + json.dumps({"response": bundle}) + "\n```"
    _patch_post(
        monkeypatch,
        FakeResponse({"assistant_message": {"content": fenced}}),
    )

    # When fetching the bundle
    result = _call(xtm_client)

    # Then the fence is stripped, the wrapper unwrapped and the bundle parsed
    assert result["type"] == "bundle"
    assert len(result["objects"]) == 1


def test_error_envelope_raises_actionable_error(monkeypatch, xtm_client):
    # Given the proxy relays an upstream failure via its 200 error envelope
    _patch_post(
        monkeypatch,
        FakeResponse(
            {
                "content": "",
                "status": "error",
                "error": "XTM One is unreachable",
                "code": 503,
            }
        ),
    )

    # When fetching the bundle, then a clear error surfaces the real cause
    with pytest.raises(ValueError) as exc_info:
        _call(xtm_client)

    message = str(exc_info.value)
    assert "cti-stix-harvester" in message
    assert "503" in message
    assert "unreachable" in message.lower()
    # And the generic, misleading message is gone
    assert "Unexpected response format" not in message


def test_empty_assistant_content_raises_clear_error(monkeypatch, xtm_client):
    # Given a success-shaped reply whose assistant content is blank
    _patch_post(
        monkeypatch,
        FakeResponse({"assistant_message": {"content": "   "}}),
    )

    # When fetching the bundle, then the empty response is reported clearly
    with pytest.raises(ValueError) as exc_info:
        _call(xtm_client)

    assert "empty response" in str(exc_info.value)


def test_non_json_content_raises_clear_error(monkeypatch, xtm_client):
    # Given an assistant message that is not valid JSON
    _patch_post(
        monkeypatch,
        FakeResponse(
            {"assistant_message": {"content": "I could not extract anything"}}
        ),
    )

    # When fetching the bundle, then the JSON decode failure is reported clearly
    with pytest.raises(ValueError) as exc_info:
        _call(xtm_client)

    assert "not " in str(exc_info.value)
    assert "valid JSON" in str(exc_info.value)


def test_non_json_http_body_raises_clear_error(monkeypatch, xtm_client):
    # Given the proxy returns a non-JSON body (e.g. an HTML error page)
    _patch_post(
        monkeypatch,
        FakeResponse(ValueError("no json"), text="<html>502 Bad Gateway</html>"),
    )

    # When fetching the bundle, then the non-JSON response is reported clearly
    with pytest.raises(ValueError) as exc_info:
        _call(xtm_client)

    assert "non-JSON response" in str(exc_info.value)


def test_non_dict_json_response_raises_clear_error(monkeypatch, xtm_client):
    # Given the proxy relays a non-object JSON payload (e.g. a bare list)
    _patch_post(monkeypatch, FakeResponse([1, 2, 3]))

    # When fetching the bundle, then the unexpected type is reported clearly
    with pytest.raises(ValueError) as exc_info:
        _call(xtm_client)

    message = str(exc_info.value)
    assert "unexpected response type" in message
    assert "list" in message


def test_success_text_mode_content(monkeypatch, xtm_client):
    # Given a text-mode reply returning the bundle under a top-level "content"
    bundle = _bundle_dict()
    _patch_post(
        monkeypatch,
        FakeResponse({"content": json.dumps(bundle), "status": "success"}),
    )

    # When fetching the bundle
    result = _call(xtm_client)

    # Then the top-level content is parsed into the bundle
    assert result["type"] == "bundle"
    assert len(result["objects"]) == 1


def test_success_assistant_content_already_dict(monkeypatch, xtm_client):
    # Given an assistant message whose content is an already-decoded bundle dict
    bundle = _bundle_dict()
    _patch_post(
        monkeypatch,
        FakeResponse({"assistant_message": {"content": bundle}}),
    )

    # When fetching the bundle
    result = _call(xtm_client)

    # Then the dict content is used directly
    assert result["type"] == "bundle"
    assert len(result["objects"]) == 1


def test_json_array_content_raises_clear_error(monkeypatch, xtm_client):
    # Given assistant content that is valid JSON but not an object (a list)
    _patch_post(
        monkeypatch,
        FakeResponse({"assistant_message": {"content": "[1, 2, 3]"}}),
    )

    # When fetching the bundle, then the non-object payload is reported clearly
    with pytest.raises(ValueError) as exc_info:
        _call(xtm_client)

    assert "expected a STIX bundle object" in str(exc_info.value)


def test_non_string_non_dict_content_raises_clear_error(monkeypatch, xtm_client):
    # Given assistant content that is neither a string nor a dict (e.g. a number)
    _patch_post(monkeypatch, FakeResponse({"assistant_message": {"content": 123}}))

    # When fetching the bundle, then the unexpected content type is reported
    with pytest.raises(ValueError) as exc_info:
        _call(xtm_client)

    assert "unexpected content type" in str(exc_info.value)


def test_connection_error_is_reraised(monkeypatch, xtm_client):
    # Given the chatbot proxy is unreachable
    def _raise(*args, **kwargs):
        raise requests.ConnectionError("boom")

    monkeypatch.setattr("import_doc_ai.client_api.requests.post", _raise)

    # When fetching the bundle, then a friendly ConnectionError is raised
    with pytest.raises(requests.ConnectionError) as exc_info:
        _call(xtm_client)

    assert "unreachable" in str(exc_info.value).lower()


def test_http_error_status_is_reraised(monkeypatch, xtm_client):
    # Given the proxy answers with a hard HTTP error status
    _patch_post(monkeypatch, FakeResponse({"detail": "boom"}, status_code=500))

    # When fetching the bundle, then the HTTP error propagates
    with pytest.raises(requests.RequestException):
        _call(xtm_client)


def test_invalid_stix_bundle_raises_stixerror(monkeypatch, xtm_client):
    # Given valid JSON that is not a valid STIX bundle (malware missing fields)
    invalid_bundle = {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": [
            {
                "type": "malware",
                "spec_version": "2.1",
                "id": f"malware--{uuid.uuid4()}",
            }
        ],
    }
    _patch_post(
        monkeypatch,
        FakeResponse({"assistant_message": {"content": json.dumps(invalid_bundle)}}),
    )

    # When fetching the bundle, then the STIX validation error surfaces
    with pytest.raises(stix2.exceptions.STIXError):
        _call(xtm_client)

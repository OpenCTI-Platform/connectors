import asyncio
import json
import sys
from http import HTTPStatus
from io import BytesIO
from pathlib import Path
from unittest.mock import Mock
from urllib.parse import urlparse

import pycti
import pytest
import requests
import stix2
from fastapi.testclient import TestClient
from requests.structures import CaseInsensitiveDict

sys.path.append(str((Path(__file__).resolve().parent.parent / "src")))
sys.path.append(str((Path(__file__).resolve().parent.parent / "dev")))

from fake_rest import app, generate_fake_certificate
from import_doc_ai.connector import Connector
from import_doc_ai.util import OpenCTIFileObject


@pytest.fixture(name="fastapi_test_client")
def fixture_fastapi_test_client():
    test_client = TestClient(app)
    yield test_client
    test_client.close()


@pytest.fixture(name="mock_connector_helper")
def fixture_mock_connector_helper() -> Mock:
    helper = Mock()
    helper.api.query.return_value = {
        "data": {"settings": {"id": "opencti-instance-id"}}
    }
    helper.get_only_contextual.return_value = False
    helper.send_stix2_bundle = Mock()
    helper.connector_logger.info = Mock()
    helper.connector_logger.error = Mock()
    helper.connector_logger.warning = Mock()
    return helper


@pytest.fixture(name="mock_config")
def fixture_mock_config() -> Mock:
    config = Mock()
    config.api_base_url = "http://testserver"
    config.create_indicator = False
    config.include_relationships = False
    config.licence_key_base64 = generate_fake_certificate(
        common_name="test",
        validity_start=None,
        validity_duration=None,
    ).decode("utf-8")
    return config


@pytest.fixture(name="imported_file")
def fixture_imported_file() -> OpenCTIFileObject:
    return OpenCTIFileObject(
        path="reports/smoke-test.pdf",
        buffered_data=BytesIO(b"%PDF-1.4 smoke test"),
        mime_type="application/pdf",
        id="import/global/smoke-test.pdf",
    )


def build_triggering_entity_mock(
    triggering_entity_stix: stix2.v21._STIXBase21,
    author_id: str | None = "identity--00000000-0000-4000-8000-000000000001",
    object_marking_refs: list[str] | None = None,
) -> Mock:
    triggering_entity = Mock()
    triggering_entity.id = triggering_entity_stix["id"]
    triggering_entity.author_id = author_id
    triggering_entity.object_marking_refs = (
        object_marking_refs
        if object_marking_refs is not None
        else [stix2.TLP_GREEN["id"]]
    )
    triggering_entity.get_stix = Mock(return_value=triggering_entity_stix)
    return triggering_entity


def connect_import_document_ai_client_to_test_server(
    connector: Connector, fastapi_test_client: TestClient
) -> None:
    """Adapt the ImportDocumentAIClient to send requests to the FastAPI test client with a request lib adaptation layer."""

    def to_header_bytes(value: str | bytes) -> bytes:
        if isinstance(value, bytes):
            return value
        return value.encode("latin-1")

    def to_header_str(value: str | bytes) -> str:
        if isinstance(value, bytes):
            return value.decode("latin-1")
        return value

    def dispatch_test_client_request_as_requests_response(
        test_client: TestClient, request
    ) -> requests.Response:
        request_body = request.read()
        response_start = {}
        response_body_parts = []
        request_has_been_sent = False

        async def receive():
            nonlocal request_has_been_sent
            if not request_has_been_sent:
                request_has_been_sent = True
                return {
                    "type": "http.request",
                    "body": request_body,
                    "more_body": False,
                }
            return {"type": "http.disconnect"}

        async def send(message):
            if message["type"] == "http.response.start":
                response_start["status"] = message["status"]
                response_start["headers"] = message.get("headers", [])
            elif message["type"] == "http.response.body":
                response_body_parts.append(message.get("body", b""))

        scope = {
            "type": "http",
            "asgi": {"version": "3.0", "spec_version": "2.3"},
            "http_version": "1.1",
            "method": request.method,
            "scheme": request.url.scheme,
            "path": request.url.path,
            "raw_path": to_header_bytes(request.url.raw_path),
            "query_string": to_header_bytes(request.url.query),
            "headers": [
                (to_header_bytes(key.lower()), to_header_bytes(value))
                for key, value in request.headers.multi_items()
            ],
            "client": ("testclient", 50000),
            "server": (
                request.url.host or "testserver",
                request.url.port or (443 if request.url.scheme == "https" else 80),
            ),
            "root_path": "",
            "state": {},
        }

        asyncio.run(test_client.app(scope, receive, send))

        response = requests.Response()
        response.status_code = response_start["status"]
        response.headers = CaseInsensitiveDict(
            {
                to_header_str(key): to_header_str(value)
                for key, value in response_start["headers"]
            }
        )
        response._content = b"".join(response_body_parts)
        response.url = str(request.url)
        response.reason = HTTPStatus(response.status_code).phrase
        response.request = requests.Request(
            method=request.method,
            url=str(request.url),
            headers=dict(request.headers),
        ).prepare()
        response.encoding = requests.utils.get_encoding_from_headers(response.headers)
        return response

    def post_through_fastapi_test_client(url: str, files: dict):
        parsed_url = urlparse(url)
        request = fastapi_test_client.build_request(
            "POST",
            parsed_url.path or url,
            files=files,
            headers=dict(connector.import_doc_ia_client.session.headers),
        )
        return dispatch_test_client_request_as_requests_response(
            test_client=fastapi_test_client,
            request=request,
        )

    connector.import_doc_ia_client.session.post = post_through_fastapi_test_client


def build_connector_for_smoke_test(
    monkeypatch: pytest.MonkeyPatch,
    mock_connector_helper: Mock,
    mock_config: Mock,
    imported_file: OpenCTIFileObject,
    triggering_entity: Mock | None = None,
    fastapi_test_client: TestClient | None = None,
) -> Connector:
    monkeypatch.setattr(
        "import_doc_ai.connector.download_import_file",
        Mock(return_value=imported_file),
    )
    monkeypatch.setattr(
        "import_doc_ai.connector.get_triggering_entity",
        Mock(return_value=triggering_entity),
    )
    monkeypatch.setattr(
        "import_doc_ai.connector.fetch_octi_attack_pattern_by_mitre_id",
        Mock(return_value=None),
    )
    connector = Connector(config=mock_config, helper=mock_connector_helper)
    if fastapi_test_client is not None:
        connect_import_document_ai_client_to_test_server(
            connector=connector, fastapi_test_client=fastapi_test_client
        )
    return connector


def extract_sent_bundle(mock_connector_helper: Mock) -> dict:
    return json.loads(
        mock_connector_helper.send_stix2_bundle.call_args.kwargs["bundle"]
    )


def extract_observable_ids_from_bundle(
    sent_bundle: dict, excluded_ids: set[str] | None = None
) -> set[str]:
    excluded_ids = excluded_ids or set()
    observable_ids = set()
    for obj in sent_bundle["objects"]:
        if obj.get("id") in excluded_ids:
            continue
        parsed_object = stix2.parse(obj, allow_custom=True)
        if isinstance(parsed_object, stix2.v21._Observable):
            observable_ids.add(obj["id"])
    return observable_ids


def test_process_message_with_dev_server_sends_filtered_bundle_with_report_attachment(
    monkeypatch: pytest.MonkeyPatch,
    fastapi_test_client: TestClient,
    mock_connector_helper: Mock,
    mock_config: Mock,
    imported_file: OpenCTIFileObject,
) -> None:
    # Given a connector wired to the dev FastAPI server and a downloaded import/global file
    connector = build_connector_for_smoke_test(
        monkeypatch=monkeypatch,
        mock_connector_helper=mock_connector_helper,
        mock_config=mock_config,
        imported_file=imported_file,
        triggering_entity=None,
        fastapi_test_client=fastapi_test_client,
    )

    # When processing a message through the full connector flow
    returned_stats = connector.process_message(data={})

    # Then the connector sends a bundle enriched with a report attachment and without ML relationships
    assert returned_stats == str(
        {
            "observables": 1,
            "entities": 6,
            "relationships": 0,
            "reports": 1,
            "total_sent": 8,
        }
    )
    mock_connector_helper.send_stix2_bundle.assert_called_once()
    sent_bundle = extract_sent_bundle(mock_connector_helper)
    sent_objects = sent_bundle["objects"]
    sent_report = next(obj for obj in sent_objects if obj["type"] == "report")
    sent_relationships = [obj for obj in sent_objects if obj["type"] == "relationship"]

    assert sent_relationships == []
    assert sent_report["name"] == "import-document-ai-smoke-test.pdf"
    assert sent_report["x_opencti_files"][0]["name"] == "smoke-test.pdf"
    assert sent_report["x_opencti_files"][0]["no_trigger_import"] is True
    assert mock_connector_helper.send_stix2_bundle.call_args.kwargs["file_name"] == (
        "import-document-ai-smoke-test.json"
    )
    assert mock_connector_helper.send_stix2_bundle.call_args.kwargs["entity_id"] is None
    assert (
        mock_connector_helper.send_stix2_bundle.call_args.kwargs["bypass_validation"]
        is False
    )


def test_process_message_with_invalid_certificate_raises_http_error(
    monkeypatch: pytest.MonkeyPatch,
    fastapi_test_client: TestClient,
    mock_connector_helper: Mock,
    mock_config: Mock,
    imported_file: OpenCTIFileObject,
) -> None:
    # Given a connector wired to the dev FastAPI server with an invalid certificate header
    mock_config.licence_key_base64 = "not-a-valid-certificate"
    connector = build_connector_for_smoke_test(
        monkeypatch=monkeypatch,
        mock_connector_helper=mock_connector_helper,
        mock_config=mock_config,
        imported_file=imported_file,
        triggering_entity=None,
        fastapi_test_client=fastapi_test_client,
    )

    # When processing a message through the full connector flow
    # Then the dev server rejects the certificate and the connector propagates the HTTP error
    with pytest.raises(requests.HTTPError):
        connector.process_message(data={})

    mock_connector_helper.send_stix2_bundle.assert_not_called()
    mock_connector_helper.connector_logger.error.assert_called()


def test_process_message_with_container_triggering_entity_updates_object_refs(
    monkeypatch: pytest.MonkeyPatch,
    fastapi_test_client: TestClient,
    mock_connector_helper: Mock,
    mock_config: Mock,
    imported_file: OpenCTIFileObject,
) -> None:
    # Given a contextual import triggered from a report that already references one object
    existing_identity = stix2.Identity(
        id=pycti.Identity.generate_id(
            "Existing Container Object",
            "organization",
        ),
        name="Existing Container Object",
        identity_class="organization",
    )
    report_published = "2026-01-01T00:00:00Z"
    triggering_entity_stix = stix2.Report(
        id=pycti.Report.generate_id("Triggering Report", report_published),
        name="Triggering Report",
        description="Contextual smoke test report",
        published=report_published,
        report_types=["threat-report"],
        object_refs=[existing_identity["id"]],
        allow_custom=True,
    )
    triggering_entity = build_triggering_entity_mock(
        triggering_entity_stix=triggering_entity_stix
    )
    connector = build_connector_for_smoke_test(
        monkeypatch=monkeypatch,
        mock_connector_helper=mock_connector_helper,
        mock_config=mock_config,
        imported_file=imported_file,
        triggering_entity=triggering_entity,
        fastapi_test_client=fastapi_test_client,
    )

    # When processing a message through the full connector flow
    connector.process_message(data={})

    # Then the triggering report keeps its existing refs and is extended with imported object ids
    sent_bundle = extract_sent_bundle(mock_connector_helper)
    sent_objects = sent_bundle["objects"]
    sent_triggering_report = next(
        obj for obj in sent_objects if obj["id"] == triggering_entity.id
    )
    imported_object_ids = {
        obj["id"] for obj in sent_objects if obj.get("id") != triggering_entity.id
    }

    assert existing_identity["id"] in sent_triggering_report["object_refs"]
    assert imported_object_ids.issubset(set(sent_triggering_report["object_refs"]))
    assert mock_connector_helper.send_stix2_bundle.call_args.kwargs["entity_id"] == (
        triggering_entity.id
    )


def test_process_message_with_observed_data_triggering_entity_updates_only_observable_refs(
    monkeypatch: pytest.MonkeyPatch,
    fastapi_test_client: TestClient,
    mock_connector_helper: Mock,
    mock_config: Mock,
    imported_file: OpenCTIFileObject,
) -> None:
    # Given a contextual import triggered from observed-data that already references one observable
    existing_observable = stix2.MACAddress(value="00:11:22:33:44:55")
    observed_object_ids = [existing_observable["id"]]
    triggering_entity_stix = stix2.ObservedData(
        id=pycti.ObservedData.generate_id(observed_object_ids),
        first_observed="2026-01-01T00:00:00Z",
        last_observed="2026-01-01T00:00:00Z",
        number_observed=1,
        object_refs=observed_object_ids,
        allow_custom=True,
    )
    triggering_entity = build_triggering_entity_mock(
        triggering_entity_stix=triggering_entity_stix
    )
    connector = build_connector_for_smoke_test(
        monkeypatch=monkeypatch,
        mock_connector_helper=mock_connector_helper,
        mock_config=mock_config,
        imported_file=imported_file,
        triggering_entity=triggering_entity,
        fastapi_test_client=fastapi_test_client,
    )

    # When processing a message through the full connector flow
    connector.process_message(data={})

    # Then only observables are appended to the observed-data object_refs
    sent_bundle = extract_sent_bundle(mock_connector_helper)
    sent_objects = sent_bundle["objects"]
    sent_triggering_observed_data = next(
        obj for obj in sent_objects if obj["id"] == triggering_entity.id
    )
    observable_ids = extract_observable_ids_from_bundle(
        sent_bundle=sent_bundle,
        excluded_ids={triggering_entity.id},
    )

    assert observable_ids
    assert set(sent_triggering_observed_data["object_refs"]) == (
        observable_ids | {existing_observable["id"]}
    )
    assert mock_connector_helper.send_stix2_bundle.call_args.kwargs["entity_id"] == (
        triggering_entity.id
    )


def test_process_message_with_non_container_triggering_entity_creates_related_to_relationships(
    monkeypatch: pytest.MonkeyPatch,
    fastapi_test_client: TestClient,
    mock_connector_helper: Mock,
    mock_config: Mock,
    imported_file: OpenCTIFileObject,
) -> None:
    # Given a contextual import triggered from a non-container entity
    triggering_entity_stix = stix2.Identity(
        id=pycti.Identity.generate_id("Triggering Identity", "organization"),
        name="Triggering Identity",
        identity_class="organization",
    )
    triggering_entity = build_triggering_entity_mock(
        triggering_entity_stix=triggering_entity_stix
    )
    connector = build_connector_for_smoke_test(
        monkeypatch=monkeypatch,
        mock_connector_helper=mock_connector_helper,
        mock_config=mock_config,
        imported_file=imported_file,
        triggering_entity=triggering_entity,
        fastapi_test_client=fastapi_test_client,
    )

    # When processing a message through the full connector flow
    connector.process_message(data={})

    # Then the connector creates one deterministic related-to relationship per imported object
    sent_bundle = extract_sent_bundle(mock_connector_helper)
    sent_objects = sent_bundle["objects"]
    related_to_relationships = [
        obj
        for obj in sent_objects
        if obj["type"] == "relationship" and obj["relationship_type"] == "related-to"
    ]
    imported_non_relationship_ids = {
        obj["id"] for obj in sent_objects if obj["type"] != "relationship"
    }

    assert len(related_to_relationships) == len(imported_non_relationship_ids)
    assert {obj["source_ref"] for obj in related_to_relationships} == (
        imported_non_relationship_ids
    )
    assert {obj["target_ref"] for obj in related_to_relationships} == {
        triggering_entity.id
    }
    assert mock_connector_helper.send_stix2_bundle.call_args.kwargs["entity_id"] == (
        triggering_entity.id
    )


def test_process_message_with_create_indicator_enabled_marks_observables_for_indicator_creation(
    monkeypatch: pytest.MonkeyPatch,
    fastapi_test_client: TestClient,
    mock_connector_helper: Mock,
    mock_config: Mock,
    imported_file: OpenCTIFileObject,
) -> None:
    # Given a connector configured to delegate indicator creation to the platform
    mock_config.create_indicator = True
    connector = build_connector_for_smoke_test(
        monkeypatch=monkeypatch,
        mock_connector_helper=mock_connector_helper,
        mock_config=mock_config,
        imported_file=imported_file,
        triggering_entity=None,
        fastapi_test_client=fastapi_test_client,
    )

    # When processing a message through the full connector flow
    connector.process_message(data={})

    # Then every observable sent in the bundle is marked for indicator creation
    sent_bundle = extract_sent_bundle(mock_connector_helper)
    observable_ids = extract_observable_ids_from_bundle(sent_bundle=sent_bundle)
    observable_objects = [
        obj for obj in sent_bundle["objects"] if obj.get("id") in observable_ids
    ]

    assert observable_objects
    assert all(
        obj.get("x_opencti_create_indicator") is True for obj in observable_objects
    )


def test_process_message_returns_early_when_connector_is_only_contextual_and_entity_is_missing(
    monkeypatch: pytest.MonkeyPatch,
    mock_connector_helper: Mock,
    mock_config: Mock,
    imported_file: OpenCTIFileObject,
) -> None:
    # Given a connector configured as only contextual with no triggering entity available
    mock_connector_helper.get_only_contextual.return_value = True
    connector = build_connector_for_smoke_test(
        monkeypatch=monkeypatch,
        mock_connector_helper=mock_connector_helper,
        mock_config=mock_config,
        imported_file=imported_file,
        triggering_entity=None,
    )
    connector.import_doc_ia_client.get_bundle = Mock()

    # When processing a message through the full connector flow
    returned_message = connector.process_message(data={})

    # Then the connector exits before calling the AI service or sending any STIX bundle
    assert (
        returned_message
        == "Connector is only contextual and entity is not defined. Nothing was imported"
    )
    connector.import_doc_ia_client.get_bundle.assert_not_called()
    mock_connector_helper.send_stix2_bundle.assert_not_called()

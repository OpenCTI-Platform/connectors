"""Unit tests for `OpenCTIStream` (the SSE forwarding connector).

The connector is a thin passthrough: each test exercises one branch of `_on_event`
or one of the small URL/token resolution helpers against an `OpenCTIStream` instance
whose helper / config attributes have been replaced by `MagicMock`s. This avoids any
network or pycti machinery while still validating the actual code paths users care
about.
"""

import base64
import json
from typing import Any
from unittest.mock import MagicMock

import pytest
from opencti_stream.connector import OpenCTIStream
from pycti import STIX_EXT_OCTI
from pydantic import HttpUrl, SecretStr
from requests import HTTPError


@pytest.fixture
def connector():
    """Build an `OpenCTIStream` with a fully mocked helper, bypassing __init__ side effects."""
    instance = OpenCTIStream.__new__(OpenCTIStream)
    instance.config = MagicMock()
    instance.config.connector.live_stream_opencti_url = None
    instance.config.connector.live_stream_opencti_token = None
    # Mirror the real default: no fallback applicant unless explicitly configured.
    instance.config.stream.default_applicant_id = None
    instance.config.stream.include_files = False
    instance.helper = MagicMock()
    instance.helper.opencti_url = "http://source-opencti:8080"
    instance.helper.opencti_token = "connector-token"
    instance.helper.connector_logger = MagicMock()
    instance.helper.stix2_create_bundle.side_effect = lambda objects: (
        f'{{"type":"bundle","objects":[{json.dumps(objects[0]) if objects else ""}]}}'
    )
    instance._stream_thread = None
    return instance


def _make_msg(event: str, data: Any, msg_id: str = "1-0"):
    """Build a stub matching pycti's SSE message shape (event/id/data)."""
    msg = MagicMock()
    msg.event = event
    msg.id = msg_id
    msg.data = json.dumps(data) if not isinstance(data, str) else data
    return msg


def test_on_event_forwards_create(connector):
    stix_object = {
        "id": "report--00000000-0000-0000-0000-000000000001",
        "type": "report",
    }
    payload = {
        "data": stix_object,
        "origin": {"user_id": "user-uuid-1"},
    }

    connector._on_event(_make_msg("create", payload))

    assert connector.helper.applicant_id == "user-uuid-1"
    connector.helper.stix2_create_bundle.assert_called_once_with([stix_object])
    args, kwargs = connector.helper.send_stix2_bundle.call_args
    assert kwargs == {"no_split": True, "cleanup_inconsistent_bundle": True}


def test_on_event_forwards_update(connector):
    stix_object = {
        "id": "indicator--00000000-0000-0000-0000-000000000002",
        "type": "indicator",
    }
    payload = {"data": stix_object, "origin": {"user_id": "user-uuid-2"}}

    connector._on_event(_make_msg("update", payload))

    connector.helper.send_stix2_bundle.assert_called_once()


def test_on_event_skips_delete(connector):
    """`delete` events are not forwarded (upsert-only relay)."""
    payload = {
        "data": {
            "id": "report--00000000-0000-0000-0000-000000000003",
            "type": "report",
        },
        "origin": {"user_id": "user-uuid-3"},
    }

    connector._on_event(_make_msg("delete", payload))

    connector.helper.stix2_create_bundle.assert_not_called()
    connector.helper.send_stix2_bundle.assert_not_called()


def test_on_event_skips_unknown_event_type(connector):
    payload = {
        "data": {
            "id": "report--00000000-0000-0000-0000-000000000004",
            "type": "report",
        },
    }

    connector._on_event(_make_msg("heartbeat", payload))

    connector.helper.send_stix2_bundle.assert_not_called()


def test_on_event_skips_malformed_json(connector):
    msg = MagicMock()
    msg.event = "create"
    msg.id = "9-0"
    msg.data = "{this is not valid json"

    connector._on_event(msg)

    connector.helper.connector_logger.warning.assert_called_once()
    connector.helper.send_stix2_bundle.assert_not_called()


def test_on_event_skips_payload_without_data(connector):
    payload = {"origin": {"user_id": "user-uuid-5"}}

    connector._on_event(_make_msg("create", payload))

    connector.helper.send_stix2_bundle.assert_not_called()


def test_on_event_skips_payload_with_non_dict_data(connector):
    payload = {"data": "not-a-dict", "origin": {"user_id": "user-uuid-6"}}

    connector._on_event(_make_msg("create", payload))

    connector.helper.send_stix2_bundle.assert_not_called()


def test_on_event_resets_applicant_when_origin_missing(connector):
    """When `origin.user_id` is missing, `applicant_id` MUST be reset (not inherited from a previous event)."""
    connector.helper.applicant_id = "previous-user-leaks"

    payload_without_origin = {
        "data": {
            "id": "report--00000000-0000-0000-0000-000000000007",
            "type": "report",
        },
    }
    connector._on_event(_make_msg("create", payload_without_origin))

    assert connector.helper.applicant_id is None
    connector.helper.send_stix2_bundle.assert_called_once()


def test_on_event_resets_applicant_when_origin_user_id_missing(connector):
    """An event with an `origin` block but no `user_id` MUST also reset `applicant_id`."""
    connector.helper.applicant_id = "previous-user-leaks"

    payload = {
        "data": {
            "id": "report--00000000-0000-0000-0000-000000000008",
            "type": "report",
        },
        "origin": {"socket": "query", "ip": "::1"},
    }
    connector._on_event(_make_msg("create", payload))

    assert connector.helper.applicant_id is None


def test_on_event_falls_back_to_default_applicant_when_origin_user_id_missing(
    connector,
):
    """When `origin.user_id` is missing but `default_applicant_id` is configured,
    `applicant_id` MUST fall back to that default instead of being reset to None."""
    connector.config.stream.default_applicant_id = "default-user-uuid"

    payload = {
        "data": {
            "id": "report--00000000-0000-0000-0000-000000000009",
            "type": "report",
        },
        "origin": {"socket": "query", "ip": "::1"},
    }
    connector._on_event(_make_msg("create", payload))

    assert connector.helper.applicant_id == "default-user-uuid"
    connector.helper.send_stix2_bundle.assert_called_once()


def test_on_event_prefers_origin_user_id_over_default_applicant(connector):
    """A present `origin.user_id` MUST take precedence over the configured default."""
    connector.config.stream.default_applicant_id = "default-user-uuid"

    stix_object = {
        "id": "report--00000000-0000-0000-0000-000000000010",
        "type": "report",
    }
    payload = {"data": stix_object, "origin": {"user_id": "event-user-uuid"}}
    connector._on_event(_make_msg("create", payload))

    assert connector.helper.applicant_id == "event-user-uuid"


def test_live_stream_url_falls_back_to_helper_when_not_configured(connector):
    connector.config.connector.live_stream_opencti_url = None
    connector.helper.opencti_url = "http://target-opencti:8080/"

    assert connector._live_stream_url() == "http://target-opencti:8080"


def test_live_stream_url_uses_configured_value_and_strips_trailing_slash(connector):
    connector.config.connector.live_stream_opencti_url = HttpUrl(
        "http://source-opencti:8080"
    )
    connector.helper.opencti_url = "http://target-opencti:8080/"

    # Pydantic's HttpUrl normalizes to add a trailing slash; the resolver must strip it.
    assert connector._live_stream_url() == "http://source-opencti:8080"


def test_live_stream_token_falls_back_to_helper_when_not_configured(connector):
    connector.config.connector.live_stream_opencti_token = None
    connector.helper.opencti_token = "target-token"

    assert connector._live_stream_token() == "target-token"


def test_live_stream_token_uses_configured_value(connector):
    connector.config.connector.live_stream_opencti_token = SecretStr("source-token")
    connector.helper.opencti_token = "target-token"

    assert connector._live_stream_token() == "source-token"


FILE_URI = "/storage/get/import/Report/report-internal-id/report.pdf"
FILE_CONTENT = b"%PDF-1.4 fake content"


def _report_with_files(*files: dict) -> dict:
    """Build a report as sent by the live stream, with files in the OpenCTI extension."""
    return {
        "id": "report--00000000-0000-0000-0000-000000000020",
        "type": "report",
        "extensions": {
            STIX_EXT_OCTI: {
                "extension_type": "property-extension",
                "files": list(files),
            }
        },
    }


def _stream_file(uri: str = FILE_URI) -> dict:
    return {
        "name": "report.pdf",
        "uri": uri,
        "version": "2026-11-17T10:00:00.000Z",
        "mime_type": "application/pdf",
        "object_marking_refs": [],
    }


def _sent_object(connector) -> dict:
    """Return the single STIX object of the bundle passed to `send_stix2_bundle`."""
    bundle = connector.helper.send_stix2_bundle.call_args.args[0]
    return json.loads(bundle)["objects"][0]


def _sent_files(connector) -> list[dict]:
    return _sent_object(connector)["extensions"][STIX_EXT_OCTI]["files"]


@pytest.fixture
def connector_with_files(connector):
    """Connector with file inclusion enabled and a successful file download."""
    connector.config.stream.include_files = True
    connector.helper.api.session.get.return_value.content = FILE_CONTENT
    return connector


def test_on_event_does_not_download_files_when_disabled(connector):
    payload = {"data": _report_with_files(_stream_file())}

    connector._on_event(_make_msg("create", payload))

    connector.helper.api.session.get.assert_not_called()
    assert "data" not in _sent_files(connector)[0]


def test_on_event_includes_file_content_when_enabled(connector_with_files):
    connector = connector_with_files
    payload = {"data": _report_with_files(_stream_file())}

    connector._on_event(_make_msg("update", payload))

    sent_file = _sent_files(connector)[0]
    assert base64.b64decode(sent_file["data"]) == FILE_CONTENT
    # The other file attributes are forwarded unchanged.
    assert sent_file["name"] == "report.pdf"
    assert sent_file["mime_type"] == "application/pdf"
    args, kwargs = connector.helper.api.session.get.call_args
    assert args == ("http://source-opencti:8080" + FILE_URI,)
    assert kwargs["headers"] == {"Authorization": "Bearer connector-token"}


def test_on_event_downloads_files_from_remote_source_with_source_token(
    connector_with_files,
):
    """In A -> B replication, files live on the source OpenCTI, not on the one the
    connector is registered with."""
    connector = connector_with_files
    connector.config.connector.live_stream_opencti_url = HttpUrl(
        "http://remote-source:8080"
    )
    connector.config.connector.live_stream_opencti_token = SecretStr("source-token")
    connector.helper.opencti_url = "http://target-opencti:8080"
    payload = {"data": _report_with_files(_stream_file())}

    connector._on_event(_make_msg("create", payload))

    args, kwargs = connector.helper.api.session.get.call_args
    assert args == ("http://remote-source:8080" + FILE_URI,)
    assert kwargs["headers"] == {"Authorization": "Bearer source-token"}
    assert base64.b64decode(_sent_files(connector)[0]["data"]) == FILE_CONTENT


def test_on_event_keeps_existing_file_data(connector_with_files):
    connector = connector_with_files
    existing = {"name": "inline.txt", "uri": "unknown", "data": "aW5saW5l"}
    payload = {"data": _report_with_files(existing)}

    connector._on_event(_make_msg("create", payload))

    connector.helper.api.session.get.assert_not_called()
    assert _sent_files(connector)[0]["data"] == "aW5saW5l"


@pytest.mark.parametrize(
    "file",
    [
        pytest.param({"name": "no-uri.pdf"}, id="missing_uri"),
        pytest.param({"name": "unknown.pdf", "uri": "unknown"}, id="unknown_uri"),
        pytest.param(
            {"name": "remote.pdf", "uri": "http://evil.example/file"},
            id="absolute_uri",
        ),
    ],
)
def test_on_event_skips_files_without_storage_uri(connector_with_files, file):
    connector = connector_with_files
    payload = {"data": _report_with_files(file)}

    connector._on_event(_make_msg("create", payload))

    connector.helper.api.session.get.assert_not_called()
    connector.helper.connector_logger.warning.assert_called_once()
    assert "data" not in _sent_files(connector)[0]
    connector.helper.send_stix2_bundle.assert_called_once()


@pytest.mark.parametrize(
    "failure",
    [
        pytest.param(ConnectionError("connection refused"), id="network_error"),
        pytest.param(HTTPError("404 Client Error"), id="http_error"),
    ],
)
def test_on_event_forwards_object_without_data_when_download_fails(
    connector_with_files, failure
):
    """A failing download must neither block the event nor emit `data: None`,
    which the target instance cannot decode."""
    connector = connector_with_files
    if isinstance(failure, HTTPError):
        connector.helper.api.session.get.return_value.raise_for_status.side_effect = (
            failure
        )
    else:
        connector.helper.api.session.get.side_effect = failure
    payload = {"data": _report_with_files(_stream_file(), _stream_file())}

    connector._on_event(_make_msg("create", payload))

    assert connector.helper.connector_logger.warning.call_count == 2
    assert all("data" not in file for file in _sent_files(connector))
    connector.helper.send_stix2_bundle.assert_called_once()


@pytest.mark.parametrize(
    "stix_object",
    [
        pytest.param({"id": "report--1", "type": "report"}, id="no_extension"),
        pytest.param(
            {"id": "report--1", "type": "report", "extensions": {STIX_EXT_OCTI: {}}},
            id="no_files",
        ),
        pytest.param(
            {
                "id": "report--1",
                "type": "report",
                "extensions": {STIX_EXT_OCTI: {"files": "not-a-list"}},
            },
            id="files_not_a_list",
        ),
        pytest.param(_report_with_files("not-a-dict"), id="file_not_a_dict"),
    ],
)
def test_on_event_ignores_objects_without_downloadable_files(
    connector_with_files, stix_object
):
    connector = connector_with_files

    connector._on_event(_make_msg("create", {"data": stix_object}))

    connector.helper.api.session.get.assert_not_called()
    connector.helper.send_stix2_bundle.assert_called_once()

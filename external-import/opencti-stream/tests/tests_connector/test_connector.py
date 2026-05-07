"""Unit tests for `OpenCTIStream._on_event` (the SSE forwarding callback).

The connector itself is a thin passthrough: each test exercises one branch of
`_on_event` against a stub message and an `OpenCTIStream` instance whose helper
attributes have been replaced by `MagicMock`s. This avoids any network or pycti
machinery while still validating the actual code path users care about.
"""

import json
from typing import Any
from unittest.mock import MagicMock

import pytest
from opencti_stream.connector import OpenCTIStream


@pytest.fixture
def connector():
    """Build an `OpenCTIStream` with a fully mocked helper, bypassing __init__ side effects."""
    instance = OpenCTIStream.__new__(OpenCTIStream)
    instance.config = MagicMock()
    instance.helper = MagicMock()
    instance.helper.connector_logger = MagicMock()
    instance.helper.stix2_create_bundle.side_effect = (
        lambda objects: f'{{"type":"bundle","objects":[{json.dumps(objects[0]) if objects else ""}]}}'
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

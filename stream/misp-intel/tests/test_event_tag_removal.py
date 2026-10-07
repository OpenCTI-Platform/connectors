"""
Tests for the removal of event tags when markings or report types are
removed from a container (computed from the stream event reverse_patch).
"""

import json
import threading
from unittest.mock import MagicMock, patch

import pytest
from misp_intel_connector.api_handler import MispApiHandler, _tag_names
from misp_intel_connector.connector import MispIntelConnector
from misp_intel_connector.event_tags import (
    get_previous_list_values,
    get_removed_container_values,
)
from pymisp import MISPEvent

TLP_RED_ID = "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed"
TLP_GREEN_ID = "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da"
CUSTOM_ID = "marking-definition--11111111-2222-3333-4444-555555555555"

MARKINGS = {
    TLP_RED_ID: {"definition_type": "TLP", "definition": "TLP:RED"},
    TLP_GREEN_ID: {"definition_type": "TLP", "definition": "TLP:GREEN"},
    CUSTOM_ID: {"definition_type": "internal-dist", "definition": "INTERNAL:X"},
}


def _report(object_marking_refs=None, report_types=None):
    return {
        "type": "report",
        "id": "report--container-uuid",
        "object_marking_refs": object_marking_refs or [],
        "report_types": report_types or [],
        "extensions": {
            "extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba": {
                "id": "container-uuid",
                "type": "Report",
            }
        },
    }


# ──────────────────────────────────────────────────────
# Removed values computed from the reverse patch
# ──────────────────────────────────────────────────────


def test_previous_value_from_index_replace():
    data = _report(object_marking_refs=[TLP_GREEN_ID])
    reverse_patch = [
        {"op": "replace", "path": "/object_marking_refs/0", "value": TLP_RED_ID}
    ]

    previous = get_previous_list_values(data, reverse_patch, "object_marking_refs")

    assert previous == [TLP_RED_ID]


def test_removed_marking_on_marking_change():
    data = _report(object_marking_refs=[TLP_GREEN_ID])
    context = {
        "reverse_patch": [
            {"op": "replace", "path": "/object_marking_refs/0", "value": TLP_RED_ID}
        ]
    }

    removed = get_removed_container_values(data, context)

    assert removed == {"object_marking_refs": [TLP_RED_ID]}


def test_removed_report_type():
    data = _report(report_types=["threat-report"])
    context = {
        "reverse_patch": [
            {"op": "add", "path": "/report_types/1", "value": "malware"},
        ]
    }

    removed = get_removed_container_values(data, context)

    assert removed == {"report_types": ["malware"]}


def test_whole_list_removed_from_container():
    data = _report()
    context = {
        "reverse_patch": [
            {"op": "add", "path": "/object_marking_refs", "value": [TLP_RED_ID]},
        ]
    }

    removed = get_removed_container_values(data, context)

    assert removed == {"object_marking_refs": [TLP_RED_ID]}


def test_added_marking_removes_nothing():
    data = _report(object_marking_refs=[TLP_RED_ID])
    context = {"reverse_patch": [{"op": "remove", "path": "/object_marking_refs"}]}

    assert get_removed_container_values(data, context) == {}


def test_unrelated_changes_and_missing_context_remove_nothing():
    data = _report(object_marking_refs=[TLP_RED_ID])
    context = {"reverse_patch": [{"op": "replace", "path": "/name", "value": "Old"}]}

    assert get_removed_container_values(data, context) == {}
    assert get_removed_container_values(data, None) == {}


# ──────────────────────────────────────────────────────
# Connector: removed values -> MISP tags, queue handling
# ──────────────────────────────────────────────────────


@pytest.fixture
def connector():
    config = MagicMock()
    config.misp.url = "https://misp.example.com"
    config.misp.detect_round_trip = False
    config.misp.get_marking_types_allowlist.return_value = {"TLP", "PAP"}
    with patch(
        "misp_intel_connector.connector.OpenCTIConnectorHelper"
    ) as mock_helper_cls, patch(
        "misp_intel_connector.connector.MispApiHandler"
    ) as mock_api_cls:
        mock_helper = MagicMock()
        mock_helper.get_attribute_in_extension.return_value = "container-uuid"
        mock_helper.api.marking_definition.read.side_effect = (
            lambda id=None: MARKINGS.get(id)
        )
        mock_helper_cls.return_value = mock_helper
        mock_api = MagicMock()
        mock_api.test_connection.return_value = True
        mock_api_cls.return_value = mock_api
        conn = MispIntelConnector(config)
    return conn


def test_resolve_removed_event_tags(connector):
    removed = {
        "object_marking_refs": [TLP_RED_ID, CUSTOM_ID, "marking-definition--gone"],
        "report_types": ["malware"],
    }

    tags = connector._resolve_removed_event_tags(removed)

    assert tags == ["report-type:malware", "tlp:red"]


def test_update_message_queues_removed_values(connector):
    msg = MagicMock()
    msg.event = "update"
    msg.data = json.dumps(
        {
            "data": _report(object_marking_refs=[TLP_GREEN_ID]),
            "context": {
                "reverse_patch": [
                    {
                        "op": "replace",
                        "path": "/object_marking_refs/0",
                        "value": TLP_RED_ID,
                    }
                ]
            },
        }
    )

    connector._process_message(msg)

    item = connector.work_queue.get_nowait()
    assert item[0] == "update"
    assert item[3] == {"object_marking_refs": [TLP_RED_ID]}


def test_worker_passes_tags_to_remove(connector):
    data = _report(object_marking_refs=[TLP_GREEN_ID])
    connector.api.get_event_by_uuid.return_value = {"uuid": "container-uuid"}
    connector._update_misp_event = MagicMock(return_value=True)

    processed = threading.Event()
    original_task_done = connector.work_queue.task_done

    def task_done_and_stop():
        original_task_done()
        connector.stop_worker.set()
        processed.set()

    connector.work_queue.task_done = task_done_and_stop
    connector.work_queue.put_nowait(
        ("update", data, "container-uuid", {"object_marking_refs": [TLP_RED_ID]})
    )
    connector._worker_process_queue()

    assert processed.is_set()
    connector._update_misp_event.assert_called_once_with(
        data, "container-uuid", ["tlp:red"]
    )


# ──────────────────────────────────────────────────────
# API handler: tag removal on update
# ──────────────────────────────────────────────────────


@pytest.fixture
def api_handler():
    config = MagicMock()
    config.misp.owner_org = None
    config.misp.distribution_level = 1
    config.misp.publish_on_update = False
    helper = MagicMock()
    with patch("misp_intel_connector.api_handler.PyMISP") as mock_pymisp_cls:
        mock_pymisp_cls.return_value = MagicMock()
        handler = MispApiHandler(helper, config)
    handler.misp.update_event.return_value = {"Event": {"uuid": "container-uuid"}}
    return handler


def _existing_event(*tag_names):
    event = MISPEvent()
    event.uuid = "container-uuid"
    event.info = "Test report"
    for tag_name in tag_names:
        event.add_tag(tag_name)
    return event


def test_update_event_removes_only_given_tags(api_handler):
    api_handler.misp.get_event.return_value = _existing_event(
        "tlp:red", "report-type:malware", "analyst:manual"
    )
    event_data = {"Tag": [{"name": "tlp:green"}]}

    api_handler.update_event(
        "container-uuid",
        event_data,
        tags_to_remove=["tlp:red", "report-type:malware"],
    )

    untagged = {call.args[1] for call in api_handler.misp.untag.call_args_list}
    assert untagged == {"tlp:red", "report-type:malware"}
    sent_tags = _tag_names(api_handler.misp.update_event.call_args[0][0].tags)
    assert set(sent_tags) == {"analyst:manual", "tlp:green"}


def test_update_event_keeps_tag_still_in_payload(api_handler):
    api_handler.misp.get_event.return_value = _existing_event("tlp:red")
    event_data = {"Tag": [{"name": "tlp:red"}]}

    api_handler.update_event("container-uuid", event_data, tags_to_remove=["tlp:red"])

    api_handler.misp.untag.assert_not_called()
    sent_tags = _tag_names(api_handler.misp.update_event.call_args[0][0].tags)
    assert sent_tags == ["tlp:red"]


def test_update_event_without_tags_to_remove_keeps_existing_tags(api_handler):
    api_handler.misp.get_event.return_value = _existing_event("tlp:red")

    api_handler.update_event("container-uuid", {"Tag": [{"name": "tlp:green"}]})

    api_handler.misp.untag.assert_not_called()
    sent_tags = _tag_names(api_handler.misp.update_event.call_args[0][0].tags)
    assert set(sent_tags) == {"tlp:red", "tlp:green"}

import json
from types import SimpleNamespace

import pytest
from connector import CybleVisionWritebackConnector
from connector.mapping import (
    build_update,
    changed_fields,
    vision_alert_id,
    vision_status,
)
from cyble_client import CybleVisionClient

ALERT_ID = "b2c3d4e5-f6a7-8901-bcde-f23456789012"
IMPORT_USER_ID = "6a3a3c2e-1111-4a5b-9c0d-000000000001"
ANALYST_USER_ID = "6a3a3c2e-2222-4a5b-9c0d-000000000002"
OCTI_EXT = "/extensions/extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba"

# context.patch values captured from a live OpenCTI 7 stream.
SEVERITY_PATCH = [
    {"op": "replace", "path": "/severity", "value": "high"},
    {"op": "replace", "path": "/modified", "value": "2026-11-09T09:45:13.911Z"},
    {
        "op": "replace",
        "path": f"{OCTI_EXT}/updated_at",
        "value": "2026-11-09T09:45:13.911Z",
    },
]
STATUS_PATCH = [
    {"op": "replace", "path": "/modified", "value": "2026-11-09T09:45:15.991Z"},
    {"op": "replace", "path": f"{OCTI_EXT}/workflow_status_name", "value": "CLOSED"},
    {
        "op": "replace",
        "path": f"{OCTI_EXT}/workflow_id",
        "value": "3552077e-9c1b-4971-a261-63c6be788ac0",
    },
]
DESCRIPTION_PATCH = [
    {"op": "replace", "path": "/modified", "value": "2026-11-09T09:45:18.076Z"},
    {"op": "add", "path": "/description", "value": "edited"},
]


class _Logger:
    def info(self, *args, **kwargs):
        return None

    def debug(self, *args, **kwargs):
        return None

    def warning(self, *args, **kwargs):
        return None

    def error(self, *args, **kwargs):
        return None


def _incident(**overrides):
    entity = {
        "id": "incident--1",
        "type": "incident",
        "severity": "low",
        "labels": ["cyble", "cyble:github"],
        "external_references": [
            {"source_name": "Cyble Vision", "external_id": ALERT_ID},
        ],
        "status": {"template": {"name": "Closed"}},
    }
    entity.update(overrides)
    return entity


def _connector(sent, ignored_user_ids=(IMPORT_USER_ID,)):
    connector = CybleVisionWritebackConnector.__new__(CybleVisionWritebackConnector)
    connector.helper = SimpleNamespace(connector_logger=_Logger())
    connector.ignored_user_ids = set(ignored_user_ids)
    connector.client = SimpleNamespace(update_alerts=sent.extend)
    connector._refresh_incident = lambda entity: entity
    return connector


def _message(event, entity, patch=SEVERITY_PATCH, origin=None):
    payload = {
        "data": entity,
        "origin": origin or {"user_id": ANALYST_USER_ID},
        "context": {"patch": patch},
    }
    return SimpleNamespace(event=event, data=json.dumps(payload))


def test_alert_uuid_comes_from_external_reference():
    entity = {
        "external_references": [
            {"source_name": "Other", "external_id": "nope"},
            {
                "source_name": "Cyble Vision",
                "url": f'https://cyble.ai/alerts/github?id=["{ALERT_ID}"]',
                "external_id": ALERT_ID,
            },
        ]
    }
    assert vision_alert_id(entity) == ALERT_ID


def test_short_workflow_maps_to_vision_status():
    assert vision_status("New") == "UNREVIEWED"
    assert vision_status("NEW") == "UNREVIEWED"
    assert vision_status("In progress") == "UNDER_REVIEW"
    assert vision_status("IN_PROGRESS") == "UNDER_REVIEW"
    assert vision_status("Closed") == "RESOLVED"
    assert vision_status("CLOSED") == "RESOLVED"
    assert vision_status("Unknown") is None


def test_build_update_from_opencti_graphql_shape():
    entity = {
        "entity_type": "Incident",
        "severity": "medium",
        "objectLabel": [
            {"value": "cyble"},
            {"value": "cyble:bucket:NEW"},
            {"value": "cyble:hacktivism"},
        ],
        "externalReferences": [
            {
                "source_name": "Cyble Vision",
                "external_id": "64f9817a-3d6e-5a52-a6fd-af7a155af281",
            }
        ],
        "status": {"template": {"name": "IN_PROGRESS"}},
    }
    assert build_update(entity) == {
        "id": "64f9817a-3d6e-5a52-a6fd-af7a155af281",
        "service": "hacktivism",
        "user_severity": "MEDIUM",
        "status": "UNDER_REVIEW",
    }


def test_build_update_uses_alert_id_service_severity_and_status():
    assert build_update(_incident()) == {
        "id": ALERT_ID,
        "service": "github",
        "user_severity": "LOW",
        "status": "RESOLVED",
    }


def test_build_update_skips_non_cyble_incidents():
    assert build_update({"type": "incident", "severity": "high"}) is None


def test_update_alerts_sends_put_body():
    client = CybleVisionClient(
        base_url="https://bifrost.cyble.ai", api_token="test", logger=_Logger()
    )
    captured = {}

    def fake_put(path, json=None):
        captured["path"] = path
        captured["json"] = json
        return {"success": True}

    client._put = fake_put
    client.update_alerts(
        [
            {
                "id": ALERT_ID,
                "service": "github",
                "status": "INFORMATIONAL",
                "user_severity": "LOW",
            }
        ]
    )
    assert captured["path"].endswith("/y/alerts")
    assert captured["json"] == {
        "alerts": [
            {
                "id": ALERT_ID,
                "service": "github",
                "status": "INFORMATIONAL",
                "user_severity": "LOW",
            }
        ]
    }


def test_update_alerts_splits_large_batches():
    client = CybleVisionClient(
        base_url="https://bifrost.cyble.ai", api_token="test", logger=_Logger()
    )
    sizes = []
    client._put = lambda path, json=None: sizes.append(len(json["alerts"])) or {}

    client.update_alerts(
        [
            {"id": f"id-{n}", "service": "github", "status": "RESOLVED"}
            for n in range(150)
        ]
    )
    assert sizes == [100, 50]


def test_changed_fields_reads_opencti_patch_paths():
    assert changed_fields(SEVERITY_PATCH) == {"user_severity"}
    assert changed_fields(STATUS_PATCH) == {"status"}
    assert changed_fields(DESCRIPTION_PATCH) == set()
    assert changed_fields(None) == set()


def test_severity_change_sends_only_severity():
    sent = []
    _connector(sent).process_message(_message("update", _incident()))
    assert sent == [{"id": ALERT_ID, "service": "github", "user_severity": "LOW"}]


def test_status_change_sends_only_status():
    sent = []
    _connector(sent).process_message(
        _message("update", _incident(), patch=STATUS_PATCH)
    )
    assert sent == [{"id": ALERT_ID, "service": "github", "status": "RESOLVED"}]


def test_both_changes_in_one_event_send_both_fields():
    sent = []
    _connector(sent).process_message(
        _message("update", _incident(), patch=SEVERITY_PATCH + STATUS_PATCH)
    )
    assert sent == [
        {
            "id": ALERT_ID,
            "service": "github",
            "user_severity": "LOW",
            "status": "RESOLVED",
        }
    ]


def test_unrelated_edits_are_not_written_back():
    sent = []
    _connector(sent).process_message(
        _message("update", _incident(), patch=DESCRIPTION_PATCH)
    )
    assert sent == []


@pytest.mark.parametrize("event", ["create", "delete"])
def test_non_update_events_are_ignored(event):
    sent = []
    _connector(sent).process_message(_message(event, _incident()))
    assert sent == []


def test_non_incident_updates_are_ignored():
    sent = []
    _connector(sent).process_message(_message("update", _incident(type="report")))
    assert sent == []


@pytest.mark.parametrize(
    "origin",
    [
        {"user_id": IMPORT_USER_ID},
        {"user_id": ANALYST_USER_ID, "applicant_id": IMPORT_USER_ID},
    ],
)
def test_updates_by_the_import_connector_user_are_ignored(origin):
    sent = []
    _connector(sent).process_message(_message("update", _incident(), origin=origin))
    assert sent == []


def test_stream_recovery_is_left_to_the_connector_config():
    calls = []
    connector = CybleVisionWritebackConnector.__new__(CybleVisionWritebackConnector)
    connector.helper = SimpleNamespace(
        connect_live_stream_id="live",
        listen_stream=lambda **kwargs: calls.append(kwargs),
    )
    connector.run()
    assert calls == [{"message_callback": connector.process_message}]

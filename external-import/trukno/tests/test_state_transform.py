import json

from conftest import FIXTURES
from trukno_connector.opencti_compat import cleanup_bundle_for_opencti
from trukno_connector.state import ConnectorState, next_checkpoint
from trukno_connector.transform import transform_breach_to_bundle


def test_first_run_uses_bootstrap_window():
    state = ConnectorState.empty(
        initial_lookback_days=7, now_iso="2026-04-21T12:00:00Z"
    )
    assert state.last_seen_updated_at == "2026-04-14T12:00:00Z"


def test_next_checkpoint_advances_to_max_seen_timestamp():
    current = ConnectorState(last_seen_updated_at="2026-04-20T10:00:00Z")
    updated = next_checkpoint(
        current,
        seen_timestamps=["2026-04-20T11:00:00Z", "2026-04-20T12:00:00Z"],
    )
    assert updated.last_seen_updated_at == "2026-04-20T12:00:00Z"


def test_transform_includes_linked_attack_patterns_and_malware():
    payload = json.loads(
        (FIXTURES / "breach_with_entities.json").read_text(encoding="utf-8")
    )

    bundle = transform_breach_to_bundle(payload)
    report = next(obj for obj in bundle["objects"] if obj["type"] == "report")
    linked_objects = [obj for obj in bundle["objects"] if obj["type"] != "report"]

    assert {obj["type"] for obj in linked_objects} == {"attack-pattern", "malware"}
    assert set(report["object_refs"]) == {obj["id"] for obj in linked_objects}


def test_cleanup_removes_unsupported_relationships_and_x_properties():
    bundle = {
        "type": "bundle",
        "id": "bundle--1",
        "objects": [
            {
                "type": "report",
                "id": "report--1",
                "object_refs": ["malware--1"],
                "x_opencti_source": "trukno",
            },
            {"type": "malware", "id": "malware--1", "name": "Example"},
            {
                "type": "relationship",
                "id": "relationship--1",
                "relationship_type": "contains",
                "source_ref": "report--1",
                "target_ref": "malware--1",
            },
        ],
    }

    cleaned = cleanup_bundle_for_opencti(bundle)

    assert "x_opencti_source" not in cleaned["objects"][0]
    assert all(
        obj.get("relationship_type") != "contains"
        for obj in cleaned["objects"]
        if obj["type"] == "relationship"
    )

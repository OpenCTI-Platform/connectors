import json

from connector import ConnectorState


def test_every_field_defaults_to_none():
    assert all(f.default is None for f in ConnectorState.model_fields.values())


def test_state_is_json_serializable():
    json.dumps(ConnectorState(last_bundle_id="bundle--x").model_dump(mode="json"))

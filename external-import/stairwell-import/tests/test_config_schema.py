import json
from pathlib import Path

from connector import ConnectorSettings

CONNECTOR_DIR = Path(__file__).resolve().parents[1]


def test_committed_config_schema_matches_settings():
    """__metadata__/connector_config_schema.json is generated from settings.py.

    Regenerate it (and CONNECTOR_CONFIG_DOC.md) with upstream's
    generate_config_schema task whenever the settings change.
    """
    generated = ConnectorSettings.config_json_schema(
        by_alias=False, connector_name=CONNECTOR_DIR.name, mode="validation"
    )
    committed = json.loads(
        (CONNECTOR_DIR / "__metadata__" / "connector_config_schema.json").read_text()
    )
    assert generated == committed


def test_scope_has_a_list_default():
    """The OpenCTI UI and upstream's metadata tests need a default for array settings."""
    committed = json.loads(
        (CONNECTOR_DIR / "__metadata__" / "connector_config_schema.json").read_text()
    )
    scope = committed["properties"]["CONNECTOR_SCOPE"]
    assert scope["type"] == "array"
    assert scope["default"] == ["stairwell"]
    assert "CONNECTOR_SCOPE" not in committed.get("required", [])

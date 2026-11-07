import json
from pathlib import Path

CONNECTOR_ROOT = Path(__file__).resolve().parent.parent


def test_manager_metadata_exposes_the_sdk_generated_settings_contract():
    manifest = json.loads(
        (CONNECTOR_ROOT / "__metadata__" / "connector_manifest.json").read_text(
            encoding="utf-8"
        )
    )
    schema = json.loads(
        (CONNECTOR_ROOT / "__metadata__" / "connector_config_schema.json").read_text(
            encoding="utf-8"
        )
    )

    assert manifest["manager_supported"] is True
    assert "TRUKNO_API_KEY" in schema["required"]
    assert schema["properties"]["TRUKNO_API_KEY"] == {
        "description": "TruKno API key.",
        "format": "password",
        "type": "string",
        "writeOnly": True,
    }
    assert schema["properties"]["CONNECTOR_DURATION_PERIOD"] == {
        "default": "PT1H",
        "description": "The period of time to await between two runs.",
        "format": "duration",
        "type": "string",
    }
    assert schema["properties"]["TRUKNO_INITIAL_LOOKBACK"] == {
        "default": "P30D",
        "description": "The period of time to look back on the first run.",
        "format": "duration",
        "type": "string",
    }
    assert "TRUKNO_INITIAL_LOOKBACK_DAYS" not in schema["properties"]
    assert "CONNECTOR_ID" not in schema["properties"]
    assert "CONNECTOR_ID" not in schema["required"]


def test_root_config_sample_uses_canonical_sdk_namespaces_and_duration():
    config_sample = (CONNECTOR_ROOT / "config.yml.sample").read_text(encoding="utf-8")

    assert "connector:" in config_sample
    assert '  duration_period: "PT1H"' in config_sample
    assert "trukno:" in config_sample
    assert '  api_key: "ChangeMe"' in config_sample
    assert '  initial_lookback: "P30D"' in config_sample
    assert "interval_minutes" not in config_sample

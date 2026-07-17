import json
from pathlib import Path

import yaml
from connector.settings import ConnectorSettings, ExternalImportConnectorConfig

ROOT = Path(__file__).parents[1]


def test_generated_configuration_schema_is_current():
    committed = json.loads(
        (ROOT / "__metadata__" / "connector_config_schema.json").read_text(
            encoding="utf-8"
        )
    )
    assert committed == ConnectorSettings.config_json_schema(
        connector_name="ransomlook"
    )
    assert committed["additionalProperties"] is False


def test_sample_compose_schema_and_scope_are_synchronized():
    sample = yaml.safe_load((ROOT / "config.yml.sample").read_text(encoding="utf-8"))
    schema = json.loads(
        (ROOT / "__metadata__" / "connector_config_schema.json").read_text(
            encoding="utf-8"
        )
    )
    manifest = json.loads(
        (ROOT / "__metadata__" / "connector_manifest.json").read_text(encoding="utf-8")
    )
    compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")

    source_variables = {f"RANSOMLOOK_{key.upper()}" for key in sample["ransomlook"]}
    assert source_variables <= schema["properties"].keys()
    assert all(variable in compose for variable in source_variables)

    expected_scope = set(ExternalImportConnectorConfig.model_fields["scope"].default)
    assert set(sample["connector"]["scope"].split(",")) == expected_scope
    assert set(schema["properties"]["CONNECTOR_SCOPE"]["default"]) == expected_scope
    assert "CONNECTOR_RUN_AND_TERMINATE" in compose
    assert "CONNECTOR_RESTART_POLICY:-unless-stopped" in compose
    assert "mem_limit: 4g" in compose
    assert manifest["manager_supported"] is True

import json
from pathlib import Path

CONNECTOR_ROOT = Path(__file__).resolve().parent.parent


def test_dockerfile_removes_build_only_git_after_installing_requirements():
    dockerfile = (CONNECTOR_ROOT / "Dockerfile").read_text(encoding="utf-8")

    # Align with the repo's standard Alpine connector image (see
    # templates/external-import/Dockerfile): build-only toolchain (git,
    # build-base) is added before installing requirements and removed after,
    # so it is not left in the final image.
    assert "python:3.12-alpine" in dockerfile
    assert "apk --no-cache add git build-base" in dockerfile
    assert dockerfile.index("pip3 install --no-cache-dir -r requirements.txt") < (
        dockerfile.index("apk del git build-base")
    )


def test_entrypoint_fails_fast_and_executes_python_as_pid_one():
    entrypoint = (CONNECTOR_ROOT / "entrypoint.sh").read_text(encoding="utf-8")

    assert "set -e" in entrypoint
    assert "exec python3 main.py" in entrypoint


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
    assert "CONNECTOR_ID" not in schema["properties"]
    assert "CONNECTOR_ID" not in schema["required"]


def test_root_config_sample_uses_canonical_sdk_namespaces_and_duration():
    config_sample = (CONNECTOR_ROOT / "config.yml.sample").read_text(encoding="utf-8")

    assert "connector:" in config_sample
    assert '  duration_period: "PT1H"' in config_sample
    assert "trukno:" in config_sample
    assert '  api_key: "ChangeMe"' in config_sample
    assert "interval_minutes" not in config_sample

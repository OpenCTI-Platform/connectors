import os
from unittest.mock import patch

import pytest
from connectors_sdk import ConfigValidationError
from pydantic import ValidationError
from reportimporter.core import ReportImporter
from reportimporter.settings import ConnectorSettings, InternalImportFileConnectorConfig


@pytest.mark.parametrize(
    "connector_type", ["INTERNAL_IMPORT_FILE", "INTERNAL_ANALYSIS"]
)
def test_supported_connector_types_are_accepted(connector_type: str) -> None:
    """The connector runs as INTERNAL_IMPORT_FILE or, in content mapping mode, as INTERNAL_ANALYSIS."""
    config = InternalImportFileConnectorConfig(type=connector_type)

    assert config.type == connector_type


def test_connector_type_defaults_to_internal_import_file() -> None:
    assert InternalImportFileConnectorConfig().type == "INTERNAL_IMPORT_FILE"


def test_unsupported_connector_type_is_rejected() -> None:
    with pytest.raises(ValidationError):
        InternalImportFileConnectorConfig(type="INTERNAL_ENRICHMENT")


@pytest.fixture
def base_env(monkeypatch: pytest.MonkeyPatch) -> pytest.MonkeyPatch:
    monkeypatch.setenv("OPENCTI_URL", "http://localhost:8080")
    monkeypatch.setenv("OPENCTI_TOKEN", "test-token")
    monkeypatch.setenv("CONNECTOR_ID", "00000000-0000-4000-8000-000000000000")
    monkeypatch.delenv("CONNECTOR_TYPE", raising=False)
    monkeypatch.delenv("IMPORT_DOCUMENT_MODE", raising=False)
    return monkeypatch


@pytest.mark.parametrize(
    "connector_type, mode, expected_type",
    [
        # Mode not set: the type follows CONNECTOR_TYPE (manual deployments).
        (None, None, "INTERNAL_IMPORT_FILE"),
        ("INTERNAL_ANALYSIS", None, "INTERNAL_ANALYSIS"),
        # Mode set: it wins over the CONNECTOR_TYPE injected by the catalog.
        ("INTERNAL_IMPORT_FILE", "analysis", "INTERNAL_ANALYSIS"),
        ("INTERNAL_ANALYSIS", "import", "INTERNAL_IMPORT_FILE"),
        (None, "analysis", "INTERNAL_ANALYSIS"),
        (None, "import", "INTERNAL_IMPORT_FILE"),
    ],
)
def test_helper_config_type_follows_mode(
    base_env: pytest.MonkeyPatch,
    connector_type: str | None,
    mode: str | None,
    expected_type: str,
) -> None:
    if connector_type is not None:
        base_env.setenv("CONNECTOR_TYPE", connector_type)
    if mode is not None:
        base_env.setenv("IMPORT_DOCUMENT_MODE", mode)

    helper_config = ConnectorSettings().to_helper_config()

    assert helper_config["connector"]["type"] == expected_type


def test_unsupported_mode_is_rejected(base_env: pytest.MonkeyPatch) -> None:
    base_env.setenv("IMPORT_DOCUMENT_MODE", "enrichment")

    with pytest.raises(ConfigValidationError):
        ConnectorSettings()


def test_connector_overrides_catalog_injected_type(
    base_env: pytest.MonkeyPatch,
) -> None:
    """pycti reads CONNECTOR_TYPE from the environment first, so the connector must align it."""
    base_env.setenv("CONNECTOR_TYPE", "INTERNAL_IMPORT_FILE")
    base_env.setenv("IMPORT_DOCUMENT_MODE", "analysis")

    with patch("reportimporter.core.OpenCTIConnectorHelper") as helper_class:
        ReportImporter()

    assert os.environ["CONNECTOR_TYPE"] == "INTERNAL_ANALYSIS"
    helper_config = helper_class.call_args.kwargs["config"]
    assert helper_config["connector"]["type"] == "INTERNAL_ANALYSIS"

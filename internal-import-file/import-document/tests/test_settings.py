import pytest
from pydantic import ValidationError
from reportimporter.settings import InternalImportFileConnectorConfig


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

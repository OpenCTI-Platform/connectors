import pytest
from pydantic import ValidationError
from src.models.configs.config_loader import (
    VALID_SCOPE_VALUES,
    ConfigLoaderConnector,
)


def _minimal_kwargs(**overrides):
    kwargs = {
        "id": "test-connector-id",
        "name": "Test Connector",
    }
    kwargs.update(overrides)
    return kwargs


def test_scope_default_value_is_used_when_not_provided():
    """When CONNECTOR_SCOPE is not provided, the default valid scope list should apply."""
    config = ConfigLoaderConnector(**_minimal_kwargs())

    assert config.scope == VALID_SCOPE_VALUES


@pytest.mark.parametrize(
    "scope",
    [
        pytest.param(VALID_SCOPE_VALUES, id="full_valid_scope_list"),
        pytest.param(["attack-pattern"], id="single_valid_scope_value"),
        pytest.param(
            ["tool", "campaign", "intrusion-set"], id="subset_of_valid_scope_values"
        ),
    ],
)
def test_scope_accepts_valid_values(scope):
    """CONNECTOR_SCOPE should accept any subset of the supported STIX types."""
    config = ConfigLoaderConnector(**_minimal_kwargs(scope=scope))

    assert config.scope == scope


@pytest.mark.parametrize(
    "scope",
    [
        pytest.param("mitre", id="legacy_invalid_scope_value"),
        pytest.param(["attack-pattern", "mitre"], id="valid_value_mixed_with_invalid"),
        pytest.param(["not-a-stix-type"], id="unknown_stix_type"),
    ],
)
def test_scope_rejects_invalid_values(scope):
    """CONNECTOR_SCOPE must only contain values from the supported STIX type list."""
    with pytest.raises(ValidationError) as err:
        ConfigLoaderConnector(**_minimal_kwargs(scope=scope))

    assert "Invalid scope value(s)" in str(err.value)

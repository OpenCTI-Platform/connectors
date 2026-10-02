"""Module to test the composer catalog config loader (src/main.py)."""

from src.main import ConfigLoader


# Scenario: The composer catalog config loader aggregates the expected config sections
def test_config_loader_declares_expected_sections() -> None:
    """Test that ConfigLoader exposes the connector, opencti and gti sections."""
    field_names = set(ConfigLoader.model_fields.keys())
    assert field_names == {"connector", "opencti", "gti"}  # noqa: S101

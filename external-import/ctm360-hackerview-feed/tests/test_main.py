"""Test that the connector entry point is importable."""

from connector import ConnectorSettings, CTM360HackerViewConnector


class TestMainImports:
    """Verify that the main module imports resolve correctly."""

    def test_connector_class_importable(self):
        assert CTM360HackerViewConnector is not None

    def test_settings_class_importable(self):
        assert ConnectorSettings is not None

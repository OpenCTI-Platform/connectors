"""Test that the connector entry point is importable."""

import importlib

from connector import ConnectorSettings, CTM360CynaConnector


class TestMainImports:
    """Verify that the main module imports resolve correctly."""

    def test_connector_class_importable(self):
        assert CTM360CynaConnector is not None

    def test_settings_class_importable(self):
        assert ConnectorSettings is not None

    def test_entrypoint_module_importable(self):
        # Importing main resolves the entrypoint wiring without executing the
        # ``__main__`` guard.
        assert importlib.import_module("main") is not None

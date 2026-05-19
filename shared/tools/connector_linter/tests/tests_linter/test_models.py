"""Tests for ConnectorContext model loading."""

import pytest
from connector_linter.models import ConnectorContext


class TestConnectorTypeDetection:
    """Connector type inference behavior."""

    def test_detects_type_from_parent_directory(self, minimal_connector):
        ctx = ConnectorContext.load(minimal_connector)
        assert ctx.connector_type == "EXTERNAL_IMPORT"

    def test_detects_type_in_templates_layout(self, tmp_path):
        connector_dir = tmp_path / "templates" / "external-import"
        connector_dir.mkdir(parents=True)

        ctx = ConnectorContext.load(connector_dir)
        assert ctx.connector_type == "EXTERNAL_IMPORT"

    def test_raises_for_unknown_layout_without_manifest_type(self, tmp_path):
        connector_dir = tmp_path / "foo" / "bar"
        connector_dir.mkdir(parents=True)

        with pytest.raises(ValueError, match="Unable to determine connector type"):
            ConnectorContext.load(connector_dir)

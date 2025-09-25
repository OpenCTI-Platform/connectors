"""Tests for deterministic and identity behavior of the PGL Yoyo connector."""

from types import SimpleNamespace

from pgl_yoyo.config_loader import ConfigConnector
from pgl_yoyo.pgl_connector import PGLConnector


def test_config_defaults_present():
    """Test that default config values are present."""
    cfg = ConfigConnector(config={"connector": {"confidence_level": 50}})
    assert hasattr(cfg, "bundle_mode")
    assert hasattr(cfg, "report_per_run")


def test_identity_builds_without_helper():
    """Test that an identity can be built without a full helper."""
    # Create a fake helper minimally sufficient for construction
    fake_helper = SimpleNamespace()
    fake_helper.connector_logger = SimpleNamespace(info=lambda *args, **kwargs: None)
    fake_helper.connect_name = "pgl-yoyo-test"

    cfg = ConfigConnector(
        config={
            "connector": {"confidence_level": 50},
            "pgl": {"identity_name": "pgl-yoyo-test"},
        }
    )
    conn = PGLConnector(config=cfg, helper=fake_helper)

    ident = conn._get_or_build_identity()
    assert ident.name == conn.identity_name
    assert ident.identity_class == conn.identity_class

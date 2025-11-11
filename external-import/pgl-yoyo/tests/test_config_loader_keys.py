"""Tests for config loader keys in the PGL Yoyo connector."""

from pgl_yoyo.config_loader import ConfigConnector


def test_loader_exposes_sample_defaults():
    """Test that the config loader exposes expected default keys."""
    cfg = ConfigConnector(config={})

    # Connector-level
    assert hasattr(cfg, "duration_period")
    assert hasattr(cfg, "name")
    assert hasattr(cfg, "scope")
    assert hasattr(cfg, "update_existing_data")
    assert hasattr(cfg, "run_and_terminate")
    assert hasattr(cfg, "confidence_level")

    # PGL-specific
    assert hasattr(cfg, "bundle_mode")
    assert hasattr(cfg, "report_per_run")
    assert hasattr(cfg, "identity_name")
    assert hasattr(cfg, "identity_class")
    assert hasattr(cfg, "identity_description")
    assert hasattr(cfg, "identity_id")
    assert hasattr(cfg, "feeds")

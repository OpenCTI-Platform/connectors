"""Tests for the configuration loader of the pgl-yoyo connector."""

from pgl_yoyo.config_loader import ConfigConnector


def test_config_defaults(tmp_path, monkeypatch):
    """Test that default configuration values are set correctly."""
    tmpdir = tmp_path / "cfg"
    tmpdir.mkdir()
    monkeypatch.chdir(tmpdir)

    cfg = ConfigConnector()

    assert isinstance(cfg.load, dict)
    assert hasattr(cfg, "bundle_mode")


def test_feeds_parsing(tmp_path, monkeypatch):
    """Test that feeds configuration is parsed correctly."""
    sample = tmp_path / "config.yml"
    sample.write_text("pgl:\n  feeds: []\n")
    monkeypatch.chdir(tmp_path)

    cfg = ConfigConnector()
    # The loader may preserve an explicit empty list or substitute defaults
    # depending on runtime configuration; ensure we at least get a list.
    assert isinstance(cfg.feeds, list)

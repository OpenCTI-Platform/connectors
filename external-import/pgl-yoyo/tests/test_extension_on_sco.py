"""Tests for STIX2 extension on SCOs in the PGL Yoyo connector."""

import stix2
from pgl_yoyo.config_loader import ConfigConnector
from pgl_yoyo.pgl_connector import PGLConnector


class DummyHelper:
    """A minimal dummy helper to satisfy PGLConnector dependencies."""

    def __init__(self):
        self.connect_name = "pgl-yoyo-test"
        self.connect_id = "connector--test"
        self.connector_logger = self

    def log_info(self, *args, **kwargs):
        """Log informational messages (dummy implementation)."""
        _ = args
        _ = kwargs

    def log_error(self, *args, **kwargs):
        """Log error messages (dummy implementation)."""
        _ = args
        _ = kwargs


def test_expected_fields_present():
    """Test that the expected fields are present on created SCOs."""
    cfg = ConfigConnector()
    cfg.confidence_level = 50
    cfg.feeds = [
        {
            "name": "test",
            "url": "http://example",
            "type": "IPv4-Addr",
            "labels": ["testlabel"],
        }
    ]
    helper = DummyHelper()
    conn = PGLConnector(cfg, helper)

    identity = stix2.Identity(
        id="identity--550e8400-e29b-41d4-a716-446655440000",
        name="PGL",
        identity_class="organization",
    )
    objs = conn._build_sco_observables(
        ["1.2.3.4"], "IPv4-Addr", ["testlabel"], identity
    )
    assert len(objs) == 1
    indicator = objs[0]

    # Current implementation returns an Indicator with expected fields
    assert getattr(indicator, "type", None) == "indicator"
    assert getattr(indicator, "created_by_ref", None) == identity.id
    assert "testlabel" in getattr(indicator, "labels", [])
    assert getattr(indicator, "pattern_type", None) == "stix"
    assert "[ipv4-addr:value = '1.2.3.4']" in getattr(indicator, "pattern", "")
    assert "testlabel" in getattr(indicator, "labels", [])
    assert getattr(indicator, "pattern_type", None) == "stix"
    assert "[ipv4-addr:value = '1.2.3.4']" in getattr(indicator, "pattern", "")

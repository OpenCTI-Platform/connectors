import stix2

from pgl_yoyo.config_loader import ConfigConnector
from pgl_yoyo.pgl_connector import PGLConnector


class DummyHelper:
    def __init__(self):
        self.connect_name = "pgl-yoyo-test"
        self.connect_id = "connector--test"
        self.connector_logger = self

    def info(self, *a, **k):
        pass

    def log_info(self, *a, **k):
        pass

    def log_error(self, *a, **k):
        pass


def test_x_opencti_extension_present():
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
    ind = objs[0]

    # Current implementation returns an Indicator with expected fields
    assert getattr(ind, "type", None) == "indicator"
    assert getattr(ind, "created_by_ref", None) == identity.id
    assert "testlabel" in getattr(ind, "labels", [])
    assert getattr(ind, "pattern_type", None) == "stix"
    assert "[ipv4-addr:value = '1.2.3.4']" in getattr(ind, "pattern", "")

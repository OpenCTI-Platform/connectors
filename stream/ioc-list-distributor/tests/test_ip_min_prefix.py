"""Checks for the widest-CIDR guard (EXPORT_IP_MIN_PREFIX_V4 / _V6).

Run: python tests/test_ip_min_prefix.py (or pytest).
"""

import os
import sys
import tempfile
from pathlib import Path

os.environ["DATA_DIR"] = tempfile.mkdtemp()
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from common import config  # noqa: E402
from ioc_distributor.exporter import FeedExporter  # noqa: E402

KEYS = [
    "EXPORT_IP_MIN_PREFIX_V4",
    "EXPORT_IP_MIN_PREFIX_V6",
    "EXPORT_DROP_NON_PUBLIC_IPS",
]


def _settings(**env):
    for key in KEYS:
        os.environ.pop(key, None)
    os.environ.update({k: str(v) for k, v in env.items()})
    return config.export_settings()


def _expect_exit(**env):
    try:
        _settings(**env)
    except SystemExit as exc:
        return str(exc)
    raise AssertionError(f"expected a startup error for {env}")


class _FakeStore:
    def __init__(self, ips):
        self.ips = ips

    def select_for_export(self, ioc_type, base_attribute, cutoff, now, sort_order):
        return [(v, None) for v in self.ips] if ioc_type == "ip" else []

    def purge_older_than(self, cutoff):
        return 0


def _render(settings, value):
    """(value as exported or None, reason it was left out or None)."""
    reason = FeedExporter(_FakeStore([]), settings)._ip_drop_reason(value)
    return (None if reason else value), reason


def test_defaults():
    s = _settings()
    assert (s.ip_min_prefix_v4, s.ip_min_prefix_v6) == (24, 48)


def test_wide_v4_dropped_narrow_kept():
    s = _settings()
    out, reason = _render(s, "64.0.0.0/3")
    assert out is None and reason.startswith("too wide: /3"), reason
    assert _render(s, "8.8.8.0/23")[0] is None
    assert _render(s, "8.8.8.0/24") == ("8.8.8.0/24", None)
    assert _render(s, "8.8.8.8") == ("8.8.8.8", None)
    assert _render(s, "8.8.8.8/32") == ("8.8.8.8/32", None)


def test_wide_v6_dropped_narrow_kept():
    s = _settings()
    assert _render(s, "2a00::/12")[1].startswith("too wide: /12")
    assert _render(s, "2a00:1450:4000::/47")[0] is None
    assert _render(s, "2a00:1450:4000::/48")[0] == "2a00:1450:4000::/48"
    assert _render(s, "2a00:1450:4001:81b::200e")[0] == "2a00:1450:4001:81b::200e"


def test_applies_even_without_non_public_filter():
    s = _settings(EXPORT_DROP_NON_PUBLIC_IPS="false")
    assert _render(s, "64.0.0.0/3")[1].startswith("too wide")


def test_custom_and_zero():
    s = _settings(EXPORT_IP_MIN_PREFIX_V4=16, EXPORT_IP_MIN_PREFIX_V6=0)
    assert _render(s, "8.8.0.0/16")[0] == "8.8.0.0/16"
    assert _render(s, "8.0.0.0/15")[0] is None
    assert _render(s, "2a00::/12")[0] == "2a00::/12"  # 0 = no limit


def test_invalid_values_stop_startup():
    assert "EXPORT_IP_MIN_PREFIX_V4" in _expect_exit(EXPORT_IP_MIN_PREFIX_V4=33)
    assert "EXPORT_IP_MIN_PREFIX_V4" in _expect_exit(EXPORT_IP_MIN_PREFIX_V4="/24")
    assert "EXPORT_IP_MIN_PREFIX_V6" in _expect_exit(EXPORT_IP_MIN_PREFIX_V6=129)
    assert "EXPORT_IP_MIN_PREFIX_V6" in _expect_exit(EXPORT_IP_MIN_PREFIX_V6=-1)


def test_export_reports_too_wide():
    s = _settings()
    exporter = FeedExporter(_FakeStore(["64.0.0.0/3", "8.8.8.8", "1.1.1.0/24"]), s)
    exporter.export_once()
    status = exporter.status()
    assert status["last_error"] is None, status["last_error"]
    info = status["files"]["ip.txt"]
    assert info["entries"] == 2, info
    assert info["dropped"]["by_reason"] == {"too wide": 1}, info["dropped"]
    with open(os.path.join(config.FEEDS_DIR, "ip.txt")) as fh:
        assert "64.0.0.0/3" not in fh.read()


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print("ok", name)
    print("all widest-CIDR checks passed")

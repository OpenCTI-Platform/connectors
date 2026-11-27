"""Tests for ThreatFox._resolve_score().

Regression coverage for a bug where the per-IOC-type x_opencti_score
overrides (THREATFOX_X_OPENCTI_SCORE_IP/DOMAIN/URL/HASH) were loaded into
the connector but never actually consulted -- every observable's score was
always derived from ThreatFox's confidence_level, silently ignoring any
configured override.

ThreatFox.__init__ talks to a live OpenCTI instance (config loading, helper
construction, identity creation), so these tests call the unbound
_resolve_score() method against a minimal stand-in object instead of a real
ThreatFox instance.
"""

from types import SimpleNamespace

from src.__main__ import ThreatFox


def _fake_connector(overrides: dict, default_score: int = 50) -> SimpleNamespace:
    """Return a stand-in with just the attributes _resolve_score() reads."""
    return SimpleNamespace(
        _score_override_by_type=overrides,
        default_x_opencti_score=default_score,
    )


def _ioc(ioc_type: str, confidence_level) -> SimpleNamespace:
    return SimpleNamespace(type=ioc_type, confidence_level=confidence_level)


def test_resolve_score_uses_confidence_when_no_override_set():
    connector = _fake_connector(
        {"ip:port": None, "domain": None, "url": None, "md5_hash": None}
    )
    assert ThreatFox._resolve_score(connector, _ioc("domain", 42)) == 42


def test_resolve_score_prefers_type_override_over_confidence():
    connector = _fake_connector({"ip:port": 90})
    assert ThreatFox._resolve_score(connector, _ioc("ip:port", 10)) == 90


def test_resolve_score_hash_override_applies_to_all_hash_types():
    connector = _fake_connector({"md5_hash": 75, "sha1_hash": 75, "sha256_hash": 75})
    for hash_type in ("md5_hash", "sha1_hash", "sha256_hash"):
        assert ThreatFox._resolve_score(connector, _ioc(hash_type, 5)) == 75


def test_resolve_score_falls_back_to_default_when_confidence_unusable():
    connector = _fake_connector({"url": None}, default_score=33)
    assert ThreatFox._resolve_score(connector, _ioc("url", "not-a-number")) == 33

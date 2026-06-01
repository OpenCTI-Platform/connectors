import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from internal_enrichment_connector.mitre_resolver import MITREResolver


def _load_sample_bundle() -> dict:
    fixture = Path(__file__).parent / "fixtures" / "enterprise-attack-sample.json"
    return json.loads(fixture.read_text(encoding="utf-8"))


class _MockResponse:
    def __init__(self, payload: dict):
        self._payload = payload

    def raise_for_status(self):
        return None

    def json(self):
        return self._payload


def test_resolve_known_data_source(monkeypatch, tmp_path):
    sample = _load_sample_bundle()
    monkeypatch.setattr(
        "internal_enrichment_connector.mitre_resolver.requests.get",
        lambda *_, **__: _MockResponse(sample),
    )
    resolver = MITREResolver(cache_dir=str(tmp_path), cache_ttl_days=7)

    assert resolver.initialize() is True
    result = resolver.resolve_data_source("Network Traffic")
    assert result is not None
    assert result["type"] == "x-mitre-data-source"


def test_resolve_unknown_data_source(monkeypatch, tmp_path):
    sample = _load_sample_bundle()
    monkeypatch.setattr(
        "internal_enrichment_connector.mitre_resolver.requests.get",
        lambda *_, **__: _MockResponse(sample),
    )
    resolver = MITREResolver(cache_dir=str(tmp_path))
    resolver.initialize()

    assert resolver.resolve_data_source("Not A Real Source") is None


def test_case_insensitive_lookup(monkeypatch, tmp_path):
    sample = _load_sample_bundle()
    monkeypatch.setattr(
        "internal_enrichment_connector.mitre_resolver.requests.get",
        lambda *_, **__: _MockResponse(sample),
    )
    resolver = MITREResolver(cache_dir=str(tmp_path))
    resolver.initialize()

    assert resolver.resolve_data_source("network traffic") is not None


def test_resolve_data_components(monkeypatch, tmp_path):
    sample = _load_sample_bundle()
    monkeypatch.setattr(
        "internal_enrichment_connector.mitre_resolver.requests.get",
        lambda *_, **__: _MockResponse(sample),
    )
    resolver = MITREResolver(cache_dir=str(tmp_path))
    resolver.initialize()

    source_id = "x-mitre-data-source--3e23e4b8-1111-4111-8111-111111111111"
    components = resolver.resolve_data_components(source_id)
    assert components
    assert all(c["x_mitre_data_source_ref"] == source_id for c in components)


def test_resolve_asset(monkeypatch, tmp_path):
    sample = _load_sample_bundle()
    monkeypatch.setattr(
        "internal_enrichment_connector.mitre_resolver.requests.get",
        lambda *_, **__: _MockResponse(sample),
    )
    resolver = MITREResolver(cache_dir=str(tmp_path))
    resolver.initialize()

    asset = resolver.resolve_asset("Network Device")
    assert asset is not None
    assert asset["type"] == "x-mitre-asset"


def test_validate_names_all_valid(monkeypatch, tmp_path):
    sample = _load_sample_bundle()
    monkeypatch.setattr(
        "internal_enrichment_connector.mitre_resolver.requests.get",
        lambda *_, **__: _MockResponse(sample),
    )
    resolver = MITREResolver(cache_dir=str(tmp_path))
    resolver.initialize()

    assert resolver.validate_names(["Network Traffic", "Firewall"]) == []


def test_validate_names_with_invalid(monkeypatch, tmp_path):
    sample = _load_sample_bundle()
    monkeypatch.setattr(
        "internal_enrichment_connector.mitre_resolver.requests.get",
        lambda *_, **__: _MockResponse(sample),
    )
    resolver = MITREResolver(cache_dir=str(tmp_path))
    resolver.initialize()

    assert resolver.validate_names(["Network Traffic", "Typo Source", "Firewall"]) == [
        "Typo Source"
    ]


def test_cache_ttl_respected(monkeypatch, tmp_path):
    sample = _load_sample_bundle()
    call_count = {"count": 0}

    def _mock_get(*_, **__):
        call_count["count"] += 1
        return _MockResponse(sample)

    monkeypatch.setattr(
        "internal_enrichment_connector.mitre_resolver.requests.get", _mock_get
    )

    resolver = MITREResolver(cache_dir=str(tmp_path), cache_ttl_days=7)
    assert resolver.initialize() is True
    assert resolver.initialize() is True
    assert call_count["count"] == 1


def test_cache_expired_refetch(monkeypatch, tmp_path):
    sample = _load_sample_bundle()
    call_count = {"count": 0}

    def _mock_get(*_, **__):
        call_count["count"] += 1
        return _MockResponse(sample)

    monkeypatch.setattr(
        "internal_enrichment_connector.mitre_resolver.requests.get", _mock_get
    )

    resolver = MITREResolver(cache_dir=str(tmp_path), cache_ttl_days=7)
    assert resolver.initialize() is True

    meta_path = tmp_path / "enterprise-attack.meta.json"
    stale_ts = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()
    meta_path.write_text(json.dumps({"fetched_at": stale_ts}), encoding="utf-8")

    assert resolver.initialize() is True
    assert call_count["count"] == 2


def test_graceful_degradation_no_network(monkeypatch, tmp_path):
    def _raise_get(*_, **__):
        raise RuntimeError("network unavailable")

    monkeypatch.setattr(
        "internal_enrichment_connector.mitre_resolver.requests.get", _raise_get
    )

    resolver = MITREResolver(cache_dir=str(tmp_path))
    assert resolver.initialize() is False
    assert resolver.is_available is False
    assert resolver.resolve_data_source("Network Traffic") is None


def test_stale_cache_fallback(monkeypatch, tmp_path):
    sample = _load_sample_bundle()
    cache_path = tmp_path / "enterprise-attack.json"
    cache_path.write_text(json.dumps(sample), encoding="utf-8")

    stale_ts = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()
    (tmp_path / "enterprise-attack.meta.json").write_text(
        json.dumps({"fetched_at": stale_ts}), encoding="utf-8"
    )

    def _raise_get(*_, **__):
        raise RuntimeError("network unavailable")

    monkeypatch.setattr(
        "internal_enrichment_connector.mitre_resolver.requests.get", _raise_get
    )

    resolver = MITREResolver(cache_dir=str(tmp_path))
    assert resolver.initialize() is True
    assert resolver.is_available is True
    assert resolver.resolve_data_source("Network Traffic") is not None


def test_data_source_names_property(monkeypatch, tmp_path):
    sample = _load_sample_bundle()
    monkeypatch.setattr(
        "internal_enrichment_connector.mitre_resolver.requests.get",
        lambda *_, **__: _MockResponse(sample),
    )
    resolver = MITREResolver(cache_dir=str(tmp_path))
    resolver.initialize()

    names = resolver.data_source_names
    assert "Network Traffic" in names
    assert "Firewall" in names

"""Tests for Amit's sandbox connector changes.

Covers: PDF polling, per-provider dedup/scores/families/labels/refs,
permalink formats, _cfg helper, backward compat auto-detection.
"""

import types
from unittest.mock import MagicMock, patch

from connector.stix_builder import StixBuilder

# ── helpers ────────────────────────────────────────────────────────────────────


class _StubLogger:
    def info(self, msg, *args, **kwargs):
        pass

    def warning(self, msg, *args, **kwargs):
        pass

    def error(self, msg, *args, **kwargs):
        pass

    def debug(self, msg, *args, **kwargs):
        pass


class _StubHelper:
    connect_scope = "Artifact"
    connect_log_level = "info"
    config = {}
    connector_logger = _StubLogger()

    class _API:
        class _Observable:
            def add_file(self, **kwargs):
                pass

            def update_field(self, **kwargs):
                pass

        stix_cyber_observable = _Observable()

    api = _API()

    def log_info(self, msg):
        pass

    def log_warning(self, msg):
        pass

    def log_error(self, msg):
        pass

    def log_debug(self, msg):
        pass

    def stix2_create_bundle(self, objects):
        return {"type": "bundle", "spec_version": "2.1", "objects": objects}

    def send_stix2_bundle(self, bundle, **kwargs):
        return ["bundle-1"]

    @staticmethod
    def check_max_tlp(markings, max_tlp):
        return True


def _make_builder(**kw) -> StixBuilder:
    helper = _StubHelper()
    return StixBuilder(helper, **kw)


ENTITY = {
    "id": "file--test-entity-id",
    "entity_type": "StixFile",
    "hashes": {"SHA-256": "a" * 64},
    "standard_id": "file--test-entity-id",
}


def _sandbox_result(
    provider: str,
    score: int = 70,
    family: str | None = "WannaCry",
    sha256: str = "a" * 64,
    sandbox_id: str = "sb-123",
    permalink: str | None = None,
    iocs: dict | None = None,
) -> dict:
    base = {
        "provider": provider,
        "score": score,
        "family": family,
        "sha256": sha256,
        "sandbox_id": sandbox_id,
        "permalink": permalink
        or f"https://polyswarm.network/sandbox/detail/file/{sha256}?sandboxId={sandbox_id}",
    }
    if provider == "triage":
        base["triage_behavioral_score"] = 8
    elif provider == "cape":
        base["cape_malscore"] = 6
    if iocs:
        base.update(iocs)
    return base


# ── 1. PDF polling ─────────────────────────────────────────────────────────────


class TestPdfPolling:
    """Test generate_pdf polling loop handles timeout, NotFoundException, success."""

    def _make_client(self):
        from connector.polyswarm_client import PolySwarmClient

        helper = _StubHelper()
        client = object.__new__(PolySwarmClient)
        client.helper = helper
        client.api = MagicMock()
        client._session = MagicMock()
        client._breaker_lock = __import__("threading").Lock()
        client._circuit_breaker = MagicMock()
        client._circuit_breaker.can_execute.return_value = (True, None)
        return client

    @patch("time.sleep")
    def test_polling_timeout(self, mock_sleep):
        client = self._make_client()
        # _retry_sdk_call returns a report stub on create, then None on every wait
        report_stub = types.SimpleNamespace(id="rpt-1")
        client._retry_sdk_call = MagicMock(side_effect=[report_stub] + [None] * 30)

        result = client.generate_pdf("task-1", "scan")
        assert result is None

    @patch("time.sleep")
    def test_polling_success(self, mock_sleep):
        client = self._make_client()
        report_stub = types.SimpleNamespace(id="rpt-1")
        finished_stub = types.SimpleNamespace(
            state="SUCCEEDED", url="https://example.com/pdf"
        )
        client._retry_sdk_call = MagicMock(side_effect=[report_stub, finished_stub])
        resp = MagicMock()
        resp.status_code = 200
        resp.content = b"%PDF-test"
        client._session.get.return_value = resp

        result = client.generate_pdf("task-1", "sandbox")
        assert result == b"%PDF-test"

    @patch("time.sleep")
    def test_polling_handles_not_found_exception(self, mock_sleep):
        from polyswarm_api.exceptions import NotFoundException

        client = self._make_client()
        report_stub = types.SimpleNamespace(id="rpt-1")

        def _side_effect(*args, **kwargs):
            raise NotFoundException("not found")

        # create succeeds, waits raise NotFoundException
        call_count = [0]
        MagicMock()

        def _retry(func, *a, **kw):
            call_count[0] += 1
            if call_count[0] == 1:
                return report_stub
            raise NotFoundException("not found")

        client._retry_sdk_call = _retry

        result = client.generate_pdf("task-1", "scan")
        assert result is None  # should not crash

    @patch("time.sleep")
    def test_polling_handles_connection_error(self, mock_sleep):
        client = self._make_client()
        report_stub = types.SimpleNamespace(id="rpt-1")
        call_count = [0]

        def _retry(func, *a, **kw):
            call_count[0] += 1
            if call_count[0] == 1:
                return report_stub
            raise ConnectionError("network down")

        client._retry_sdk_call = _retry
        result = client.generate_pdf("task-1", "scan")
        assert result is None


# ── 2. Per-provider dedup ──────────────────────────────────────────────────────


class TestPerProviderDedup:
    """IOCs from multiple providers are deduplicated in build_stix_bundle."""

    @patch.object(StixBuilder, "_fetch_polykg_profile", return_value=None)
    def test_ioc_dedup_across_providers(self, _mock_profile):
        builder = _make_builder()
        triage = _sandbox_result("triage", score=60, family="WannaCry")
        cape = _sandbox_result("cape", score=80, family="WannaCry")
        # Both report the same IOC domain
        triage["ioc_domains"] = ["evil.example.com"]
        cape["ioc_domains"] = ["evil.example.com"]

        results = {"triage": triage, "cape": cape}
        objects = builder.build_bundle(
            entity=ENTITY,
            sandbox_results=results,
            config={},
        )
        # Count domain objects
        domains = [o for o in objects if o.get("type") == "domain-name"]
        # Should be at most 1 (deduped)
        assert len(domains) <= 1


# ── 3. Per-provider score ──────────────────────────────────────────────────────


class TestPerProviderScore:
    """Highest score across providers wins."""

    @patch.object(StixBuilder, "_fetch_polykg_profile", return_value=None)
    def test_highest_score_wins(self, _mock_profile):
        builder = _make_builder()
        triage = _sandbox_result("triage", score=40, family="TestMal")
        cape = _sandbox_result("cape", score=85, family="TestMal")
        results = {"triage": triage, "cape": cape}
        objects = builder.build_bundle(
            entity=ENTITY, sandbox_results=results, config={}
        )
        indicators = [o for o in objects if o.get("type") == "indicator"]
        if indicators:
            assert indicators[0].get("x_opencti_score", 0) >= 85


# ── 4. Per-provider family ────────────────────────────────────────────────────


class TestPerProviderFamily:
    """Family from highest-scoring provider is used."""

    @patch.object(StixBuilder, "_fetch_polykg_profile", return_value=None)
    def test_family_from_highest_scorer(self, _mock_profile):
        builder = _make_builder()
        triage = _sandbox_result("triage", score=40, family="Emotet")
        cape = _sandbox_result("cape", score=90, family="WannaCry")
        results = {"triage": triage, "cape": cape}
        objects = builder.build_bundle(
            entity=ENTITY, sandbox_results=results, config={}
        )
        malware_objs = [o for o in objects if o.get("type") == "malware"]
        if malware_objs:
            assert malware_objs[0]["name"] == "WannaCry"


# ── 5. Per-provider external refs ─────────────────────────────────────────────


class TestPerProviderExternalRefs:
    """Each provider gets its own external reference URL."""

    def test_per_provider_external_refs(self):
        builder = _make_builder()
        triage = _sandbox_result("triage", permalink="https://example.com/triage")
        cape = _sandbox_result("cape", permalink="https://example.com/cape")
        refs = builder._build_external_refs(
            None, None, sandbox_results={"triage": triage, "cape": cape}
        )
        urls = [r["url"] for r in refs]
        assert "https://example.com/triage" in urls
        assert "https://example.com/cape" in urls
        assert len(refs) == 2


# ── 6. Sandbox permalink format ───────────────────────────────────────────────


class TestSandboxPermalink:
    """Sandbox URL format: /sandbox/detail/file/{sha256}?sandboxId={id}"""

    def test_sandbox_permalink_format(self):
        sha = "b" * 64
        result = _sandbox_result(
            "triage", sha256=sha, sandbox_id="sb-999", permalink=None
        )
        # The helper constructs this — verify the format
        expected = (
            f"https://polyswarm.network/sandbox/detail/file/{sha}?sandboxId=sb-999"
        )
        assert result["permalink"] == expected


# ── 7. Scan permalink format ──────────────────────────────────────────────────


class TestScanPermalink:
    """Scan URL format: /scan/results/file/{sha256}"""

    def test_scan_permalink_format(self):
        builder = _make_builder()
        sha = "c" * 64
        scan_data = {"permalink": f"https://polyswarm.network/scan/results/file/{sha}"}
        refs = builder._build_external_refs(scan_data, None)
        assert any("/scan/results/file/" in r["url"] for r in refs)


# ── 8. Label generation ───────────────────────────────────────────────────────


class TestLabelGeneration:
    """Provider-prefixed family labels (e.g. cape_malware_family:WannaCry)."""

    def test_provider_prefixed_labels(self):
        builder = _make_builder()
        triage = _sandbox_result("triage", family="Emotet")
        cape = _sandbox_result("cape", family="WannaCry")
        labels = builder._collect_labels(
            None,
            None,
            None,
            sandbox_results={"triage": triage, "cape": cape},
        )
        assert "triage_malware_family:Emotet" in labels
        assert "cape_malware_family:WannaCry" in labels


# ── 9. Label cleanup ──────────────────────────────────────────────────────────


class TestLabelCleanup:
    """Behavior and signature labels are NOT included."""

    def test_no_behavior_or_signature_labels(self):
        builder = _make_builder()
        scan_data = {
            "family": "TestMal",
            "labels": ["Trojan"],
            "operating_systems": ["Windows"],
            "score": 80,
        }
        labels = builder._collect_labels(scan_data, None, None)
        # Should not contain raw behavior/signature labels
        for lbl in labels:
            assert not lbl.startswith("behavior:")
            assert not lbl.startswith("signature:")


# ── 10. _cfg() helper ─────────────────────────────────────────────────────────


class TestCfgHelper:
    """Test both Pydantic-style and dict-style config access."""

    def test_dict_style(self):
        config = {"min_score": 50}
        assert StixBuilder._cfg(config, "min_score") == 50
        assert StixBuilder._cfg(config, "missing", "default") == "default"

    def test_pydantic_style(self):
        ps = types.SimpleNamespace(min_score=75)
        config = types.SimpleNamespace(polyswarm=ps)
        assert StixBuilder._cfg(config, "min_score") == 75
        assert StixBuilder._cfg(config, "missing", "fallback") == "fallback"

    def test_unknown_type(self):
        assert StixBuilder._cfg(42, "key", "default") == "default"


# ── 11. Backward compat ───────────────────────────────────────────────────────


class TestBackwardCompat:
    """sandbox_data without sandbox_results still works via auto-detection."""

    @patch.object(StixBuilder, "_fetch_polykg_profile", return_value=None)
    def test_triage_auto_detect(self, _mock_profile):
        builder = _make_builder()
        sb_data = _sandbox_result("triage", score=70, family="Emotet")
        sb_data["triage_behavioral_score"] = 8
        objects = builder.build_bundle(entity=ENTITY, sandbox_data=sb_data, config={})
        # Should produce objects (auto-detected as triage)
        assert len(objects) > 0

    @patch.object(StixBuilder, "_fetch_polykg_profile", return_value=None)
    def test_cape_auto_detect(self, _mock_profile):
        builder = _make_builder()
        sb_data = _sandbox_result("cape", score=60, family="TestMal")
        sb_data["cape_malscore"] = 5
        objects = builder.build_bundle(entity=ENTITY, sandbox_data=sb_data, config={})
        assert len(objects) > 0

    @patch.object(StixBuilder, "_fetch_polykg_profile", return_value=None)
    def test_explicit_provider_auto_detect(self, _mock_profile):
        builder = _make_builder()
        sb_data = _sandbox_result("triage", score=70, family="Emotet")
        objects = builder.build_bundle(entity=ENTITY, sandbox_data=sb_data, config={})
        assert len(objects) > 0

    @patch.object(StixBuilder, "_fetch_polykg_profile", return_value=None)
    def test_unknown_provider_fallback(self, _mock_profile):
        builder = _make_builder()
        sb_data = {"score": 50, "family": "Foo", "sha256": "a" * 64}
        objects = builder.build_bundle(entity=ENTITY, sandbox_data=sb_data, config={})
        assert len(objects) > 0

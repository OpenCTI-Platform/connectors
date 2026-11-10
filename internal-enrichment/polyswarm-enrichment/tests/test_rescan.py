"""Tests for the opt-in rescan of stale or unfinished scans (all SDK calls mocked).

Result objects are real SDK ArtifactInstance resources built from JSON in the
shape the API returns, so field handling matches production.
"""

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from conftest import StubHelper
from polyswarm_api import resources
from polyswarm_enrichment.client_api import CircuitBreaker, ConnectorClient
from polyswarm_enrichment.connector import ConnectorTemplate
from polyswarm_enrichment.polyswarm_client import polyswarm_exceptions

SHA256 = "a" * 64


def _instance(
    days_old=1, assertions=True, failed=False, window_closed=True, polyscore=0.5
):
    """A real SDK ArtifactInstance built from API-shaped JSON."""
    scanned = (datetime.now(timezone.utc) - timedelta(days=days_old)).isoformat()
    content = {
        "id": "12345678901234567",
        "sha256": SHA256,
        "md5": "b" * 32,
        "sha1": "c" * 40,
        "mimetype": "application/x-dosexec",
        "size": 1024,
        "extended_type": "PE32 executable",
        "first_seen": scanned,
        "last_seen": scanned,
        "last_scanned": scanned,
        "created": scanned,
        "upload_url": None,
        "community": "default",
        "failed": failed,
        "window_closed": window_closed,
        "polyscore": polyscore,
        "detections": {"benign": 1, "malicious": 3, "total": 4},
        "metadata": [],
        "assertions": (
            [
                {
                    "author": "0x1",
                    "author_name": "engine-a",
                    "bid": "1",
                    "engine": {"name": "engine-a"},
                    "mask": True,
                    "verdict": True,
                    "metadata": {"malware_family": "Foo"},
                }
            ]
            if assertions
            else []
        ),
    }
    return resources.ArtifactInstance(content, api=None)


def _client(days=7, timeout=300, search=None, rescan=None, wait_for=None):
    client = object.__new__(ConnectorClient)
    client.helper = StubHelper()
    client.config = SimpleNamespace(rescan_older_than_days=days, rescan_timeout=timeout)
    client.polyswarm_community = "default"
    client.polyswarm = MagicMock()
    client.polyswarm.tag_link_get.return_value = None
    client.polyswarm.search.return_value = search if search is not None else []
    if rescan is not None:
        client.polyswarm.rescan.return_value = rescan
    if wait_for is not None:
        client.polyswarm.wait_for.side_effect = wait_for
    client.polyswarm_default = None
    client._circuit_breakers = {"default": CircuitBreaker()}
    return client


def _query(client):
    result = client.query_polyswarm(SHA256)
    return result["data"], (result["errors"][0] if result["errors"] else None)


class TestRescanOffByDefault:
    def test_setting_defaults(self):
        from polyswarm_enrichment.settings import PolySwarmConfig

        cfg = PolySwarmConfig(api_key="k")
        assert cfg.rescan_older_than_days == 0
        assert cfg.rescan_timeout == 300

    def test_old_scan_not_rescanned_when_zero(self):
        client = _client(days=0, search=[_instance(days_old=400)])
        data, error = _query(client)
        assert error is None and data is not None
        client.polyswarm.rescan.assert_not_called()
        assert "rescan" not in data

    def test_no_completed_scan_not_rescanned_when_zero(self):
        client = _client(days=0, search=[_instance(assertions=False)])
        _query(client)
        client.polyswarm.rescan.assert_not_called()


class TestRescanTriggers:
    def test_fresh_scan_is_left_alone(self):
        client = _client(days=7, search=[_instance(days_old=2)])
        data, _ = _query(client)
        client.polyswarm.rescan.assert_not_called()
        assert "rescan" not in data

    def test_stale_scan_rescans_and_uses_fresh_result(self):
        fresh = _instance(days_old=0, polyscore=0.9)
        client = _client(
            days=7,
            search=[_instance(days_old=30, polyscore=0.1)],
            rescan=_instance(days_old=0, assertions=False, window_closed=False),
            wait_for=lambda *_a, **_k: fresh,
        )
        data, error = _query(client)
        assert error is None
        client.polyswarm.rescan.assert_called_once_with(SHA256, hash_type="sha256")
        assert data["polyscore"] == 0.9
        assert data["rescan"]["status"] == "completed"
        assert "latest scan is 30 days old" in data["rescan"]["reason"]

    def test_known_hash_without_completed_scan_rescans(self):
        fresh = _instance(days_old=0)
        client = _client(
            days=7,
            search=[_instance(assertions=False, window_closed=True)],
            rescan=_instance(assertions=False, window_closed=False),
            wait_for=lambda *_a, **_k: fresh,
        )
        data, error = _query(client)
        assert error is None and data is not None
        client.polyswarm.rescan.assert_called_once()
        assert data["rescan"]["reason"] == "no completed scan"

    def test_scan_still_running_is_not_doubled(self):
        client = _client(
            days=7, search=[_instance(assertions=False, window_closed=False)]
        )
        _query(client)
        client.polyswarm.rescan.assert_not_called()

    def test_unknown_hash_is_never_rescanned(self):
        client = _client(days=7, search=[])
        data, error = _query(client)
        assert data is None and error["is_no_results"]
        client.polyswarm.rescan.assert_not_called()

    def test_no_results_exception_is_never_rescanned(self):
        client = _client(days=7)
        client.polyswarm.search.side_effect = polyswarm_exceptions.NoResultsException(
            "none"
        )
        data, error = _query(client)
        assert data is None and error["is_no_results"]
        client.polyswarm.rescan.assert_not_called()


class TestRescanFailureModes:
    def test_timeout_keeps_old_result_and_records_it(self):
        def _timeout(*_a, **_k):
            raise polyswarm_exceptions.TimeoutException("too slow")

        client = _client(
            days=7,
            timeout=5,
            search=[_instance(days_old=30, polyscore=0.1)],
            rescan=_instance(assertions=False, window_closed=False),
            wait_for=_timeout,
        )
        data, error = _query(client)
        assert error is None
        assert data["polyscore"] == 0.1
        assert data["rescan"]["status"] == "timed_out"
        assert client.polyswarm.wait_for.call_args.kwargs["timeout"] == 5

    def test_rescan_error_keeps_old_result(self):
        client = _client(days=7, search=[_instance(days_old=30)])
        client.polyswarm.rescan.side_effect = polyswarm_exceptions.RequestException(
            "429 quota"
        )
        data, error = _query(client)
        assert error is None and data is not None
        assert data["rescan"]["status"] == "failed"

    def _dual(self, private_days, default_days):
        client = _client(days=7, search=[_instance(days_old=private_days)])
        client.polyswarm_community = "private"
        default_api = MagicMock()
        default_api.search.return_value = [_instance(days_old=default_days)]
        default_api.tag_link_get.return_value = None
        client.polyswarm_default = default_api
        client._circuit_breakers["private"] = CircuitBreaker()
        client._circuit_breakers["default"] = CircuitBreaker()
        for api in (client.polyswarm, default_api):
            api.rescan.return_value = _instance(assertions=False)
            api.wait_for.return_value = _instance(days_old=0, polyscore=0.9)
        return client, default_api

    def test_dual_fresh_winner_means_no_rescan_of_stale_copy(self):
        client, default_api = self._dual(private_days=30, default_days=1)
        result = client.query_polyswarm(SHA256)
        assert result["data"]["community"] == "default"
        client.polyswarm.rescan.assert_not_called()
        default_api.rescan.assert_not_called()

    def test_dual_both_stale_rescans_exactly_once(self):
        client, default_api = self._dual(private_days=30, default_days=20)
        result = client.query_polyswarm(SHA256)
        total = client.polyswarm.rescan.call_count + default_api.rescan.call_count
        assert total == 1
        # The winner is the newer (default) copy, and that is the one rescanned
        default_api.rescan.assert_called_once()
        assert result["data"]["rescan"]["status"] == "completed"
        assert "_source_result" not in result["data"]

    def test_age_comes_from_the_scan_the_data_was_built_from(self):
        # First held result is unusable and old; the usable one is fresh
        client = _client(
            days=7,
            search=[_instance(days_old=400, assertions=False), _instance(days_old=1)],
        )
        _query(client)
        client.polyswarm.rescan.assert_not_called()

    def test_no_completed_scan_and_failed_rescan_is_reported(self):
        client = _client(days=7, search=[_instance(assertions=False)])
        client.polyswarm.rescan.side_effect = polyswarm_exceptions.RequestException(
            "429 https://example.test/x?sig=SECRET"
        )
        result = client.query_polyswarm(SHA256)
        assert result["data"] is None
        assert result["rescan"]["status"] == "failed"
        connector = object.__new__(ConnectorTemplate)
        connector.converter_to_stix = SimpleNamespace(
            author=SimpleNamespace(id="identity--x")
        )
        note = connector._create_hash_not_found_note(
            "file--1", SHA256, result["rescan"]
        )
        assert "No Completed Scan" in note["content"]
        assert "failed" in note["content"]

    def test_rescan_failure_log_has_no_error_text(self, capsys):
        client = _client(days=7, search=[_instance(days_old=30)])
        client.polyswarm.rescan.side_effect = polyswarm_exceptions.RequestException(
            "https://example.test/x?sig=SECRET"
        )
        _query(client)
        assert "SECRET" not in capsys.readouterr().out


class TestRescanNote:
    @pytest.mark.parametrize(
        "status,needle",
        [
            ("completed", "from the new scan"),
            ("timed_out", "from the previous scan"),
            ("failed", "failed"),
            ("no_result", "no usable result"),
        ],
    )
    def test_note_text(self, status, needle):
        text = ConnectorTemplate._rescan_note_text(
            {"status": status, "reason": "no completed scan", "timeout": 300}
        )
        assert needle in text

    def test_no_rescan_no_line(self):
        assert ConnectorTemplate._rescan_note_text(None) is None

    def test_note_contains_rescan_section(self):
        connector = object.__new__(ConnectorTemplate)
        connector.converter_to_stix = SimpleNamespace(
            author=SimpleNamespace(id="identity--x")
        )
        note = connector._create_polyswarm_note(
            "file--1",
            {
                "community": "default",
                "detections": {"malicious": 1, "total": 2},
                "rescan": {
                    "status": "timed_out",
                    "reason": "no completed scan",
                    "timeout": 30,
                },
            },
        )
        assert "**Rescan:**" in note["content"]
        assert "30 seconds" in note["content"]


class TestRescanQuotaExhausted:
    def test_429_on_rescan_is_flagged(self):
        client = _client(days=7, search=[_instance(days_old=30)])
        client.polyswarm.rescan.side_effect = (
            polyswarm_exceptions.UsageLimitsExceededException(None, "429 limit")
        )
        data, error = _query(client)
        assert error is None and data is not None
        assert data["rescan"]["status"] == "failed"
        assert data["rescan"]["quota_exhausted"] is True

    def test_other_errors_are_not_flagged(self):
        client = _client(days=7, search=[_instance(days_old=30)])
        client.polyswarm.rescan.side_effect = polyswarm_exceptions.RequestException(
            "boom"
        )
        data, _ = _query(client)
        assert "quota_exhausted" not in data["rescan"]

    def test_note_names_quota_and_adds_quota_lines(self):
        connector = object.__new__(ConnectorTemplate)
        connector.converter_to_stix = SimpleNamespace(
            author=SimpleNamespace(id="identity--x")
        )
        connector.quota = MagicMock()
        connector.quota.exhausted_note_lines.return_value = ["- Plan: Free"]
        note = connector._create_polyswarm_note(
            "file--1",
            {
                "community": "default",
                "detections": {"malicious": 1, "total": 2},
                "rescan": {
                    "status": "failed",
                    "reason": "scan older than 7 days",
                    "quota_exhausted": True,
                },
            },
        )
        assert "quota is exhausted" in note["content"]
        assert "**Account quota:**" in note["content"]
        assert "- Plan: Free" in note["content"]

    def test_plain_failure_has_no_quota_lines(self):
        connector = object.__new__(ConnectorTemplate)
        connector.converter_to_stix = SimpleNamespace(
            author=SimpleNamespace(id="identity--x")
        )
        connector.quota = MagicMock()
        note = connector._create_polyswarm_note(
            "file--1",
            {
                "community": "default",
                "detections": {"malicious": 1, "total": 2},
                "rescan": {"status": "failed", "reason": "x"},
            },
        )
        assert "**Account quota:**" not in note["content"]
        connector.quota.exhausted_note_lines.assert_not_called()


class TestRescanSkippedOnRequest:
    def test_allow_rescan_false_never_rescans_a_stale_scan(self):
        client = _client(days=7, search=[_instance(days_old=30)])
        result = client.query_polyswarm(SHA256, allow_rescan=False)
        client.polyswarm.rescan.assert_not_called()
        assert "rescan" not in result["data"]
        assert "_held" not in result
        for key in ("data", "primary", "secondary"):
            assert "_source_result" not in (result.get(key) or {})

"""Tests for how the account quota reader is wired into the sandbox connector."""

import json
import threading
from unittest.mock import MagicMock, patch

import pytest
from connector.polyswarm_client import PolySwarmAPIError
from connector.quota import QuotaMonitor
from polyswarm_api import exceptions as polyswarm_exceptions

from tests.test_quota import FakeClock, FakeLogger, _account


def _sdk_client(quota_api):
    """A PolySwarmClient with a mocked SDK and a quota monitor on a fake account."""
    from connector.polyswarm_client import CircuitBreaker, PolySwarmClient

    client = PolySwarmClient.__new__(PolySwarmClient)
    client.helper = MagicMock()
    client.api = MagicMock()
    client._session = MagicMock()
    client._breaker = CircuitBreaker(failure_threshold=3, cooldown_seconds=0)
    client.SDK_MAX_RETRIES = 2
    client.SDK_BACKOFF_BASE = 0.01
    client.quota = QuotaMonitor(quota_api, FakeLogger(), clock=FakeClock())
    return client


class TestClientWiring:
    def test_sdk_429_raises_quota_exhausted_with_remaining_quota(self):
        from connector.polyswarm_client import PolySwarmAPIError

        quota_api = MagicMock()
        quota_api.account_features.return_value = _account(limit=500, remaining=0)
        client = _sdk_client(quota_api)
        client.api.submit = MagicMock(
            side_effect=polyswarm_exceptions.UsageLimitsExceededException(
                None, "You have exceeded your allowance."
            )
        )
        with pytest.raises(PolySwarmAPIError) as exc_info:
            client._retry_sdk_call(client.api.submit, operation="scan submit")
        error = exc_info.value
        assert error.category == "API Quota Exhausted (scan submit)"
        assert "Daily API calls remaining: 0 of 500" in error.detail
        assert "Usage window ends: 2026-12-01T00:00:00+00:00" in error.detail
        assert "000000000000" not in error.detail
        # Not retried: waiting seconds does not bring quota back
        assert client.api.submit.call_count == 1

    def test_quota_error_still_raised_when_quota_cannot_be_read(self):
        from connector.polyswarm_client import PolySwarmAPIError

        quota_api = MagicMock()
        quota_api.account_features.side_effect = ConnectionError("down")
        client = _sdk_client(quota_api)
        client.api.submit = MagicMock(
            side_effect=polyswarm_exceptions.UsageLimitsExceededException(None, "x")
        )
        with pytest.raises(PolySwarmAPIError) as exc_info:
            client._retry_sdk_call(client.api.submit, operation="scan submit")
        assert "could not be read" in exc_info.value.detail

    def test_url_submission_429_names_quota_and_does_not_leak_the_url(self):
        from connector.polyswarm_client import PolySwarmAPIError

        quota_api = MagicMock()
        quota_api.account_features.return_value = _account(limit=500, remaining=0)
        client = _sdk_client(quota_api)
        secret_url = "https://example.test/path?token=SECRETVALUE"
        client.api.sandbox_url = MagicMock(
            side_effect=polyswarm_exceptions.UsageLimitsExceededException(
                None, f"limit exceeded for {secret_url}"
            )
        )
        with pytest.raises(PolySwarmAPIError) as exc_info:
            client.submit_sandbox_url_async(secret_url)
        error = exc_info.value
        assert "Quota Exhausted" in error.category
        assert "SECRETVALUE" not in f"{error.category} {error.detail}"
        assert "Daily API calls remaining: 0 of 500" in error.detail

    def test_error_note_carries_the_quota_lines(self):
        from connector.polyswarm_client import PolySwarmAPIError
        from connector.stix_builder import StixBuilder

        quota_api = MagicMock()
        quota_api.account_features.return_value = _account(limit=500, remaining=0)
        client = _sdk_client(quota_api)
        error = client._quota_exhausted_error("scan submit")
        assert isinstance(error, PolySwarmAPIError)
        builder = StixBuilder(helper=MagicMock(), polykg_api_url=None)
        note = builder.create_error_note(
            {"id": "artifact--00000000-0000-4000-8000-000000000000"},
            error.category,
            error.detail,
            error.recommendations,
        )
        assert "Daily API calls remaining: 0 of 500" in note["content"]
        assert "Wait for your quota to reset" in note["content"]


class TestPollingWiring:
    @pytest.mark.parametrize(
        "method,sdk_call,arg",
        [
            ("get_scan_results", "lookup", "scan-1"),
            ("get_sandbox_results", "sandbox_task_status", "task-1"),
        ],
    )
    def test_429_while_polling_surfaces_as_the_quota_error(self, method, sdk_call, arg):
        from connector.polyswarm_client import PolySwarmAPIError

        quota_api = MagicMock()
        quota_api.account_features.return_value = _account(limit=500, remaining=0)
        client = _sdk_client(quota_api)
        setattr(
            client.api,
            sdk_call,
            MagicMock(
                side_effect=polyswarm_exceptions.UsageLimitsExceededException(None, "x")
            ),
        )
        with pytest.raises(PolySwarmAPIError) as exc_info:
            getattr(client, method)(arg)
        assert "Quota Exhausted" in exc_info.value.category
        assert "Daily API calls remaining: 0 of 500" in exc_info.value.detail


class TestConnectorWiring:
    def test_each_message_refreshes_the_quota(self):
        from connector.polyswarm_connector import PolySwarmConnector

        connector = object.__new__(PolySwarmConnector)
        connector.helper = MagicMock()
        connector.polyswarm_client = MagicMock()
        connector.stix_builder = MagicMock()
        connector._local = threading.local()
        result = connector._process_message({"stix_objects": []})
        connector.polyswarm_client.quota.refresh.assert_called_once_with()
        assert "Entity not found" in result


def _quota_client():
    quota_api = MagicMock()
    quota_api.account_features.return_value = _account(limit=500, remaining=0)
    return _sdk_client(quota_api)


def _usage_limits():
    return polyswarm_exceptions.UsageLimitsExceededException(None, "exceeded")


def _status_error(code):
    return polyswarm_exceptions.RequestException(
        MagicMock(status_code=code), f"Return code: {code}"
    )


class TestQuotaNotSwallowed:
    """Quota errors on submit, LLM and PDF calls reach a quota note."""

    @pytest.mark.parametrize(
        "sdk_call,method,kwargs",
        [
            ("submit", "submit_file_async", {"file_data": b"x", "filename": "a"}),
            (
                "sandbox_file",
                "submit_sandbox_async",
                {"file_data": b"x", "filename": "a"},
            ),
            ("llm_report_create", "create_llm_report", {"instance_id": "1"}),
            ("report_create", "generate_pdf", {"task_id": "1", "report_type": "scan"}),
        ],
    )
    def test_client_raises_quota_error(self, sdk_call, method, kwargs):
        from connector.polyswarm_client import PolySwarmAPIError

        client = _quota_client()
        setattr(client.api, sdk_call, MagicMock(side_effect=_usage_limits()))
        with pytest.raises(PolySwarmAPIError) as exc_info:
            getattr(client, method)(**kwargs)
        assert exc_info.value.is_quota_exhausted
        assert "Daily API calls remaining: 0 of 500" in exc_info.value.detail

    @pytest.mark.parametrize("method", ["submit_file_async", "submit_sandbox_async"])
    def test_submit_raises_402_as_quota(self, method):
        from connector.polyswarm_client import PolySwarmAPIError

        client = _quota_client()
        client.api.submit = MagicMock(side_effect=_status_error(402))
        client.api.sandbox_file = MagicMock(side_effect=_status_error(402))
        with pytest.raises(PolySwarmAPIError) as exc_info:
            getattr(client, method)(b"x", "a")
        assert exc_info.value.is_quota_or_rate_limited

    def test_llm_and_pdf_access_denied_stay_soft(self):
        """A plan without LLM or PDF reports is not a quota error: no raise."""
        client = _quota_client()
        client.api.llm_report_create = MagicMock(side_effect=_status_error(403))
        client.api.report_create = MagicMock(side_effect=_status_error(403))
        assert client.create_llm_report(instance_id="1") is None
        assert client.generate_pdf("1", "scan") is None

    def _artifact_connector(self, **overrides):
        from tests.test_connector import make_connector

        polyswarm = {"community": "acme-private", "allow_public_community": False}
        polyswarm.update(overrides)
        c = make_connector(polyswarm_overrides=polyswarm)
        c._local = threading.local()
        c.polyswarm_client = _quota_client()
        c._get_sandbox_providers = MagicMock(return_value=["cape", "triage"])
        c._get_vm_for_provider = MagicMock(return_value="win-10")
        c._phase_download = MagicMock(
            return_value=(b"data", "sample.exe", None, "application/octet-stream")
        )
        c._send_error_note = MagicMock()
        c._send_original_bundle = MagicMock()
        return c

    def _process(self, c):
        entity = {
            "type": "artifact",
            "id": "artifact--00000000-0000-0000-0000-000000000001",
            "hashes": {"SHA-256": "a" * 64},
        }
        with patch("connector.polyswarm_connector.time.sleep"):
            return c._process_message(
                {
                    "enrichment_entity": {"entity_type": "Artifact"},
                    "stix_entity": entity,
                    "stix_objects": [entity],
                    "entity_id": entity["id"],
                }
            )

    def _titles(self, c):
        return [call.args[1] for call in c._send_error_note.call_args_list]

    def test_scan_submit_quota_gives_one_quota_note(self):
        c = self._artifact_connector()
        c.polyswarm_client.api.submit = MagicMock(side_effect=_usage_limits())
        result = json.loads(self._process(c))
        assert result["status"] == "error"
        titles = self._titles(c)
        assert len(titles) == 1
        assert titles[0].startswith("API Quota Exhausted")
        assert "Scan Submission Failed" not in titles
        assert "Unexpected Enrichment Error" not in titles
        c._send_original_bundle.assert_called_once()

    def test_sandbox_submit_quota_gives_quota_note_and_keeps_scan(self):
        c = self._artifact_connector(sandbox_enabled=True, sandbox_provider="both")
        client = c.polyswarm_client
        client.get_provider_slugs = MagicMock(return_value=["cape", "triage"])
        client.submit_file_async = MagicMock(return_value="scan-1")
        client.api.sandbox_file = MagicMock(side_effect=_usage_limits())
        scan_id, tasks = c._phase_submit(
            {"id": "artifact--1"}, b"data", "sample.exe", None, None
        )
        assert scan_id == "scan-1"
        assert tasks == {}
        titles = self._titles(c)
        assert len(titles) == 1
        assert titles[0].startswith("API Quota Exhausted")
        # Quota is account wide: the second provider is not tried
        assert client.api.sandbox_file.call_count == 1

    def test_second_sandbox_quota_keeps_first_task(self):
        c = self._artifact_connector(sandbox_enabled=True, sandbox_provider="both")
        client = c.polyswarm_client
        client.get_provider_slugs = MagicMock(return_value=["cape", "triage"])
        client.submit_file_async = MagicMock(return_value="scan-1")
        client.api.sandbox_file = MagicMock(
            side_effect=[MagicMock(id="task-cape"), _usage_limits()]
        )
        _scan_id, tasks = c._phase_submit(
            {"id": "artifact--1"}, b"data", "sample.exe", None, None
        )
        assert tasks == {"cape": "task-cape"}
        titles = self._titles(c)
        assert len(titles) == 1
        assert titles[0].startswith("API Quota Exhausted")

    def test_report_quota_stops_further_reports_and_notes_once(self):
        c = self._artifact_connector(pdf_report_enabled=True, llm_report_enabled=True)
        client = c.polyswarm_client
        client.generate_pdf = MagicMock(
            side_effect=PolySwarmAPIError(
                "API Quota Exhausted (PDF report create (scan))", "detail"
            )
        )
        client.create_llm_report = MagicMock(return_value="llm-1")
        c._local.report_quota_error = None
        c._phase_reports(
            {"id": "artifact--1"},
            "scan-1",
            {"id": "scan-1"},
            {"score": 1},
            {"cape": "task-cape", "triage": "task-triage"},
            {
                "cape": {"status": "SUCCEEDED"},
                "triage": {"status": "SUCCEEDED"},
            },
            {},
            "sample.exe",
            "a" * 64,
        )
        # The scan PDF hit the quota: no sandbox PDF was requested after it
        assert client.generate_pdf.call_count == 1
        titles = self._titles(c)
        assert titles == ["API Quota Exhausted (PDF report create (scan))"]
        # Later report requests in the same enrichment are skipped too
        assert c._request_report(client.create_llm_report, instance_id="1") is None
        client.create_llm_report.assert_not_called()

    def test_llm_quota_while_polling_is_noted_in_reports(self):
        c = self._artifact_connector(llm_report_enabled=True)
        client = c.polyswarm_client
        client.create_llm_report = MagicMock(
            side_effect=PolySwarmAPIError("API Rate Limit Exceeded (LLM)", "slow")
        )
        client.get_scan_results = MagicMock(return_value={"id": "scan-1"})
        with patch("connector.polyswarm_connector.time.sleep"):
            _res, llm_ids = c._phase_poll_scan({"id": "artifact--1"}, "scan-1", 1, 10)
        assert llm_ids == {}
        assert self._titles(c) == []
        c._phase_reports({"id": "artifact--1"}, None, None, None, {}, {}, {}, "s", None)
        assert self._titles(c) == ["API Rate Limit Exceeded (LLM)"]


class TestSettings:
    def test_quota_warn_below_default_and_env(self, monkeypatch):
        ConnectorSettings = pytest.importorskip(
            "connector.models.configs.settings", reason="connectors_sdk unavailable"
        ).ConnectorSettings
        monkeypatch.setenv("OPENCTI_URL", "http://localhost:8080")
        monkeypatch.setenv("OPENCTI_TOKEN", "test-token")
        monkeypatch.setenv("CONNECTOR_ID", "00000000-0000-0000-0000-000000000006")
        monkeypatch.setenv("POLYSWARM_API_KEY", "test-key")
        assert ConnectorSettings().polyswarm.quota_warn_below == 100
        monkeypatch.setenv("POLYSWARM_QUOTA_WARN_BELOW", "0")
        assert ConnectorSettings().polyswarm.quota_warn_below == 0

"""Tests for graceful handling of the missing ``indicator`` API scope.

These tests pin two related defensive contracts introduced to keep the
CrowdStrike connector from crashing when the API token does not include
the ``indicator`` scope (see PR #5577 / issue #6438):

* :class:`crowdstrike_feeds_connector.report.importer.ReportImporter._get_related_iocs`
  must treat a ``{"errors": [...]}`` response shape (no ``resources``
  key) as a recoverable, log-only failure rather than crashing with
  ``KeyError: 'resources'`` — and, on a 403, must cache the outcome on
  ``self._missing_indicator_scope`` so the same 403-producing call is
  not re-issued once per report on a large import.
* :meth:`crowdstrike_feeds_services.client.base_api.BaseCrowdstrikeClient.handle_api_error`
  must unpack ``response["body"]["errors"][0]`` defensively so an
  upstream ``errors=[]`` / ``errors=None`` / missing-``errors``
  payload cannot raise a secondary ``IndexError`` / ``KeyError`` and
  mask the real status-code diagnostic.
"""

from unittest.mock import MagicMock, patch

import pytest
from crowdstrike_feeds_connector.report.importer import ReportImporter
from crowdstrike_feeds_services.client.base_api import BaseCrowdstrikeClient

# ---------------------------------------------------------------------------
# ``ReportImporter._get_related_iocs`` — missing-``indicator``-scope handling
# ---------------------------------------------------------------------------


@pytest.fixture
def report_importer() -> ReportImporter:
    """Build a ``ReportImporter`` whose API clients are ``MagicMock``s.

    ``ReportsAPI`` and ``IndicatorsAPI`` are patched at constructor time
    so we don't instantiate the real falconpy client (which would need
    real credentials). The tests reach into ``importer.indicators_api_cs``
    to script the indicators-API response per case.
    """
    with patch("crowdstrike_feeds_connector.report.importer.ReportsAPI"), patch(
        "crowdstrike_feeds_connector.report.importer.IndicatorsAPI"
    ):
        importer = ReportImporter(
            config=MagicMock(),
            helper=MagicMock(),
            author=MagicMock(),
            default_latest_timestamp=0,
            tlp_marking=MagicMock(),
            include_types=[],
            target_industries=[],
            report_status=0,
            report_type="threat-report",
            guess_malware=False,
            report_guess_relations=False,
            indicator_config={},
            no_file_trigger_import=True,
            scopes=set(),
        )

    importer.indicators_api_cs = MagicMock()
    return importer


def _error_response(code: int, message: str = "test") -> dict:
    """A CrowdStrike-shaped error response body (no ``resources`` key)."""
    return {"errors": [{"code": code, "message": message}]}


def test_403_response_returns_empty_and_sets_missing_scope_flag(report_importer):
    """A 403 ``errors`` body must return ``[]`` and set the cache flag.

    This is the original crash reported in #6438: before the fix the
    code would raise ``KeyError: 'resources'`` on the same response;
    the importer now skips IOC enrichment for the report instead.
    """
    report_importer.indicators_api_cs.get_combined_indicator_entities.return_value = (
        _error_response(403, "access denied")
    )

    result = report_importer._get_related_iocs("report-A")

    assert result == []
    assert report_importer._missing_indicator_scope is True


def test_missing_scope_flag_short_circuits_subsequent_calls(report_importer):
    """Once the missing-scope cache is set, the API must not be re-hit.

    A large import can carry hundreds of reports through
    ``_get_related_iocs``; without the short-circuit each one would
    re-issue the same 403-producing call (and emit the same warning),
    which is exactly the noise this PR is meant to suppress.
    """
    report_importer.indicators_api_cs.get_combined_indicator_entities.return_value = (
        _error_response(403)
    )

    report_importer._get_related_iocs("report-A")
    report_importer._get_related_iocs("report-B")
    report_importer._get_related_iocs("report-C")

    assert (
        report_importer.indicators_api_cs.get_combined_indicator_entities.call_count
        == 1
    )


def test_non_403_error_returns_empty_and_does_not_set_flag(report_importer):
    """Non-403 errors must be log-only and must not poison the cache.

    A transient 500 should not disable IOC enrichment for the rest of
    the run — only the *permission* class of failure (which cannot
    self-recover for the lifetime of the importer) does.
    """
    report_importer.indicators_api_cs.get_combined_indicator_entities.return_value = (
        _error_response(500, "internal server error")
    )

    result = report_importer._get_related_iocs("report-A")

    assert result == []
    assert report_importer._missing_indicator_scope is False


def test_empty_errors_list_returns_empty_and_does_not_raise(report_importer):
    """``{"errors": []}`` must not re-introduce the old ``IndexError``.

    Without the defensive ``errors = response.get("errors") or []`` +
    ``errors[0] if errors else {}`` guard this case would crash inside
    the new error branch — exactly the bug PR #5577 is supposed to
    prevent.
    """
    report_importer.indicators_api_cs.get_combined_indicator_entities.return_value = {
        "errors": []
    }

    result = report_importer._get_related_iocs("report-A")

    assert result == []
    assert report_importer._missing_indicator_scope is False


def test_none_errors_returns_empty_and_does_not_raise(report_importer):
    """``{"errors": None}`` must also be handled defensively."""
    report_importer.indicators_api_cs.get_combined_indicator_entities.return_value = {
        "errors": None
    }

    result = report_importer._get_related_iocs("report-A")

    assert result == []
    assert report_importer._missing_indicator_scope is False


def test_response_without_resources_or_errors_returns_empty(report_importer):
    """An unexpected response shape (neither key) must log-and-return."""
    report_importer.indicators_api_cs.get_combined_indicator_entities.return_value = {
        "meta": {"trace_id": "abc"}
    }

    result = report_importer._get_related_iocs("report-A")

    assert result == []
    assert report_importer._missing_indicator_scope is False


def test_resources_none_does_not_crash(report_importer):
    """``{"resources": None}`` must not re-introduce a ``TypeError``.

    The defensive ``resources = response.get("resources") or []``
    extraction in the ``resources`` branch guards against the case
    where CrowdStrike returns the key but with a ``None`` (or another
    non-iterable) value — the previous shape ``related_indicators.extend(
    response["resources"])`` would have raised
    ``TypeError: 'NoneType' object is not iterable`` and the
    surrounding ``try/except`` would have swallowed the real
    diagnostic.
    """
    report_importer.indicators_api_cs.get_combined_indicator_entities.return_value = {
        "resources": None
    }

    result = report_importer._get_related_iocs("report-A")

    assert result == []
    # ``_missing_indicator_scope`` is only set on a 403, not on a
    # malformed-shape response, so other reports in the same run can
    # still attempt the call.
    assert report_importer._missing_indicator_scope is False


def test_resources_empty_list_returns_empty(report_importer):
    """``{"resources": []}`` is the happy-path no-IOC shape."""
    report_importer.indicators_api_cs.get_combined_indicator_entities.return_value = {
        "resources": []
    }

    result = report_importer._get_related_iocs("report-A")

    assert result == []
    assert report_importer._missing_indicator_scope is False


def test_errors_non_list_does_not_crash(report_importer):
    """A non-list ``errors`` value (e.g. a bare dict) must not crash.

    The CrowdStrike SDK normally wraps each error in a list, but a
    malformed payload could surface ``errors`` as a single dict the
    SDK forgot to wrap. Without the ``isinstance(errors, (list, tuple))``
    normalisation step, ``errors[0]`` would index the dict by the
    integer ``0`` and raise ``KeyError`` — defeating the whole point
    of this defensive branch. ``_get_related_iocs`` must treat the
    case like a malformed-shape response: return ``[]`` and leave
    ``_missing_indicator_scope`` alone so other reports in the same
    run can still attempt the call.
    """
    report_importer.indicators_api_cs.get_combined_indicator_entities.return_value = {
        "errors": {"code": 403, "message": "access denied"}
    }

    result = report_importer._get_related_iocs("report-A")

    assert result == []
    assert report_importer._missing_indicator_scope is False


# ---------------------------------------------------------------------------
# ``BaseCrowdstrikeClient.handle_api_error`` — defensive ``errors`` unpacking
# ---------------------------------------------------------------------------


def _make_base_client() -> BaseCrowdstrikeClient:
    """Build a ``BaseCrowdstrikeClient`` whose falconpy ctor is bypassed.

    ``BaseCrowdstrikeClient.__init__`` instantiates the real falconpy
    ``Intel`` client (which would attempt to authenticate). The tests
    only exercise ``handle_api_error``, which reads ``self.helper`` —
    nothing else — so we build the client via ``__new__`` and inject
    only the helper.
    """
    client = BaseCrowdstrikeClient.__new__(BaseCrowdstrikeClient)
    client.helper = MagicMock()
    client.helper.connector_logger = MagicMock()
    return client


def test_handle_api_error_noop_below_400():
    """``handle_api_error`` must do nothing for 2xx / 3xx responses."""
    client = _make_base_client()
    client.handle_api_error({"status_code": 200, "body": {"resources": []}})

    client.helper.connector_logger.error.assert_not_called()
    client.helper.connector_logger.warning.assert_not_called()


def test_handle_api_error_403_logs_warning():
    """A 403 is expected and must be logged at ``warning`` level only."""
    client = _make_base_client()
    client.handle_api_error(
        {
            "status_code": 403,
            "body": {"errors": [{"code": 403, "message": "access denied"}]},
        }
    )

    client.helper.connector_logger.warning.assert_called_once()
    client.helper.connector_logger.error.assert_not_called()


def test_handle_api_error_500_logs_error():
    """A non-403 must be logged at ``error`` level."""
    client = _make_base_client()
    client.handle_api_error(
        {
            "status_code": 500,
            "body": {"errors": [{"code": 500, "message": "boom"}]},
        }
    )

    client.helper.connector_logger.error.assert_called_once()
    client.helper.connector_logger.warning.assert_not_called()


def test_handle_api_error_does_not_crash_on_empty_errors_list():
    """``errors=[]`` must not re-introduce an ``IndexError`` crash."""
    client = _make_base_client()
    # Pre-fix this raised ``IndexError`` on ``errors[0]`` and the
    # secondary crash buried the real 403 / 500 status code.
    client.handle_api_error({"status_code": 403, "body": {"errors": []}})

    client.helper.connector_logger.warning.assert_called_once()


def test_handle_api_error_does_not_crash_on_none_errors():
    """``errors=None`` must also be unpacked defensively."""
    client = _make_base_client()
    client.handle_api_error({"status_code": 403, "body": {"errors": None}})

    client.helper.connector_logger.warning.assert_called_once()


def test_handle_api_error_does_not_crash_on_missing_errors_key():
    """A body without an ``errors`` key (e.g. empty 403) must not crash."""
    client = _make_base_client()
    client.handle_api_error({"status_code": 403, "body": {}})

    client.helper.connector_logger.warning.assert_called_once()


def test_handle_api_error_does_not_crash_on_missing_body():
    """A response without a ``body`` key (e.g. empty 403) must not crash."""
    client = _make_base_client()
    client.handle_api_error({"status_code": 403})

    client.helper.connector_logger.warning.assert_called_once()


def test_handle_api_error_does_not_crash_on_non_dict_first_error():
    """A first error that is a string (rather than dict) must not crash."""
    client = _make_base_client()
    client.handle_api_error({"status_code": 500, "body": {"errors": ["string-error"]}})

    client.helper.connector_logger.error.assert_called_once()


def test_handle_api_error_does_not_crash_on_non_list_errors():
    """A bare-dict ``errors`` value (the SDK forgot to wrap) must not crash.

    Without the ``isinstance(raw_errors, (list, tuple))`` normalisation
    step, ``errors[0]`` would index the dict by the integer ``0`` and
    raise ``KeyError``, defeating the whole point of this defensive
    block. The normalisation falls back to ``[]`` so the warning is
    still emitted with a clean ``"no error message returned"`` fallback
    string and the real status code is still surfaced.
    """
    client = _make_base_client()
    client.handle_api_error(
        {
            "status_code": 403,
            "body": {"errors": {"code": 403, "message": "access denied"}},
        }
    )

    client.helper.connector_logger.warning.assert_called_once()


def test_handle_api_error_normalises_missing_body_in_place():
    """``response["body"]`` must be a dict after the call, even if missing.

    Several API wrappers (``IndicatorsAPI.get_combined_indicator_entities``,
    ``MalwareAPI.query_malware_entities``) call ``handle_api_error`` and
    then immediately index ``response["body"]``. If FalconPy ever
    returns an error envelope without a ``body`` key, those callers
    would crash with ``KeyError: 'body'`` — exactly the secondary
    crash class this PR is supposed to prevent. The handler now
    normalises ``response["body"]`` in place so the downstream read
    is safe under any upstream shape.
    """
    client = _make_base_client()
    response: dict = {"status_code": 403}
    client.handle_api_error(response)
    assert response["body"] == {}


def test_handle_api_error_normalises_none_body_in_place():
    """``response["body"] = None`` must also be normalised to ``{}``."""
    client = _make_base_client()
    response: dict = {"status_code": 403, "body": None}
    client.handle_api_error(response)
    assert response["body"] == {}


def test_handle_api_error_preserves_present_body():
    """A non-empty ``body`` must be preserved unchanged."""
    client = _make_base_client()
    body = {"errors": [{"code": 403, "message": "denied"}], "resources": []}
    response: dict = {"status_code": 403, "body": body}
    client.handle_api_error(response)
    assert response["body"] is body

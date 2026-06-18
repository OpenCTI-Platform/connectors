from queue import Queue
from unittest.mock import MagicMock

import pytest
import titan_client
from intel471.streams.core.base import Intel471Stream

# Real exception classes are used so `except client_wrapper.auth_exceptions` works.
UnauthorizedException = titan_client.exceptions.UnauthorizedException
ForbiddenException = titan_client.exceptions.ForbiddenException


class _ReportStream(Intel471Stream):
    """
    Minimal concrete stream that bypasses cursor/offset state handling (which would
    otherwise block on the helper-state queues) so the API call can be exercised.
    """

    label = "test_reports"
    group_label = "reports"
    api_payload_objects_key = "reports"
    api_class_name = "ReportsApi"
    api_method_name = "get_reports_test_stream"

    def _get_cursor(self):
        return None

    def _get_api_kwargs(self, cursor):
        return {}

    def _get_offsets(self):
        return [None]


def _auth_error(exc_class, body):
    exc = exc_class(status=getattr(exc_class, "status", None), reason="auth")
    exc.body = body
    return exc


def _build_stream(exc):
    """Return a stream whose single API call raises `exc`, plus its mocked helper."""
    client_wrapper = MagicMock()
    client_wrapper.backend_name = "verity471"
    client_wrapper.auth_exceptions = (UnauthorizedException, ForbiddenException)
    api_instance = client_wrapper.module.ReportsApi.return_value
    api_instance.get_reports_test_stream.side_effect = exc
    helper = MagicMock()
    stream = _ReportStream(client_wrapper, helper, Queue(), Queue())
    return stream, helper


def test_unentitled_report_type_is_skipped_with_warning():
    """
    Case 1a: 401 "... not in users access claims." is an expected per-report-type
    entitlement gap. The stream must yield nothing, warn once, and NOT propagate.
    """
    exc = _auth_error(
        UnauthorizedException, "Some(geopol_report) not in users access claims."
    )
    stream, helper = _build_stream(exc)

    assert list(stream.get_bundles()) == []
    assert helper.log_warning.call_count == 1
    helper.log_error.assert_not_called()


def test_unentitled_report_type_warns_once_then_debug():
    """The entitlement gap is permanent, so subsequent runs demote to debug."""
    exc = _auth_error(
        UnauthorizedException, "Some(geopol_report) not in users access claims."
    )
    stream, helper = _build_stream(exc)

    assert list(stream.get_bundles()) == []
    assert list(stream.get_bundles()) == []

    assert helper.log_warning.call_count == 1
    assert helper.log_debug.call_count == 1


@pytest.mark.parametrize(
    "exc_class, body",
    [
        # 1b: no report claims at all (whole reports category)
        pytest.param(
            ForbiddenException,
            "User does not have any report related claims.",
            id="no-report-claims",
        ),
        # 2: Reports API not added to the App (Kong ACL)
        pytest.param(
            ForbiddenException, "You cannot consume this service", id="not-on-app"
        ),
        # 3: bad credentials (Kong gateway), affects everything
        pytest.param(UnauthorizedException, "Unauthorized", id="bad-credentials"),
    ],
)
def test_other_auth_errors_are_reraised(exc_class, body):
    """
    Cases 1b / 2 / 3 each mean a whole stream/category cannot run, so they must stay
    loud (propagate) rather than being silently skipped.
    """
    exc = _auth_error(exc_class, body)
    stream, helper = _build_stream(exc)

    with pytest.raises(exc_class):
        list(stream.get_bundles())
    helper.log_warning.assert_not_called()


@pytest.mark.parametrize(
    "body, expected",
    [
        pytest.param("foo not in users access claims.", True, id="body-match"),
        pytest.param("User does not have any report related claims.", False, id="1b"),
        pytest.param("You cannot consume this service", False, id="2"),
        pytest.param("Unauthorized", False, id="3"),
    ],
)
def test_is_unentitled_report_type(body, expected):
    """The discriminator matches only the case-1a 'access claims' signature."""
    stream, _ = _build_stream(None)
    exc = _auth_error(UnauthorizedException, body)
    assert stream._is_unentitled_report_type(exc) is expected

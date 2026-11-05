from queue import Queue
from unittest.mock import MagicMock

import pytest
import titan_client
from intel471.common import coerce_epoch_millis
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


class _StateStream(Intel471Stream):
    """
    Minimal concrete stream whose helper-state access is served from an in-memory
    dict, so `_get_stored_initial_history` can be exercised without the queue-based
    state handler that runs in the connector.
    """

    label = "test_state"
    group_label = "indicators"
    api_payload_objects_key = "indicators"
    api_class_name = "IndicatorsApi"
    api_method_name = "indicators_stream_get"

    def _get_api_kwargs(self, cursor):
        return {}


def _build_state_stream(state, initial_history):
    stream = _StateStream(
        MagicMock(), MagicMock(), Queue(), Queue(), initial_history=initial_history
    )
    stream._get_state = lambda key: state.get(key)
    stream._set_state = lambda key, value: state.__setitem__(key, value)
    return stream


INITIAL_HISTORY_MILLIS = 1696156471000  # 2023-10-01


def test_stored_initial_history_is_seeded_from_config_when_absent():
    """First run pins the configured initial history in state."""
    state = {}
    stream = _build_state_stream(state, INITIAL_HISTORY_MILLIS)

    assert stream._get_stored_initial_history("key") == INITIAL_HISTORY_MILLIS
    assert state["key"] == INITIAL_HISTORY_MILLIS


def test_stored_initial_history_in_milliseconds_is_left_alone():
    """A value already in milliseconds is returned untouched and not rewritten."""
    state = {"key": INITIAL_HISTORY_MILLIS}
    stream = _build_state_stream(state, 0)

    assert stream._get_stored_initial_history("key") == INITIAL_HISTORY_MILLIS
    assert state["key"] == INITIAL_HISTORY_MILLIS
    stream.helper.log_warning.assert_not_called()


def test_stored_initial_history_in_seconds_is_repaired():
    """
    A value persisted in epoch seconds (by a version that took the config as-is)
    would be read as a 1970 date and re-ingest the whole history, so it is converted
    and written back once, with a warning.
    """
    state = {"key": INITIAL_HISTORY_MILLIS // 1000}
    stream = _build_state_stream(state, 0)

    assert stream._get_stored_initial_history("key") == INITIAL_HISTORY_MILLIS
    assert state["key"] == INITIAL_HISTORY_MILLIS
    assert stream.helper.log_warning.call_count == 1


def test_stored_initial_history_is_kept_when_neither_unit():
    """
    A stored value that is plausible as neither unit is left as-is: the run must not
    fail mid-schedule over state the connector cannot interpret.
    """
    state = {"key": 12345}
    stream = _build_state_stream(state, 0)

    assert stream._get_stored_initial_history("key") == 12345
    assert state["key"] == 12345


def test_zero_config_pins_current_time_not_zero():
    """
    A config value of `0` means "no initial history", which `__init__` resolves to
    the connector's start date. It is that timestamp which gets pinned in state --
    never `0`, which the API would take at face value and answer with the whole
    history. This invariant is why `_get_stored_initial_history` can treat a falsy
    stored value as absent: nothing ever writes `0`.
    """
    state = {}
    stream = _build_state_stream(state, 0)

    pinned = stream._get_stored_initial_history("key")

    assert pinned != 0
    assert pinned == stream.initial_history
    assert state["key"] == pinned
    # Returned unchanged only for a plausible millisecond timestamp.
    assert coerce_epoch_millis(pinned) == pinned


def test_stored_zero_is_reseeded_rather_than_sent_to_the_api():
    """
    Nothing writes `0` to state, but if one ever got there (a hand-edited connector
    state, say) it must not be handed to the API, which would read it as 1970 and
    answer with the whole history. Treating a falsy stored value as absent re-seeds
    it with a usable timestamp instead -- the repair branch cannot help here, since
    `0` is plausible as neither seconds nor milliseconds.
    """
    state = {"key": 0}
    stream = _build_state_stream(state, INITIAL_HISTORY_MILLIS)

    assert stream._get_stored_initial_history("key") == INITIAL_HISTORY_MILLIS
    assert state["key"] == INITIAL_HISTORY_MILLIS

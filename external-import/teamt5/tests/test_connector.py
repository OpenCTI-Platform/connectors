"""Unit tests for ``teamt5_connector.connector.TeamT5Connector``.

Pins the cursor-advance / log-branch contract on
``TeamT5Connector.process_message``:

* a clean run (no aborted handler, no partial push) advances the
  persisted ``last_run`` state;
* a partial-failure run (any handler aborted OR partial push) holds
  ``last_run`` at the previous value so the next scheduled run
  retries the unprocessed window;
* an aborted handler with no retrieved refs logs an explicit
  retry-warning rather than the misleading "No new ... found"
  info line — pins the Copilot review thread on
  ``connector.py:122``.
"""

from types import SimpleNamespace
from unittest.mock import MagicMock, Mock, patch

import pytest
from connectors_sdk import (
    Criticity,
    ErrorStore,
    ProviderApiAuthenticationError,
    ProviderApiRateLimitError,
    ProviderApiServerError,
    ProviderApiTimeoutError,
)
from teamt5_connector.connector import TeamT5Connector


def _make_connector(handler_aborted=False, retrieved_refs=None):
    """Build a connector with stub handlers we can drive deterministically.

    The connector's ``__init__`` instantiates ``Teamt5Client`` (which
    would try to authenticate against the upstream API) and the two
    real handlers. We side-step both by constructing the connector
    via ``__new__`` and assigning the attributes ``process_message``
    actually reads.
    """
    helper = Mock()
    helper.connector_logger = Mock()
    helper.connect_id = "connector-id"
    helper.connect_name = "TeamT5"
    helper.get_state.return_value = {"last_run": "2026-05-22T10:00:00"}

    work = Mock()
    work.initiate_work.return_value = "work--abc"
    helper.api.work = work

    connector = TeamT5Connector.__new__(TeamT5Connector)
    connector.helper = helper
    connector.config = SimpleNamespace(
        connector=SimpleNamespace(name="TeamT5", duration_period=3600),
        teamt5=SimpleNamespace(first_run_retrieval_timestamp=0),
    )

    report_handler = MagicMock()
    report_handler.name = "Report"
    report_handler.aborted = handler_aborted
    report_handler.partial_push = False
    report_handler.retrieve_bundle_references.return_value = retrieved_refs or []
    report_handler.push_objects.return_value = 0

    indicator_handler = MagicMock()
    indicator_handler.name = "Indicator Bundle"
    indicator_handler.aborted = False
    indicator_handler.partial_push = False
    indicator_handler.retrieve_bundle_references.return_value = []
    indicator_handler.push_objects.return_value = 0

    connector.report_handler = report_handler
    connector.indicator_bundle_handler = indicator_handler
    return connector, helper, report_handler, indicator_handler


class TestProcessMessageNoNewItemsLogBranching:
    """The empty-listing log branches on ``handler.aborted``.

    Pins the Copilot review thread on ``connector.py:122``: the
    previous shape always logged "No new <handler>s found" when the
    listing returned no refs, even when the listing actually FAILED
    after ``_MAX_PAGE_FAILURES`` consecutive failed pages. That was
    misleading — the run did not "find no new items", it failed to
    retrieve them — and it hid the actionable retry-on-next-cycle
    behaviour from the operator. The new branch logs a dedicated
    warning when ``handler.aborted`` is True, surfacing the
    failure, the held-cursor consequence, and the retry-on-next-cycle
    contract together.
    """

    def test_logs_no_new_items_when_listing_truly_empty(self):
        # ``report_handler`` is unpacked from ``_make_connector`` but
        # not read by this test (it asserts against the helper's log
        # calls instead). Discard the slot with ``_`` to keep flake8
        # F841 happy.
        connector, helper, _, _ = _make_connector(
            handler_aborted=False, retrieved_refs=[]
        )

        with patch("teamt5_connector.connector.datetime") as fake_datetime:
            fake_datetime.now.return_value = SimpleNamespace(
                isoformat=lambda timespec=None: "2026-05-22T11:00:00"
            )
            fake_datetime.fromisoformat = lambda s: SimpleNamespace(
                timestamp=lambda: 1700000000.0
            )
            fake_datetime.fromtimestamp = lambda ts: f"<{ts}>"
            connector.process_message()

        # Mixture of info / warning calls — assert the "No new" info
        # message fired AND no retrieval-aborted warning fired for the
        # report handler.
        info_messages = [
            args[0] if args else kwargs.get("msg")
            for args, kwargs in (
                (call.args, call.kwargs)
                for call in helper.connector_logger.info.call_args_list
            )
        ]
        assert any(
            "No new Reports found" in (msg or "") for msg in info_messages
        ), f"expected 'No new Reports found' info log; got: {info_messages}"
        warning_messages = [
            args[0] if args else kwargs.get("msg")
            for args, kwargs in (
                (call.args, call.kwargs)
                for call in helper.connector_logger.warning.call_args_list
            )
        ]
        assert not any(
            "Report retrieval aborted" in (msg or "") for msg in warning_messages
        ), f"unexpected aborted warning on clean run: {warning_messages}"

    def test_logs_aborted_warning_when_handler_aborted_with_no_refs(self):
        # Same ``_`` discard as the sibling clean-run test above.
        connector, helper, _, _ = _make_connector(
            handler_aborted=True, retrieved_refs=[]
        )

        with patch("teamt5_connector.connector.datetime") as fake_datetime:
            fake_datetime.now.return_value = SimpleNamespace(
                isoformat=lambda timespec=None: "2026-05-22T11:00:00"
            )
            fake_datetime.fromisoformat = lambda s: SimpleNamespace(
                timestamp=lambda: 1700000000.0
            )
            fake_datetime.fromtimestamp = lambda ts: f"<{ts}>"
            connector.process_message()

        # The dedicated aborted-warning fired and the misleading "No
        # new ... found" did NOT.
        warning_messages = [
            args[0] if args else kwargs.get("msg")
            for args, kwargs in (
                (call.args, call.kwargs)
                for call in helper.connector_logger.warning.call_args_list
            )
        ]
        assert any(
            "Report retrieval aborted" in (msg or "") for msg in warning_messages
        ), f"expected aborted-retrieval warning; got: {warning_messages}"

        info_messages = [
            args[0] if args else kwargs.get("msg")
            for args, kwargs in (
                (call.args, call.kwargs)
                for call in helper.connector_logger.info.call_args_list
            )
        ]
        assert not any(
            "No new Reports found" in (msg or "") for msg in info_messages
        ), (
            "must NOT log 'No new Reports found' when the handler aborted; "
            f"got: {info_messages}"
        )


class TestProcessMessageCursorAdvance:
    """The persisted ``last_run`` cursor only advances on a clean run.

    A handler that aborted (or pushed only some of its refs) must
    leave ``last_run`` at the previous value so the next scheduled
    cycle retries the unprocessed window. Otherwise the connector
    silently skips every TeamT5 item between the frozen cursor and
    the failed bundle.
    """

    def test_aborted_handler_holds_cursor(self):
        connector, helper, _, _ = _make_connector(
            handler_aborted=True, retrieved_refs=[]
        )

        with patch("teamt5_connector.connector.datetime") as fake_datetime:
            fake_datetime.now.return_value = SimpleNamespace(
                isoformat=lambda timespec=None: "2026-05-22T11:00:00"
            )
            fake_datetime.fromisoformat = lambda s: SimpleNamespace(
                timestamp=lambda: 1700000000.0
            )
            fake_datetime.fromtimestamp = lambda ts: f"<{ts}>"
            connector.process_message()

        # ``set_state`` is what advances the cursor; the aborted run
        # must skip that call entirely so the previous ``last_run``
        # value persists.
        helper.set_state.assert_not_called()

    def test_clean_run_advances_cursor(self):
        connector, helper, _, _ = _make_connector(
            handler_aborted=False, retrieved_refs=[]
        )

        with patch("teamt5_connector.connector.datetime") as fake_datetime:
            fake_datetime.now.return_value = SimpleNamespace(
                isoformat=lambda timespec=None: "2026-05-22T11:00:00"
            )
            fake_datetime.fromisoformat = lambda s: SimpleNamespace(
                timestamp=lambda: 1700000000.0
            )
            fake_datetime.fromtimestamp = lambda ts: f"<{ts}>"
            connector.process_message()

        helper.set_state.assert_called_once()
        new_state = helper.set_state.call_args.args[0]
        assert new_state["last_run"] == "2026-05-22T11:00:00"


def _run(connector):
    """Run ``process_message`` with the same frozen clock as the tests above."""
    with patch("teamt5_connector.connector.datetime") as fake_datetime:
        fake_datetime.now.return_value = SimpleNamespace(
            isoformat=lambda timespec=None: "2026-05-22T11:00:00"
        )
        fake_datetime.fromisoformat = lambda s: SimpleNamespace(
            timestamp=lambda: 1700000000.0
        )
        fake_datetime.fromtimestamp = lambda ts: f"<{ts}>"
        return connector.process_message()


class TestReturnRunErrorList:
    def test_no_error_returns_empty_list(self):
        assert TeamT5Connector._return_run_error_list() == []

    def test_run_error_comes_first_then_recorded_errors(self, empty_error_store):
        empty_error_store.record_error(ProviderApiServerError("page 1"))
        empty_error_store.record_error(ProviderApiTimeoutError("page 2"))

        errors = TeamT5Connector._return_run_error_list(
            ProviderApiAuthenticationError("token")
        )

        assert errors == [
            {
                "code": "api.authentication",
                "message": "token",
                "criticity": int(Criticity.CRITICAL),
            },
            {
                "code": "api.server",
                "message": "page 1",
                "criticity": int(Criticity.ERROR),
            },
            {
                "code": "api.timeout",
                "message": "page 2",
                "criticity": int(Criticity.ERROR),
            },
        ]


class TestCloseWorkInError:
    def test_no_open_work_is_a_noop(self, empty_error_store):
        connector, helper, _, _ = _make_connector()

        connector._close_work_in_error(None, RuntimeError("boom"))

        helper.api.work.to_processed.assert_not_called()
        assert empty_error_store.get_errors() == []

    def test_open_work_is_closed_in_error(self, empty_error_store):
        connector, helper, _, _ = _make_connector()

        connector._close_work_in_error("work--abc", RuntimeError("boom"))

        helper.api.work.to_processed.assert_called_once_with(
            "work--abc", "Unhandled exception: boom", in_error=True
        )
        assert empty_error_store.get_errors() == []

    def test_failure_to_close_is_recorded_as_octi_unreachable(self, empty_error_store):
        connector, helper, _, _ = _make_connector()
        helper.api.work.to_processed.side_effect = ConnectionError("platform down")

        connector._close_work_in_error("work--abc", RuntimeError("boom"))

        errors = empty_error_store.get_errors()
        assert [type(error).code for error in errors] == ["octi.unreachable"]
        assert "work--abc" in str(errors[0])
        assert "platform down" in str(errors[0])
        helper.connector_logger.error.assert_called_once()


class TestProcessMessageReturnsErrors:
    """``process_message`` returns the errors of the run to pycti."""

    def test_clean_run_returns_empty_list(self):
        connector, _, _, _ = _make_connector()

        assert _run(connector) == []

    def test_errors_recorded_during_the_run_are_returned(self):
        connector, helper, report_handler, _ = _make_connector()

        def failed_listing(last_run_timestamp):
            ErrorStore().record_error(ProviderApiRateLimitError("throttled"))
            return []

        report_handler.retrieve_bundle_references.side_effect = failed_listing

        errors = _run(connector)

        assert [error["code"] for error in errors] == ["api.rate_limit"]
        # The flow is unchanged: a clean listing still advances the cursor
        helper.set_state.assert_called_once()

    def test_standard_error_stopping_the_run_is_returned_first(self):
        connector, helper, report_handler, _ = _make_connector()

        def failed_run(last_run_timestamp):
            ErrorStore().record_error(ProviderApiServerError("page 1"))
            raise ProviderApiAuthenticationError("token rejected")

        report_handler.retrieve_bundle_references.side_effect = failed_run

        errors = _run(connector)

        assert errors == [
            {
                "code": "api.authentication",
                "message": "token rejected",
                "criticity": int(Criticity.CRITICAL),
            },
            {
                "code": "api.server",
                "message": "page 1",
                "criticity": int(Criticity.ERROR),
            },
        ]
        helper.set_state.assert_not_called()
        helper.connector_logger.error.assert_called_once()

    def test_unexpected_exception_is_returned_as_unknown(self):
        connector, helper, report_handler, _ = _make_connector()
        report_handler.retrieve_bundle_references.side_effect = RuntimeError("boom")

        errors = _run(connector)

        assert errors == [
            {
                "code": "other.unknown",
                "message": "boom",
                "criticity": int(Criticity.CRITICAL),
            }
        ]
        helper.set_state.assert_not_called()

    def test_errors_of_the_previous_run_are_not_returned_again(self, empty_error_store):
        connector, _, _, _ = _make_connector()
        empty_error_store.record_error(ProviderApiServerError("previous run"))

        assert _run(connector) == []

    def test_failure_to_close_work_is_returned_after_the_run_error(self):
        connector, helper, report_handler, _ = _make_connector(
            retrieved_refs=[{"stix_url": "https://example.com/bundle"}]
        )
        report_handler.push_objects.side_effect = RuntimeError("push failed")
        helper.api.work.to_processed.side_effect = ConnectionError("platform down")

        errors = _run(connector)

        assert [error["code"] for error in errors] == [
            "other.unknown",
            "octi.unreachable",
        ]
        helper.api.work.to_processed.assert_called_once_with(
            "work--abc", "Unhandled exception: push failed", in_error=True
        )

    def test_stopping_the_connector_reports_nothing(self):
        connector, _, report_handler, _ = _make_connector()
        report_handler.retrieve_bundle_references.side_effect = KeyboardInterrupt

        with pytest.raises(SystemExit) as info:
            _run(connector)

        assert info.value.code == 0

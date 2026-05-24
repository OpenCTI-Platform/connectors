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

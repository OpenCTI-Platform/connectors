from unittest.mock import MagicMock

import pytest
from src.connector.sekoia import SekoiaConnector


def _build_connector():
    """Build a SekoiaConnector without running its heavy ``__init__``.

    Only the attributes read by ``process_message`` are wired up so that the
    work lifecycle (initiate_work / _run / to_processed) is the only code path
    that actually executes.
    """
    connector = SekoiaConnector.__new__(SekoiaConnector)

    connector.helper = MagicMock()
    connector.helper.api.work.initiate_work.return_value = "work-1"
    connector.helper.get_state.return_value = {"last_cursor": "cur0"}

    # ``process_message`` always evaluates ``self.generate_first_cursor()`` as
    # the default of ``state.get(...)``, so stub it out to avoid touching the
    # un-initialised Sekoia config attributes.
    connector.generate_first_cursor = MagicMock(return_value="cur0")

    # ``_run`` is the heavy collaborator; replace it so only the work
    # lifecycle lines run.
    connector._run = MagicMock(return_value="cur1")

    return connector


def test_process_message_success_closes_work_without_error():
    connector = _build_connector()

    connector.process_message()

    initiate_work = connector.helper.api.work.initiate_work
    initiate_work.assert_called_once()
    assert initiate_work.call_args.kwargs["is_multipart"] is True

    connector._run.assert_called_once_with("cur0", "work-1")

    to_processed = connector.helper.api.work.to_processed
    to_processed.assert_called_once()
    assert to_processed.call_args.args[0] == "work-1"
    assert to_processed.call_args.kwargs["in_error"] is False


def test_process_message_error_closes_work_in_error():
    connector = _build_connector()
    connector._run = MagicMock(side_effect=Exception("boom"))

    # The exception is swallowed by the except/finally block.
    connector.process_message()

    initiate_work = connector.helper.api.work.initiate_work
    initiate_work.assert_called_once()
    assert initiate_work.call_args.kwargs["is_multipart"] is True

    to_processed = connector.helper.api.work.to_processed
    to_processed.assert_called_once()
    assert to_processed.call_args.args[0] == "work-1"
    assert to_processed.call_args.kwargs["in_error"] is True


def test_process_message_interrupt_closes_work_in_error_and_exits():
    connector = _build_connector()
    connector._run = MagicMock(side_effect=KeyboardInterrupt())

    with pytest.raises(SystemExit):
        connector.process_message()

    to_processed = connector.helper.api.work.to_processed
    to_processed.assert_called_once_with("work-1", "Connector stop", in_error=True)

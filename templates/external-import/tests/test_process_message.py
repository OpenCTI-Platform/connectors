from unittest.mock import MagicMock

from connector import TemplateConnector


def _make_connector():
    """Build a TemplateConnector without running __init__ (which needs a live helper)."""
    connector = TemplateConnector.__new__(TemplateConnector)
    connector.helper = MagicMock()
    connector.helper.get_state.return_value = None
    connector.helper.api.work.initiate_work.return_value = "work-1"
    connector.config = MagicMock()
    return connector


def test_process_message_initiates_multipart_and_closes_work():
    connector = _make_connector()
    connector._collect_intelligence = MagicMock(return_value=[])

    connector.process_message()

    initiate = connector.helper.api.work.initiate_work
    initiate.assert_called_once()
    # The work must be opened as multipart so it only completes on to_processed.
    assert initiate.call_args.kwargs.get("is_multipart") is True

    to_processed = connector.helper.api.work.to_processed
    to_processed.assert_called_once()
    assert to_processed.call_args.kwargs.get("in_error") is False


def test_process_message_marks_work_in_error_on_failure():
    connector = _make_connector()
    connector._collect_intelligence = MagicMock(side_effect=RuntimeError("boom"))

    connector.process_message()

    to_processed = connector.helper.api.work.to_processed
    to_processed.assert_called_once()
    assert to_processed.call_args.kwargs.get("in_error") is True

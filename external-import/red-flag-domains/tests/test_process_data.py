from unittest.mock import MagicMock

from red_flag_domains import RedFlagDomainImportConnector


def _make_connector():
    """Build the connector without running __init__ (which needs a live helper)."""
    connector = RedFlagDomainImportConnector.__new__(RedFlagDomainImportConnector)
    connector.helper = MagicMock()
    connector.helper.get_state.return_value = None
    connector.helper.api.work.initiate_work.return_value = "work-1"
    connector.config = MagicMock()
    connector.author = MagicMock()
    connector.api_url = "https://dl.red.flag.domains/daily/"
    return connector


def test_process_data_initiates_multipart_and_closes_work():
    connector = _make_connector()
    # Empty domain list keeps the test off the network and away from stix2
    # object building while still exercising the full work lifecycle.
    connector.get_domains = MagicMock(return_value=[])

    connector.process_data()

    initiate = connector.helper.api.work.initiate_work
    initiate.assert_called_once()
    # The work must be opened as multipart so it only completes on to_processed.
    assert initiate.call_args.kwargs.get("is_multipart") is True

    to_processed = connector.helper.api.work.to_processed
    to_processed.assert_called_once()
    assert to_processed.call_args.kwargs.get("in_error") is False


def test_process_data_marks_work_in_error_on_failure():
    connector = _make_connector()
    connector.get_domains = MagicMock(side_effect=RuntimeError("boom"))

    connector.process_data()

    to_processed = connector.helper.api.work.to_processed
    to_processed.assert_called_once()
    assert to_processed.call_args.kwargs.get("in_error") is True

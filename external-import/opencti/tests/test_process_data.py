from unittest.mock import MagicMock

from connector import OpenCTI


def _make_connector(urls=None, remove_creator=False):
    """Build an OpenCTI connector without running __init__ (which needs config)."""
    connector = OpenCTI.__new__(OpenCTI)
    connector.helper = MagicMock()
    connector.helper.get_state.return_value = None
    connector.helper.api.work.initiate_work.return_value = "work-1"
    connector.urls = urls if urls is not None else []
    connector.remove_creator = remove_creator
    connector.interval = 7 * 24 * 60 * 60
    return connector


def test_process_data_initiates_multipart_and_closes_work():
    connector = _make_connector(
        urls=["https://example.test/sectors.json"], remove_creator=True
    )
    connector.retrieve_data = MagicMock(
        return_value={"objects": [{"id": "a", "created_by_ref": "identity--x"}]}
    )

    connector.process_data()

    initiate = connector.helper.api.work.initiate_work
    initiate.assert_called_once()
    # The work must be opened as multipart so it only completes on to_processed.
    assert initiate.call_args.kwargs.get("is_multipart") is True

    connector.retrieve_data.assert_called_once()
    connector.helper.send_stix2_bundle.assert_called_once()

    to_processed = connector.helper.api.work.to_processed
    to_processed.assert_called_once()
    assert to_processed.call_args.args[0] == "work-1"
    assert to_processed.call_args.kwargs.get("in_error") is False


def test_process_data_per_url_error_still_completes_work():
    connector = _make_connector(urls=["https://example.test/sectors.json"])
    # A single URL failing is logged and swallowed so the run still completes
    # the work successfully (matching the connector's existing behaviour).
    connector.retrieve_data = MagicMock(side_effect=Exception("url boom"))

    connector.process_data()

    to_processed = connector.helper.api.work.to_processed
    to_processed.assert_called_once()
    assert to_processed.call_args.kwargs.get("in_error") is False


def test_process_data_closes_work_in_error_on_failure():
    connector = _make_connector()
    # An exception raised after initiate_work (here from set_state) must still
    # close the multipart work, flagged in_error, instead of leaving it stuck
    # "in-progress" forever.
    connector.helper.set_state.side_effect = RuntimeError("boom")

    connector.process_data()

    to_processed = connector.helper.api.work.to_processed
    to_processed.assert_called_once()
    assert to_processed.call_args.args[0] == "work-1"
    assert to_processed.call_args.kwargs.get("in_error") is True

"""Tests for the work-lifecycle helpers (start/send/finish)."""

from unittest.mock import MagicMock

from connector.util import works


def test_start_work_initiates_and_returns_work_id(helper):
    helper.api.work.initiate_work.return_value = "work-123"

    work_id = works.start_work(helper, MagicMock(), "First Run")

    assert work_id == "work-123"
    helper.api.work.initiate_work.assert_called_once()
    # message is built from the work_name
    args, _ = helper.api.work.initiate_work.call_args
    assert "First Run" in args[1]


def test_send_bundle_creates_and_sends(helper):
    helper.stix2_create_bundle.return_value = "BUNDLE"
    helper.send_stix2_bundle.return_value = ["x", "y"]

    works.send_bundle(helper, MagicMock(), ["obj1", "obj2"], "work-1")

    helper.stix2_create_bundle.assert_called_once_with(["obj1", "obj2"])
    helper.send_stix2_bundle.assert_called_once_with(
        "BUNDLE", work_id="work-1", cleanup_inconsistent_bundle=True
    )


def test_send_bundle_noop_when_bundle_is_none(helper):
    helper.stix2_create_bundle.return_value = None

    works.send_bundle(helper, MagicMock(), [], "work-1")

    helper.send_stix2_bundle.assert_not_called()


def test_finish_work_marks_processed(helper):
    works.finish_work(helper, MagicMock(), "work-1", "First Run")

    helper.api.work.to_processed.assert_called_once()
    args, _ = helper.api.work.to_processed.call_args
    assert args[0] == "work-1"

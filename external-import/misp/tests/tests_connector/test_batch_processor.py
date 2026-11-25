import logging
from unittest.mock import MagicMock, call, patch

import pycti
import pytest
import stix2
from exceptions import MispWorkProcessingError
from utils.batch_processor import BatchProcessor


def _make_identity(name: str) -> stix2.Identity:
    return stix2.Identity(
        id=pycti.Identity.generate_id(name=name, identity_class="organization"),
        name=name,
        identity_class="organization",
    )


@pytest.fixture
def work_manager():
    work_manager = MagicMock()
    work_manager.initiate_work.side_effect = [f"work-{i}" for i in range(1, 10)]
    return work_manager


@pytest.fixture
def batch_processor(work_manager):
    processor = BatchProcessor(
        work_manager=work_manager,
        logger=logging.getLogger("misp"),
        batch_size=10,
        max_retries=2,
        retry_delay=1,
    )
    processor.add_item(_make_identity("entity-1"))
    return processor


def test_flush_sends_batch_on_first_attempt(batch_processor, work_manager):
    with patch("utils.batch_processor.batch_processor.time.sleep") as mock_sleep:
        work_id = batch_processor.flush()

    assert work_id == "work-1"
    work_manager.send_bundle.assert_called_once()
    work_manager.work_to_process.assert_called_once_with(work_id="work-1")
    mock_sleep.assert_not_called()
    assert batch_processor.get_failed_items() == []


def test_flush_retries_a_transient_failure_with_backoff(batch_processor, work_manager):
    work_manager.send_bundle.side_effect = [
        ConnectionError("rabbitmq unreachable"),
        ConnectionError("rabbitmq unreachable"),
        None,
    ]

    with patch("utils.batch_processor.batch_processor.time.sleep") as mock_sleep:
        work_id = batch_processor.flush()

    assert work_id == "work-3"
    assert work_manager.send_bundle.call_count == 3
    assert mock_sleep.call_args_list == [call(1), call(2)]
    assert batch_processor.get_failed_items() == []
    assert batch_processor.get_current_batch_length() == 0


def test_flush_deletes_the_work_of_an_attempt_whose_bundle_was_not_sent(
    batch_processor, work_manager
):
    work_manager.send_bundle.side_effect = [ConnectionError("rabbitmq"), None]

    with patch("utils.batch_processor.batch_processor.time.sleep"):
        batch_processor.flush()

    work_manager.delete_work.assert_called_once_with(work_id="work-1")
    work_manager.work_to_process.assert_called_once_with(work_id="work-2")


def test_flush_marks_the_work_in_error_when_it_cannot_be_marked_for_processing(
    batch_processor, work_manager
):
    work_manager.work_to_process.side_effect = [ConnectionError("opencti"), None, None]

    with patch("utils.batch_processor.batch_processor.time.sleep"):
        batch_processor.flush()

    # The bundle of work-1 was sent: the workers complete it, so it is closed in
    # error rather than deleted.
    work_manager.delete_work.assert_not_called()
    assert work_manager.work_to_process.call_args_list == [
        call(work_id="work-1"),
        call(
            work_id="work-1",
            error_flag=True,
            error_message="Error processing work: Failed to mark work for processing for batch #1: opencti",
        ),
        call(work_id="work-2"),
    ]


def test_flush_raises_after_all_retries(batch_processor, work_manager):
    work_manager.send_bundle.side_effect = ConnectionError("rabbitmq unreachable")

    with (
        patch("utils.batch_processor.batch_processor.time.sleep"),
        pytest.raises(MispWorkProcessingError, match="after 3 attempts"),
    ):
        batch_processor.flush()

    assert work_manager.send_bundle.call_count == 3
    # Every initiated work is deleted, none stays in progress.
    assert work_manager.delete_work.call_args_list == [
        call(work_id="work-1"),
        call(work_id="work-2"),
        call(work_id="work-3"),
    ]
    work_manager.work_to_process.assert_not_called()
    assert len(batch_processor.get_failed_items()) == 1


def test_flush_raises_original_error_when_work_cannot_be_deleted(
    batch_processor, work_manager
):
    batch_processor.max_retries = 0
    work_manager.send_bundle.side_effect = ConnectionError("rabbitmq unreachable")
    work_manager.delete_work.side_effect = ConnectionError("opencti unreachable")

    with pytest.raises(MispWorkProcessingError, match="rabbitmq unreachable"):
        batch_processor.flush()


def test_flush_retries_when_work_initiation_fails(batch_processor, work_manager):
    work_manager.initiate_work.side_effect = [ConnectionError("opencti"), "work-2"]

    with patch("utils.batch_processor.batch_processor.time.sleep"):
        work_id = batch_processor.flush()

    assert work_id == "work-2"
    work_manager.work_to_process.assert_called_once_with(work_id="work-2")

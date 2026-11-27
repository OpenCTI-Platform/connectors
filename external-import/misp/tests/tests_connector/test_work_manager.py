import logging
from unittest.mock import MagicMock, call

from utils.work_manager import WorkManager


def test_process_all_remaining_works_only_closes_works_never_reported():
    helper = MagicMock()
    helper.connect_id = "connector-id"
    helper.api.work.get_connector_works.return_value = [
        # Initiated, never reported by the connector: left open by the run.
        {"id": "work-open", "status": "wait", "processed_time": None},
        # Sent and reported, still being ingested by the workers.
        {
            "id": "work-ingesting",
            "status": "progress",
            "processed_time": "2026-11-25T15:24:36Z",
        },
        {
            "id": "work-done",
            "status": "complete",
            "processed_time": "2026-11-25T15:24:35Z",
        },
    ]
    work_manager = WorkManager(MagicMock(), helper, logging.getLogger("misp"))

    work_manager.process_all_remaining_works(
        error_flag=True, error_message="Batch #6 processing failed"
    )

    assert helper.api.work.to_processed.call_args_list == [
        call(
            work_id="work-open",
            message="Error: Batch #6 processing failed",
            in_error=True,
        )
    ]


def test_delete_work_deletes_the_work_and_forgets_it_as_current():
    helper = MagicMock()
    work_manager = WorkManager(MagicMock(), helper, logging.getLogger("misp"))
    work_manager.set_current_work_id("work-id")

    work_manager.delete_work(work_id="work-id")

    helper.api.work.delete.assert_called_once_with(id="work-id")
    assert work_manager.get_current_work_id() is None

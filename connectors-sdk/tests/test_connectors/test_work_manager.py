# pragma: no cover
# type: ignore
from unittest.mock import MagicMock

import pytest
from connectors_sdk.connectors.external_import._work_manager import (
    WorkManager,
    _Work,
)
from connectors_sdk.logging.sdk_logger import SDKLogger


class TestWork:
    def test_init_subclass(self):
        assert isinstance(WorkManager.logger, SDKLogger)
        assert WorkManager.logger._logger.name == "connectors_sdk.WorkManager"

    def test_init(self, mock_helper: MagicMock):
        work = _Work(mock_helper, "w-1", "test-work")
        assert work.id == "w-1"
        assert work.name == "test-work"
        assert work._closed is False
        assert work._has_sent_bundles is False

    def test_create(self, mock_helper: MagicMock):
        work = _Work.create(mock_helper, "test-work")
        mock_helper.api.work.initiate_work.assert_called_once_with(
            "test-connector-id", "test-work"
        )
        assert work.id == "work-123"
        assert work.name == "test-work"
        assert work._closed is False

    def test_send_bundle(self, mock_helper: MagicMock):
        work = _Work(mock_helper, "w-1", "test-work")
        work.send_bundle(["obj1", "obj2"])
        mock_helper.stix2_create_bundle.assert_called_once_with(["obj1", "obj2"])
        mock_helper.send_stix2_bundle.assert_called_once()
        assert work._has_sent_bundles is True

    def test_send_bundle_forwards_kwargs(self, mock_helper: MagicMock):
        work = _Work(mock_helper, "w-1", "test-work")
        work.send_bundle(["obj"], update=True)
        mock_helper.send_stix2_bundle.assert_called_once_with(
            mock_helper.stix2_create_bundle.return_value,
            work_id="w-1",
            update=True,
        )

    def test_success(self, mock_helper: MagicMock):
        work = _Work(mock_helper, "w-1", "test-work")
        work.success("Done")
        mock_helper.api.work.to_processed.assert_called_once_with("w-1", "Done")
        assert work._closed is True

    def test_fail(self, mock_helper: MagicMock):
        work = _Work(mock_helper, "w-1", "test-work")
        work.fail("Error occurred")
        mock_helper.api.work.to_processed.assert_called_once_with(
            "w-1", "Error occurred", in_error=True
        )
        assert work._closed is True

    def test_delete(self, mock_helper: MagicMock):
        work = _Work(mock_helper, "w-1", "test-work")
        work._delete()
        mock_helper.api.work.delete.assert_called_once_with(id="w-1")
        assert work._closed is True

    def test_to_stix_converts_sdk_objects(self):
        sdk_obj = MagicMock()
        sdk_obj.to_stix2_object.return_value = {"type": "indicator"}
        raw_obj = {"type": "malware"}
        result = _Work._to_stix([sdk_obj, raw_obj])
        assert result == [{"type": "indicator"}, {"type": "malware"}]
        sdk_obj.to_stix2_object.assert_called_once()


class TestWorkManager:
    def test_init(self, mock_helper: MagicMock):
        wm = WorkManager(mock_helper)
        assert wm._current_work is None
        assert wm._active is False

    def test_enter_exit_no_work(self, mock_helper: MagicMock):
        wm = WorkManager(mock_helper)
        with wm:
            assert wm._active is True
        assert wm._active is False
        assert wm._current_work is None

    def test_send_creates_work_and_sends(self, mock_helper: MagicMock):
        wm = WorkManager(mock_helper)
        with wm:
            wm.send(["obj1"], "default")
        mock_helper.api.work.initiate_work.assert_called_once_with(
            "test-connector-id", "default"
        )
        mock_helper.stix2_create_bundle.assert_called_once()
        mock_helper.api.work.to_processed.assert_called_once_with(
            "work-123", "Work completed successfully"
        )

    def test_send_empty_list_is_noop(self, mock_helper: MagicMock):
        wm = WorkManager(mock_helper)
        with wm:
            wm.send([], "default")
        mock_helper.api.work.initiate_work.assert_not_called()

    def test_send_outside_context_raises(self, mock_helper: MagicMock):
        wm = WorkManager(mock_helper)
        with pytest.raises(RuntimeError, match="inside a 'with' block"):
            wm.send(["obj"], "default")

    def test_send_same_name_reuses_work(self, mock_helper: MagicMock):
        wm = WorkManager(mock_helper)
        with wm:
            wm.send(["obj1"], "default")
            wm.send(["obj2"], "default")
        # Only one work initiated
        assert mock_helper.api.work.initiate_work.call_count == 1
        # Two bundles sent
        assert mock_helper.send_stix2_bundle.call_count == 2

    def test_send_different_name_closes_previous(self, mock_helper: MagicMock):
        wm = WorkManager(mock_helper)
        with wm:
            wm.send(["obj1"], "default")  # creates "default" work
            wm.send(["obj2"], "other")  # closes "default", creates "other"
        # Two works initiated
        assert mock_helper.api.work.initiate_work.call_count == 2
        # to_processed called: once for closing "default", once for closing "other" on exit
        assert mock_helper.api.work.to_processed.call_count == 2

    def test_exit_deletes_work_with_no_bundles(self, mock_helper: MagicMock):
        """Work created but no bundles sent → deleted on exit."""
        mock_helper.send_stix2_bundle.return_value = []
        wm = WorkManager(mock_helper)
        with wm:
            wm.send(["obj1"], "default")
        # _has_sent_bundles is set to True regardless of return, so this tests
        # the normal success path
        # Let's test the no-bundle path differently: init a work but don't send
        mock_helper.reset_mock()
        wm2 = WorkManager(mock_helper)
        # Manually test: enter, init work, but don't send anything
        wm2.__enter__()
        wm2._current_work = _Work(mock_helper, "w-empty", "default")
        wm2.__exit__(None, None, None)
        mock_helper.api.work.delete.assert_called_once_with(id="w-empty")

    def test_exit_on_exception_marks_failed(self, mock_helper: MagicMock):
        wm = WorkManager(mock_helper)
        try:
            with wm:
                wm.send(["obj"], "default")
                raise ValueError("boom")
        except ValueError:
            pass
        mock_helper.api.work.to_processed.assert_called_once_with(
            "work-123", "Work failed with error: boom", in_error=True
        )

    def test_exit_already_closed_work_is_noop(self, mock_helper: MagicMock):
        wm = WorkManager(mock_helper)
        wm.__enter__()
        work = _Work(mock_helper, "w-1", "default")
        work._closed = True
        wm._current_work = work
        wm.__exit__(None, None, None)
        mock_helper.api.work.to_processed.assert_not_called()
        mock_helper.api.work.delete.assert_not_called()

    def test_close_current_work_no_bundles_deletes(self, mock_helper: MagicMock):
        wm = WorkManager(mock_helper)
        wm._current_work = _Work(mock_helper, "w-1", "default")
        wm._close_current_work()
        mock_helper.api.work.delete.assert_called_once_with(id="w-1")

    def test_close_current_work_with_bundles_succeeds(self, mock_helper: MagicMock):
        wm = WorkManager(mock_helper)
        work = _Work(mock_helper, "w-1", "default")
        work._has_sent_bundles = True
        wm._current_work = work
        wm._close_current_work()
        mock_helper.api.work.to_processed.assert_called_once_with(
            "w-1", "Work completed successfully"
        )

    def test_close_current_work_none_is_noop(self, mock_helper: MagicMock):
        wm = WorkManager(mock_helper)
        wm._close_current_work()  # no exception

    def test_send_forwards_kwargs_to_send_bundle(self, mock_helper: MagicMock):
        wm = WorkManager(mock_helper)
        with wm:
            wm.send(["obj"], "default", update=True, entities_types=["Indicator"])
        mock_helper.send_stix2_bundle.assert_called_once_with(
            mock_helper.stix2_create_bundle.return_value,
            work_id="work-123",
            update=True,
            entities_types=["Indicator"],
        )

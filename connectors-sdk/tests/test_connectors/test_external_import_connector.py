# pragma: no cover
# type: ignore
from datetime import datetime, timezone
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from connectors_sdk.connectors.external_import.base_data_processor import (
    BaseDataProcessor,
)
from connectors_sdk.connectors.external_import.external_import_connector import (
    ExternalImportConnector,
)
from connectors_sdk.logging.logger import Logger

PATCH_HELPER = "connectors_sdk.connectors.external_import.external_import_connector.OpenCTIConnectorHelper"


class DummyProcessor(BaseDataProcessor):
    work_name = "Dummy Import"

    def collect(self) -> list[str]:
        return ["raw"]

    def transform(self, data: Any) -> list[Any]:
        return [f"stix-{d}" for d in data]


class FailingProcessor(BaseDataProcessor):
    work_name = "Failing Import"

    def collect(self) -> Any:
        raise RuntimeError("collect failed")

    def transform(self, data: Any) -> list[Any]:
        return []


def _make_helper_mock() -> MagicMock:
    helper = MagicMock()
    helper.connect_id = "test-connector-id"
    helper.connector_logger = MagicMock()
    helper.api.work.initiate_work.return_value = "w-1"
    helper.api.work.to_processed.return_value = None
    helper.api.work.delete.return_value = None
    helper.stix2_create_bundle.return_value = '{"type": "bundle"}'
    helper.send_stix2_bundle.return_value = ["b1"]
    helper.get_state.return_value = {}
    helper.set_state.return_value = None
    helper.force_ping.return_value = None
    helper.schedule_process.return_value = None
    return helper


def _make_state_mock() -> MagicMock:
    state = MagicMock()
    state.last_run = None
    return state


def _make_logger_mock() -> MagicMock:
    logger = MagicMock()
    logger.error.return_value = None
    return logger


class TestExternalImportConnector:
    def test_init_subclass(self):
        class MyConnector(ExternalImportConnector):
            pass

        assert isinstance(MyConnector.logger, Logger)
        assert MyConnector.logger._logger.name.endswith(".MyConnector")

    def test_init(self, mock_settings: MagicMock):
        proc = DummyProcessor()
        connector = ExternalImportConnector(
            settings=mock_settings, data_processors=[proc]
        )
        assert connector.settings is mock_settings
        assert connector.data_processors == [proc]

    def test_init_empty_processors_raises(self, mock_settings: MagicMock):
        with pytest.raises(ValueError, match="At least one BaseDataProcessor"):
            ExternalImportConnector(settings=mock_settings, data_processors=[])

    @patch(PATCH_HELPER)
    def test_init_dependencies_wires_up_components(
        self, mock_helper_cls: MagicMock, mock_settings: MagicMock
    ):
        mock_helper_cls.return_value = _make_helper_mock()

        proc = DummyProcessor()
        connector = ExternalImportConnector(
            settings=mock_settings, data_processors=[proc]
        )
        connector._init_dependencies()

        assert connector.logger is not None
        assert connector.state is not None
        assert proc.settings is mock_settings
        assert proc.logger is not None
        assert proc.state is connector.state
        assert proc.work_manager is not None

    @patch(PATCH_HELPER)
    def test_init_dependencies_custom_state(
        self, mock_helper_cls: MagicMock, mock_settings: MagicMock
    ):
        mock_helper_cls.return_value = _make_helper_mock()

        custom_state = MagicMock()
        proc = DummyProcessor()
        connector = ExternalImportConnector(
            settings=mock_settings, data_processors=[proc], state=custom_state
        )
        connector._init_dependencies()

        assert connector.state is custom_state
        assert proc.state is custom_state

    @patch(PATCH_HELPER)
    def test_callback_success(
        self, mock_helper_cls: MagicMock, mock_settings: MagicMock
    ):
        helper = _make_helper_mock()
        mock_helper_cls.return_value = helper
        state = _make_state_mock()

        proc = DummyProcessor()
        connector = ExternalImportConnector(
            settings=mock_settings, data_processors=[proc], state=state
        )
        connector._init_dependencies()
        connector.callback()

        state.load.assert_called_once_with(force=True)
        state.save.assert_called_once()
        assert state.last_run is not None

    @patch(PATCH_HELPER)
    def test_callback_with_last_run(
        self, mock_helper_cls: MagicMock, mock_settings: MagicMock
    ):
        helper = _make_helper_mock()
        mock_helper_cls.return_value = helper
        state = _make_state_mock()
        state.last_run = datetime(2025, 1, 1, tzinfo=timezone.utc)

        proc = DummyProcessor()
        connector = ExternalImportConnector(
            settings=mock_settings, data_processors=[proc], state=state
        )
        connector._init_dependencies()
        connector.callback()

        state.save.assert_called_once()

    @patch(PATCH_HELPER)
    def test_callback_exception_is_logged(
        self, mock_helper_cls: MagicMock, mock_settings: MagicMock
    ):
        helper = _make_helper_mock()
        mock_helper_cls.return_value = helper
        state = _make_state_mock()

        proc = FailingProcessor()
        connector = ExternalImportConnector(
            settings=mock_settings, data_processors=[proc], state=state
        )
        connector.logger = _make_logger_mock()

        connector._init_dependencies()
        connector.callback()

        connector.logger.error.assert_called()

    @patch(PATCH_HELPER)
    def test_callback_keyboard_interrupt(
        self, mock_helper_cls: MagicMock, mock_settings: MagicMock
    ):
        helper = _make_helper_mock()
        mock_helper_cls.return_value = helper
        state = _make_state_mock()
        state.load.side_effect = KeyboardInterrupt()

        proc = DummyProcessor()
        connector = ExternalImportConnector(
            settings=mock_settings, data_processors=[proc], state=state
        )
        connector._init_dependencies()

        with pytest.raises(SystemExit):
            connector.callback()

    @patch(PATCH_HELPER)
    def test_callback_system_exit(
        self, mock_helper_cls: MagicMock, mock_settings: MagicMock
    ):
        helper = _make_helper_mock()
        mock_helper_cls.return_value = helper
        state = _make_state_mock()
        state.load.side_effect = SystemExit(0)

        proc = DummyProcessor()
        connector = ExternalImportConnector(
            settings=mock_settings, data_processors=[proc], state=state
        )
        connector._init_dependencies()

        with pytest.raises(SystemExit):
            connector.callback()

    @patch(PATCH_HELPER)
    def test_start(self, mock_helper_cls: MagicMock, mock_settings: MagicMock):
        helper = _make_helper_mock()
        mock_helper_cls.return_value = helper

        proc = DummyProcessor()
        connector = ExternalImportConnector(
            settings=mock_settings, data_processors=[proc]
        )
        connector.start()

        helper.schedule_process.assert_called_once_with(
            message_callback=connector.callback,
            duration_period=3600.0,
        )

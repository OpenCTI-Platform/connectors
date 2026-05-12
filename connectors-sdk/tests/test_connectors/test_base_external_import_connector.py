# pragma: no cover
# type: ignore
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from connectors_sdk.connectors.external_import.base_data_processor import (
    BaseDataProcessor,
)
from connectors_sdk.connectors.external_import.base_external_import_connector import (
    BaseExternalImportConnector,
)

PATCH_HELPER = "connectors_sdk.connectors.external_import.base_external_import_connector.OpenCTIConnectorHelper"


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


class TestBaseExternalImportConnector:
    def test_init(self, mock_config: MagicMock):
        proc = DummyProcessor()
        connector = BaseExternalImportConnector(
            config=mock_config, data_processors=[proc]
        )
        assert connector.config is mock_config
        assert connector.data_processors == [proc]

    def test_init_empty_processors_raises(self, mock_config: MagicMock):
        with pytest.raises(ValueError, match="At least one BaseDataProcessor"):
            BaseExternalImportConnector(config=mock_config, data_processors=[])

    @patch(PATCH_HELPER)
    def test_init_infrastructure_wires_up_components(
        self, mock_helper_cls: MagicMock, mock_config: MagicMock
    ):
        mock_helper_cls.return_value = _make_helper_mock()

        proc = DummyProcessor()
        connector = BaseExternalImportConnector(
            config=mock_config, data_processors=[proc]
        )
        connector._init_infrastructure()

        assert connector.logger is not None
        assert connector.state is not None
        assert proc.config is mock_config
        assert proc.logger is connector.logger
        assert proc.state is connector.state
        assert proc.work_manager is not None

    @patch(PATCH_HELPER)
    def test_init_infrastructure_custom_state(
        self, mock_helper_cls: MagicMock, mock_config: MagicMock
    ):
        mock_helper_cls.return_value = _make_helper_mock()

        custom_state = MagicMock()
        proc = DummyProcessor()
        connector = BaseExternalImportConnector(
            config=mock_config, data_processors=[proc], state=custom_state
        )
        connector._init_infrastructure()

        assert connector.state is custom_state
        assert proc.state is custom_state

    @patch(PATCH_HELPER)
    def test_callback_success(self, mock_helper_cls: MagicMock, mock_config: MagicMock):
        helper = _make_helper_mock()
        mock_helper_cls.return_value = helper
        state = _make_state_mock()

        proc = DummyProcessor()
        connector = BaseExternalImportConnector(
            config=mock_config, data_processors=[proc], state=state
        )
        connector._init_infrastructure()
        connector.callback()

        state.load.assert_called_once_with(force=True)
        state.save.assert_called_once()
        assert state.last_run is not None

    @patch(PATCH_HELPER)
    def test_callback_with_last_run(
        self, mock_helper_cls: MagicMock, mock_config: MagicMock
    ):
        helper = _make_helper_mock()
        mock_helper_cls.return_value = helper
        state = _make_state_mock()
        state.last_run = "2025-01-01T00:00:00+00:00"

        proc = DummyProcessor()
        connector = BaseExternalImportConnector(
            config=mock_config, data_processors=[proc], state=state
        )
        connector._init_infrastructure()
        connector.callback()

        state.save.assert_called_once()

    @patch(PATCH_HELPER)
    def test_callback_exception_is_logged(
        self, mock_helper_cls: MagicMock, mock_config: MagicMock
    ):
        helper = _make_helper_mock()
        mock_helper_cls.return_value = helper
        state = _make_state_mock()

        proc = FailingProcessor()
        connector = BaseExternalImportConnector(
            config=mock_config, data_processors=[proc], state=state
        )
        connector._init_infrastructure()
        connector.callback()

        helper.connector_logger.error.assert_called()

    @patch(PATCH_HELPER)
    def test_callback_keyboard_interrupt(
        self, mock_helper_cls: MagicMock, mock_config: MagicMock
    ):
        helper = _make_helper_mock()
        mock_helper_cls.return_value = helper
        state = _make_state_mock()
        state.load.side_effect = KeyboardInterrupt()

        proc = DummyProcessor()
        connector = BaseExternalImportConnector(
            config=mock_config, data_processors=[proc], state=state
        )
        connector._init_infrastructure()

        with pytest.raises(SystemExit):
            connector.callback()

    @patch(PATCH_HELPER)
    def test_callback_system_exit(
        self, mock_helper_cls: MagicMock, mock_config: MagicMock
    ):
        helper = _make_helper_mock()
        mock_helper_cls.return_value = helper
        state = _make_state_mock()
        state.load.side_effect = SystemExit(0)

        proc = DummyProcessor()
        connector = BaseExternalImportConnector(
            config=mock_config, data_processors=[proc], state=state
        )
        connector._init_infrastructure()

        with pytest.raises(SystemExit):
            connector.callback()

    @patch(PATCH_HELPER)
    def test_start(self, mock_helper_cls: MagicMock, mock_config: MagicMock):
        helper = _make_helper_mock()
        mock_helper_cls.return_value = helper

        proc = DummyProcessor()
        connector = BaseExternalImportConnector(
            config=mock_config, data_processors=[proc]
        )
        connector.start()

        helper.schedule_process.assert_called_once_with(
            message_callback=connector.callback,
            duration_period=3600.0,
        )

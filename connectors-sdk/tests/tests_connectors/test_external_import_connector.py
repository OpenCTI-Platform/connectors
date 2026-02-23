from unittest.mock import MagicMock

import connectors_sdk.connectors.external_import_connector as external_import_connector_module
import pytest
from connectors_sdk.connectors.external_import_connector import ExternalImportConnector


@pytest.fixture
def connector_mock_dependencies(
    dummy_connector_settings,
    mock_opencti_connector_helper,
):
    """Build connector dependencies using mocks only."""
    state_manager = MagicMock()
    state_manager.last_run = None
    state_manager.load = MagicMock()
    state_manager.save = MagicMock()

    first_data_processor = MagicMock()
    first_data_processor.collect = MagicMock(return_value=["first-collected"])
    first_data_processor.transform = MagicMock(return_value=["first-transformed"])
    first_data_processor.send = MagicMock()

    second_data_processor = MagicMock()
    second_data_processor.collect = MagicMock(return_value=["second-collected"])
    second_data_processor.transform = MagicMock(return_value=["second-transformed"])
    second_data_processor.send = MagicMock()

    return {
        "config": dummy_connector_settings,
        "helper": mock_opencti_connector_helper,
        "state_manager": state_manager,
        "data_processors": [
            first_data_processor,
            second_data_processor,
        ],
    }


def test_external_import_connector_initialization(connector_mock_dependencies):
    """Test that ExternalImportConnector initializes dependencies and logger."""
    connector = ExternalImportConnector(**connector_mock_dependencies)

    assert connector.config is connector_mock_dependencies["config"]
    assert connector.helper is connector_mock_dependencies["helper"]
    assert connector.state_manager is connector_mock_dependencies["state_manager"]
    assert connector.data_processors is connector_mock_dependencies["data_processors"]


def test_external_import_connector_callback_success_flow(connector_mock_dependencies):
    """Test callback happy path: load, process all data processors, and save."""
    connector = ExternalImportConnector(**connector_mock_dependencies)

    state_manager = connector_mock_dependencies["state_manager"]
    first_data_processor, second_data_processor = connector_mock_dependencies[
        "data_processors"
    ]

    connector.callback()

    state_manager.load.assert_called_once_with()
    state_manager.save.assert_called_once()
    assert state_manager.last_run is not None

    first_data_processor.collect.assert_called_once()
    first_data_processor.transform.assert_called_once_with(["first-collected"])
    first_data_processor.send.assert_called_once_with(["first-transformed"])
    second_data_processor.collect.assert_called_once()
    second_data_processor.transform.assert_called_once()
    second_data_processor.send.assert_called_once()


def test_external_import_connector_exits_on_keyboard_interrupt(
    connector_mock_dependencies, monkeypatch
):
    """Test callback stops connector cleanly when interruption occurs."""
    state_manager = connector_mock_dependencies["state_manager"]
    state_manager.load = MagicMock(side_effect=KeyboardInterrupt)

    mocked_sys_exit = MagicMock()
    monkeypatch.setattr(external_import_connector_module.sys, "exit", mocked_sys_exit)

    first_data_processor, second_data_processor = connector_mock_dependencies[
        "data_processors"
    ]

    connector = ExternalImportConnector(**connector_mock_dependencies)
    connector.callback()

    mocked_sys_exit.assert_called_once_with(0)
    first_data_processor.collect.assert_not_called()
    first_data_processor.transform.assert_not_called()
    first_data_processor.send.assert_not_called()
    second_data_processor.collect.assert_not_called()
    second_data_processor.transform.assert_not_called()
    second_data_processor.send.assert_not_called()
    state_manager.save.assert_not_called()


def test_external_import_connector_keeps_running_on_unexpected_error(
    connector_mock_dependencies,
):
    """Test callback logs any unexpected exception and keeps connector alive."""
    second_data_processor = connector_mock_dependencies["data_processors"][1]
    second_data_processor.collect = MagicMock(side_effect=ValueError("unexpected"))

    first_data_processor = connector_mock_dependencies["data_processors"][0]
    state_manager = connector_mock_dependencies["state_manager"]

    connector = ExternalImportConnector(**connector_mock_dependencies)
    connector.callback()

    first_data_processor.collect.assert_called_once()
    first_data_processor.transform.assert_called_once_with(["first-collected"])
    first_data_processor.send.assert_called_once_with(["first-transformed"])
    second_data_processor.transform.assert_not_called()
    second_data_processor.send.assert_not_called()
    state_manager.save.assert_not_called()


def test_external_import_connector_start_schedules_callback(
    connector_mock_dependencies,
):
    """Test that start schedules callback using configured duration period."""
    connector = ExternalImportConnector(**connector_mock_dependencies)
    helper = connector_mock_dependencies["helper"]

    connector.start()

    helper.schedule_iso.assert_called_once_with(
        message_callback=connector.callback,
        duration_period="PT5M",
    )

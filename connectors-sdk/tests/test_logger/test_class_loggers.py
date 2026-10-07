"""Tests for the loggers of the SDK classes."""

import importlib

import pytest
from connectors_sdk.logger import ConnectorLoggerAdapter

# Every SDK class logging through `self.logger` / `cls.logger`
CLASSES_WITH_LOGGER = [
    ("connectors_sdk.connectors.external_import._work_manager", "_Work"),
    ("connectors_sdk.connectors.external_import._work_manager", "WorkManager"),
    (
        "connectors_sdk.connectors.external_import.base_data_processor",
        "BaseDataProcessor",
    ),
    (
        "connectors_sdk.connectors.external_import.external_import_connector",
        "ExternalImportConnector",
    ),
    ("connectors_sdk.settings._settings_loader", "_SettingsLoader"),
    ("connectors_sdk.settings.base_settings", "BaseConnectorSettings"),
    ("connectors_sdk.states._base_state", "_StateClient"),
    ("connectors_sdk.states._base_state", "BaseConnectorState"),
]


@pytest.mark.parametrize("module_name, class_name", CLASSES_WITH_LOGGER)
def test_class_logger_should_be_named_after_its_module(module_name, class_name):
    """Test that an SDK class logs under the name of the module defining it."""
    cls = getattr(importlib.import_module(module_name), class_name)

    assert isinstance(cls.logger, ConnectorLoggerAdapter)
    assert cls.logger.name == module_name


@pytest.mark.parametrize("module_name, class_name", CLASSES_WITH_LOGGER)
def test_subclass_logger_should_be_named_after_the_subclass_module(
    module_name, class_name
):
    """Test that a subclass logs under the name of the module defining the subclass."""
    cls = getattr(importlib.import_module(module_name), class_name)

    subclass = type("Subclass", (cls,), {"__module__": "connector.my_module"})

    assert isinstance(subclass.logger, ConnectorLoggerAdapter)
    assert subclass.logger.name == "connector.my_module"
    assert cls.logger.name == module_name  # the parent class keeps its own logger

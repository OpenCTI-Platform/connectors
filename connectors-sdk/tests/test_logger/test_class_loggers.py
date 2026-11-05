"""Tests for the loggers of the SDK classes."""

import importlib

import pytest
from connectors_sdk.logger import ConnectorLoggerAdapter, get_logger
from connectors_sdk.logger._class_logger import _ClassLoggerMixin

# Every SDK class logging through `self.logger` / `cls.logger`
CLASSES_WITH_LOGGER = [
    ("connectors_sdk.client.base_client_api", "BaseClientApi"),
    ("connectors_sdk.client.rate_limit", "_RateLimitAdapter"),
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


def test_class_logger_mixin_should_name_loggers_after_their_module():
    """Test that a class and its subclasses get a logger named after their module."""

    class SdkClass(_ClassLoggerMixin):
        pass

    connector_class = type(
        "ConnectorClass", (SdkClass,), {"__module__": "connector.my_module"}
    )

    assert isinstance(SdkClass.logger, ConnectorLoggerAdapter)
    assert SdkClass.logger.name == __name__
    assert connector_class.logger.name == "connector.my_module"
    assert connector_class().logger.name == "connector.my_module"
    assert SdkClass.logger.name == __name__  # the parent class keeps its own logger


def test_class_logger_mixin_should_refuse_a_logger_defined_in_the_class_body():
    """Test that a class can't define its own `logger`: the SDK always sets it."""
    with pytest.raises(TypeError, match="must not define its own `logger`"):

        class ConnectorClass(_ClassLoggerMixin):
            logger = get_logger("connector.custom")


def test_class_logger_mixin_should_allow_replacing_logger_on_the_class():
    """Test that a test can replace the logger of a class, after its definition."""

    class SdkClass(_ClassLoggerMixin):
        pass

    class ConnectorClass(SdkClass):
        pass

    fake_logger = get_logger("tests.fake")

    ConnectorClass.logger = fake_logger

    assert ConnectorClass().logger is fake_logger
    assert SdkClass.logger.name == __name__

import importlib.util
import os
from typing import Any
from unittest.mock import MagicMock

import pytest
from pycti import OpenCTIConnectorHelper
from settings import ConnectorSettings

_SRC_DIR = os.path.join(os.path.dirname(__file__), "..", "src")
_CONNECTOR_MODULE_PATH = os.path.join(_SRC_DIR, "import-file-yara.py")


def _load_connector_module():
    """Load the hyphenated connector entry module (``import-file-yara.py``).

    The module cannot be imported with a normal ``import`` statement because its
    filename contains hyphens, so it is loaded from its file location instead.
    """
    spec = importlib.util.spec_from_file_location(
        "import_file_yara", _CONNECTOR_MODULE_PATH
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class StubConnectorSettings(ConnectorSettings):
    """
    Subclass of ConnectorSettings for testing purpose.
    Overrides _load_config_dict to return a fake but valid config dict.
    """

    @classmethod
    def _load_config_dict(cls, _, handler) -> dict[str, Any]:
        return handler(
            {
                "opencti": {
                    "url": "http://localhost:8080",
                    "token": "test-token",
                },
                "connector": {
                    "id": "connector-id",
                    "name": "ImportFileYARA",
                    "scope": "text/yara+plain",
                    "log_level": "error",
                    "validate_before_import": True,
                    "auto": False,
                },
                "yara_import_file": {
                    "split_rules": True,
                },
            }
        )


@pytest.fixture
def mock_opencti_connector_helper(monkeypatch):
    """Mock all heavy dependencies of OpenCTIConnectorHelper, typically API calls to OpenCTI."""

    module_import_path = "pycti.connector.opencti_connector_helper"
    monkeypatch.setattr(f"{module_import_path}.killProgramHook", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.sched.scheduler", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.ConnectorInfo", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.OpenCTIApiClient", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.OpenCTIConnector", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.OpenCTIMetricHandler", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.PingAlive", MagicMock())


def test_connector_settings_is_instantiated():
    """
    Test that ConnectorSettings can be instantiated successfully:
        - the implemented class MUST have a method `to_helper_config` (inherited from BaseConnectorSettings)
        - the method `to_helper_config` MUST return a dict
    """
    settings = StubConnectorSettings()

    assert isinstance(settings, ConnectorSettings)
    assert isinstance(settings.to_helper_config(), dict)


def test_opencti_connector_helper_is_instantiated(mock_opencti_connector_helper):
    """
    Test that OpenCTIConnectorHelper can be instantiated successfully:
        - the value of settings.to_helper_config MUST be the expected dict for OpenCTIConnectorHelper
        - the helper MUST be able to get its instance's attributes from the config dict
    """
    settings = StubConnectorSettings()
    helper = OpenCTIConnectorHelper(config=settings.to_helper_config())

    assert helper.opencti_url == "http://localhost:8080/"
    assert helper.opencti_token == "test-token"
    assert helper.connect_id == "connector-id"
    assert helper.connect_name == "ImportFileYARA"
    assert helper.connect_scope == "text/yara+plain"
    assert helper.log_level == "ERROR"
    assert helper.get_validate_before_import() is True


def test_connector_is_instantiated(mock_opencti_connector_helper, monkeypatch):
    """
    Test that the connector's main class can be instantiated successfully:
        - the connector's main class MUST build `self.config` from `ConnectorSettings`
        - the connector's main class MUST build `self.helper` from `self.config.to_helper_config()`
        - the connector's main class MUST read its own config values from `self.config`
    """
    module = _load_connector_module()
    monkeypatch.setattr(module, "ConnectorSettings", StubConnectorSettings)

    connector = module.ImportFileYARA()

    assert isinstance(connector.config, ConnectorSettings)
    assert connector.helper is not None
    assert connector.yara_import_file_split_rules is True

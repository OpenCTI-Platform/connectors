import logging
import os
import sys
from unittest.mock import MagicMock

import pytest

sys.path.append(os.path.join(os.path.dirname(__file__), "..", "src"))


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


@pytest.fixture
def mock_py_misp(monkeypatch):
    """Mock MISP client, to avoid real requests to MISP API."""

    monkeypatch.setattr("api_client.client.PyMISP", MagicMock())


@pytest.fixture(autouse=True)
def patch_logger_for_tests(monkeypatch):
    """Patch logger methods to format logs with dictionary data for tests."""

    def create_enhanced_log_method(original_method):
        def enhanced_log(self, msg, *args, **kwargs):
            if args and len(args) == 1 and isinstance(args[0], dict):
                log_dict = args[0]
                formatted_msg = f"{msg} - {log_dict}"
                return original_method(self, formatted_msg)
            else:
                return original_method(self, msg, *args, **kwargs)

        return enhanced_log

    orig_info = logging.Logger.info
    orig_debug = logging.Logger.debug
    orig_warning = logging.Logger.warning
    orig_error = logging.Logger.error

    monkeypatch.setattr(logging.Logger, "info", create_enhanced_log_method(orig_info))
    monkeypatch.setattr(logging.Logger, "debug", create_enhanced_log_method(orig_debug))
    monkeypatch.setattr(
        logging.Logger, "warning", create_enhanced_log_method(orig_warning)
    )
    monkeypatch.setattr(logging.Logger, "error", create_enhanced_log_method(orig_error))

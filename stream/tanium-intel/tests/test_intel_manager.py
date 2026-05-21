import importlib.util
import sys
import types
from pathlib import Path
from unittest.mock import MagicMock, call

pycti_module = types.ModuleType("pycti")


class OpenCTIConnectorHelper:
    @staticmethod
    def get_attribute_in_extension(_key, entity):
        return entity.get("id")


pycti_module.OpenCTIConnectorHelper = OpenCTIConnectorHelper
sys.modules.setdefault("pycti", pycti_module)

intel_manager_spec = importlib.util.spec_from_file_location(
    "tanium_intel_intel_manager",
    Path(__file__).resolve().parents[1]
    / "src"
    / "tanium_intel_connector"
    / "intel_manager.py",
)
intel_manager_module = importlib.util.module_from_spec(intel_manager_spec)
intel_manager_spec.loader.exec_module(intel_manager_module)
IntelManager = intel_manager_module.IntelManager


def test_update_indicator_creates_yara_intel_when_missing_from_cache():
    helper = MagicMock()
    helper.connector_logger = MagicMock()
    cache = MagicMock()
    cache.get.return_value = None
    manager = IntelManager(helper, MagicMock(), cache)
    manager.create_intel_from_indicator = MagicMock(return_value="intel-123")
    intel_id = manager.update_intel_from_indicator(
        {"id": "indicator--1", "pattern_type": "yara"}
    )

    assert intel_id == "intel-123"
    manager.create_intel_from_indicator.assert_called_once_with(
        {"id": "indicator--1", "pattern_type": "yara"}
    )
    helper.connector_logger.info.assert_has_calls(
        [
            call(
                "[UPDATE] YARA indicator not found in cache, creating intel",
                {"id": "indicator--1"},
            ),
            call(
                "[UPDATE] YARA intel created from cache-miss update",
                {"id": "indicator--1", "intel_id": "intel-123"},
            ),
        ]
    )


def test_update_indicator_skips_non_yara_when_missing_from_cache():
    helper = MagicMock()
    helper.connector_logger = MagicMock()
    cache = MagicMock()
    cache.get.return_value = None
    manager = IntelManager(helper, MagicMock(), cache)
    manager.create_intel_from_indicator = MagicMock(return_value="intel-123")
    intel_id = manager.update_intel_from_indicator(
        {"id": "indicator--2", "pattern_type": "stix"}
    )

    assert intel_id is None
    manager.create_intel_from_indicator.assert_not_called()
    helper.connector_logger.info.assert_called_once_with(
        "[UPDATE] Indicator does not exist, doing nothing",
        {"id": "indicator--2"},
    )


def test_update_indicator_logs_error_when_yara_creation_fails():
    helper = MagicMock()
    helper.connector_logger = MagicMock()
    cache = MagicMock()
    cache.get.return_value = None
    manager = IntelManager(helper, MagicMock(), cache)
    manager.create_intel_from_indicator = MagicMock(return_value=None)

    intel_id = manager.update_intel_from_indicator(
        {"id": "indicator--3", "pattern_type": "yara"}
    )

    assert intel_id is None
    helper.connector_logger.error.assert_called_once_with(
        "[UPDATE] Failed to create YARA intel from cache-miss update",
        {"id": "indicator--3"},
    )

import importlib.util
import sys
import types
from pathlib import Path
from unittest.mock import MagicMock

pycti_module = types.ModuleType("pycti")


class OpenCTIConnectorHelper:
    @staticmethod
    def get_attribute_in_extension(_key, _entity):
        return None


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


def test_update_indicator_creates_yara_intel_when_missing_from_cache(monkeypatch):
    helper = MagicMock()
    helper.connector_logger = MagicMock()
    cache = MagicMock()
    cache.get.return_value = None
    manager = IntelManager(helper, MagicMock(), cache)
    manager.create_intel_from_indicator = MagicMock(return_value="intel-123")
    monkeypatch.setattr(
        intel_manager_module.OpenCTIConnectorHelper,
        "get_attribute_in_extension",
        lambda _key, entity: entity["id"],
    )

    intel_id = manager.update_intel_from_indicator(
        {"id": "indicator--1", "pattern_type": "yara"}
    )

    assert intel_id == "intel-123"
    manager.create_intel_from_indicator.assert_called_once_with(
        {"id": "indicator--1", "pattern_type": "yara"}
    )


def test_update_indicator_skips_non_yara_when_missing_from_cache(monkeypatch):
    helper = MagicMock()
    helper.connector_logger = MagicMock()
    cache = MagicMock()
    cache.get.return_value = None
    manager = IntelManager(helper, MagicMock(), cache)
    manager.create_intel_from_indicator = MagicMock(return_value="intel-123")
    monkeypatch.setattr(
        intel_manager_module.OpenCTIConnectorHelper,
        "get_attribute_in_extension",
        lambda _key, entity: entity["id"],
    )

    intel_id = manager.update_intel_from_indicator(
        {"id": "indicator--2", "pattern_type": "stix"}
    )

    assert intel_id is None
    manager.create_intel_from_indicator.assert_not_called()

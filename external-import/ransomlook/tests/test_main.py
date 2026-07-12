# pylint: disable=wrong-import-order

import runpy
import traceback
from pathlib import Path
from unittest.mock import MagicMock

import connector
import pycti
import pytest

MAIN_PATH = Path(__file__).parents[1] / "src" / "main.py"


def test_importing_main_has_no_runtime_side_effects():
    namespace = runpy.run_path(str(MAIN_PATH), run_name="ransomlook_import_test")
    assert namespace["__name__"] == "ransomlook_import_test"


def test_main_builds_and_runs_connector(monkeypatch):
    settings = MagicMock()
    settings.to_helper_config.return_value = {"configured": True}
    helper = MagicMock()
    connector_instance = MagicMock()
    settings_factory = MagicMock(return_value=settings)
    helper_factory = MagicMock(return_value=helper)
    connector_factory = MagicMock(return_value=connector_instance)
    monkeypatch.setattr(connector, "ConnectorSettings", settings_factory)
    monkeypatch.setattr(connector, "RansomLookConnector", connector_factory)
    monkeypatch.setattr(pycti, "OpenCTIConnectorHelper", helper_factory)

    runpy.run_path(str(MAIN_PATH), run_name="__main__")

    helper_factory.assert_called_once_with(config={"configured": True})
    connector_factory.assert_called_once_with(settings, helper)
    connector_instance.run.assert_called_once()


def test_main_prints_traceback_and_exits_on_failure(monkeypatch):
    monkeypatch.setattr(
        connector, "ConnectorSettings", MagicMock(side_effect=RuntimeError("invalid"))
    )
    print_exc = MagicMock()
    monkeypatch.setattr(traceback, "print_exc", print_exc)

    with pytest.raises(SystemExit) as exc:
        runpy.run_path(str(MAIN_PATH), run_name="__main__")

    assert exc.value.code == 1
    print_exc.assert_called_once()

import os
import runpy
from unittest.mock import patch

import pytest

MAIN_PATH = os.path.join(os.path.dirname(__file__), "..", "src", "main.py")


def test_main_runs_connector():
    with patch("connector.ConnectorSettings") as settings_cls, patch(
        "pycti.OpenCTIConnectorHelper"
    ) as helper_cls, patch("connector.SpurConnector") as connector_cls:
        runpy.run_path(MAIN_PATH, run_name="__main__")

    settings_cls.assert_called_once()
    helper_cls.assert_called_once()
    connector_cls.return_value.run.assert_called_once()


def test_main_exits_on_exception():
    with patch("connector.ConnectorSettings", side_effect=RuntimeError("boom")), patch(
        "pycti.OpenCTIConnectorHelper"
    ), patch("connector.SpurConnector"):
        with pytest.raises(SystemExit) as exc:
            runpy.run_path(MAIN_PATH, run_name="__main__")
    assert exc.value.code == 1

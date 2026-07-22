"""Entrypoint tests for src/main.py.

main.py is a thin __main__ wrapper. We exec it via runpy with the connector
package + pycti helper patched, covering both the success path and the
exit(1)-on-error path.
"""

import os
import runpy
from unittest.mock import MagicMock

import pytest

MAIN_PATH = os.path.join(os.path.dirname(__file__), "..", "src", "main.py")


def test_main_success_runs_connector(monkeypatch):
    import pycti

    import connector as connector_pkg

    fake_settings = MagicMock()
    fake_conn = MagicMock()
    monkeypatch.setattr(
        connector_pkg, "ConnectorSettings", MagicMock(return_value=fake_settings)
    )
    monkeypatch.setattr(
        connector_pkg, "EmailCasesConnector", MagicMock(return_value=fake_conn)
    )
    monkeypatch.setattr(pycti, "OpenCTIConnectorHelper", MagicMock())

    runpy.run_path(MAIN_PATH, run_name="__main__")

    fake_conn.run.assert_called_once()


def test_main_exits_on_error(monkeypatch):
    import connector as connector_pkg

    monkeypatch.setattr(
        connector_pkg,
        "ConnectorSettings",
        MagicMock(side_effect=RuntimeError("bad config")),
    )

    with pytest.raises(SystemExit):
        runpy.run_path(MAIN_PATH, run_name="__main__")

"""
Smoke tests for the connector entry point (src/main.py).

These tests verify that the module-level wiring in main.py correctly assembles
the connector components without actually connecting to OpenCTI or the
Threat Landscape API.
"""

from unittest.mock import MagicMock, patch

import pytest


def test_main_assembles_connector(monkeypatch):
    """
    main.py should instantiate ConnectorSettings, OpenCTIConnectorHelper, and
    ThreatLandscapeConnector, then call connector.run().
    """
    mock_settings = MagicMock()
    mock_settings.to_helper_config.return_value = {}

    mock_helper = MagicMock()
    mock_connector = MagicMock()

    with (
        patch("connector.ConnectorSettings", return_value=mock_settings),
        patch("pycti.OpenCTIConnectorHelper", return_value=mock_helper),
        patch("connector.ThreatLandscapeConnector", return_value=mock_connector),
    ):
        # Import and execute main as __main__
        import runpy

        runpy.run_path(
            str(__import__("pathlib").Path(__file__).parents[1] / "src" / "main.py"),
            run_name="__main__",
        )

    mock_connector.run.assert_called_once()


def test_main_exits_on_exception(monkeypatch, capsys):
    """
    main.py should print the traceback and exit with code 1 when an
    unhandled exception is raised during startup.
    """
    with (
        patch("connector.ConnectorSettings", side_effect=RuntimeError("boom")),
        pytest.raises(SystemExit) as exc_info,
    ):
        import runpy

        runpy.run_path(
            str(__import__("pathlib").Path(__file__).parents[1] / "src" / "main.py"),
            run_name="__main__",
        )

    assert exc_info.value.code == 1

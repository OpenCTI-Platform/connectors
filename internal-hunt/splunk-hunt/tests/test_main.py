import runpy
from pathlib import Path
from unittest.mock import patch

import pytest

MAIN = Path(__file__).parent.parent / "src" / "main.py"


def test_main_starts_the_connector():
    # Given a connector whose start is mocked
    with (
        patch("splunk_hunt.ConnectorSettings") as settings_cls,
        patch("splunk_hunt.SplunkHuntConnector") as connector_cls,
    ):
        # When the entry point runs
        runpy.run_path(str(MAIN), run_name="__main__")

    # Then the connector is created from the settings and started
    connector_cls.assert_called_once_with(settings=settings_cls.return_value)
    connector_cls.return_value.start.assert_called_once()


def test_main_exits_on_startup_error():
    # Given a configuration error at startup
    with patch("splunk_hunt.ConnectorSettings", side_effect=ValueError("bad")):
        # When/Then the entry point exits with a non-zero code
        with pytest.raises(SystemExit) as err:
            runpy.run_path(str(MAIN), run_name="__main__")
    assert err.value.code == 1

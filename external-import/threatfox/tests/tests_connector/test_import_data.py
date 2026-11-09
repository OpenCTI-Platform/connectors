import urllib.error
from datetime import UTC, datetime
from unittest.mock import MagicMock, patch

import pytest
from src.__main__ import ThreatFox

SECRET_URL = "https://threatfox-api.abuse.ch/v2/files/exports/my-secret-key/recent.csv"


@pytest.fixture
def connector():
    connector = ThreatFox.__new__(ThreatFox)
    connector.helper = MagicMock()
    connector.helper.api.work.initiate_work.return_value = "work-id"
    connector.threatfox_csv_url = SECRET_URL
    connector.ioc_to_import = ["all_types"]
    connector.threatfox_import_offline = True
    return connector


@pytest.mark.parametrize(
    "error",
    [
        urllib.error.HTTPError(SECRET_URL, 401, "Unauthorized", {}, None),
        urllib.error.URLError("network unreachable"),
    ],
    ids=["http_error", "network_error"],
)
def test_failed_download_fails_work_and_keeps_last_run(connector, error):
    now_dt = datetime.now(UTC)

    with patch("urllib.request.urlopen", side_effect=error):
        connector.import_data({"last_run": 1}, now_dt, now_dt.timestamp())

    connector.helper.set_state.assert_not_called()
    connector.helper.api.work.to_processed.assert_called_once()
    assert connector.helper.api.work.to_processed.call_args.kwargs == {"in_error": True}
    logged = str(connector.helper.mock_calls)
    assert "my-secret-key" not in logged


def test_successful_download_stores_last_run(connector):
    now_dt = datetime.now(UTC)
    connector.download_csv = MagicMock(return_value=iter([]))

    connector.import_data({}, now_dt, now_dt.timestamp())

    connector.helper.set_state.assert_called_once()
    assert connector.helper.set_state.call_args.args[0]["last_run"] == (
        now_dt.timestamp()
    )
    assert "in_error" not in connector.helper.api.work.to_processed.call_args.kwargs

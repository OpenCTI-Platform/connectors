import urllib.error
from datetime import UTC, datetime
from unittest.mock import MagicMock, patch

import pytest
from connectors_sdk.exceptions.error import DataRetrievalError
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
        result = connector.import_data({"last_run": 1}, now_dt, now_dt.timestamp())

    assert result is False

    connector.helper.set_state.assert_not_called()
    connector.helper.api.work.to_processed.assert_called_once()
    assert connector.helper.api.work.to_processed.call_args.kwargs == {"in_error": True}
    logged = str(connector.helper.mock_calls)
    assert "my-secret-key" not in logged


@pytest.mark.parametrize(
    "url",
    [
        "https://threatfox-api.abuse.ch/v2/files/exports/my-secret key/recent.csv",
        "threatfox-api.abuse.ch/v2/files/exports/my-secret-key/recent.csv",
    ],
    ids=["auth_key_with_space", "csv_url_without_scheme"],
)
def test_invalid_export_url_does_not_leak_auth_key(connector, url):
    # urlopen rejects these URLs before connecting, with an error message
    # that contains the URL. Block sockets to be sure no request leaves.
    connector.threatfox_csv_url = url
    now_dt = datetime.now(UTC)

    with patch("socket.create_connection", side_effect=AssertionError("network")):
        connector.import_data({"last_run": 1}, now_dt, now_dt.timestamp())

    connector.helper.set_state.assert_not_called()
    assert connector.helper.api.work.to_processed.call_args.kwargs == {"in_error": True}
    logged = str(connector.helper.mock_calls)
    assert "my-secret" not in logged


def test_successful_download_stores_last_run(connector):
    now_dt = datetime.now(UTC)
    connector.download_csv = MagicMock(return_value=iter([]))

    result = connector.import_data(
        {"failed_attempts": 3, "last_failure": 1}, now_dt, now_dt.timestamp()
    )

    assert result is True
    connector.helper.set_state.assert_called_once()
    stored = connector.helper.set_state.call_args.args[0]
    assert stored["last_run"] == now_dt.timestamp()
    # The success resets the backoff.
    assert "failed_attempts" not in stored
    assert "last_failure" not in stored
    assert "in_error" not in connector.helper.api.work.to_processed.call_args.kwargs


def test_loop_logs_last_run_stored_after_a_successful_run(connector):
    connector.threatfox_interval = 3
    connector.helper.get_state.return_value = {}
    connector.import_data = MagicMock(return_value=True)

    connector.loop()

    logged = [call.args[0] for call in connector.helper.log_info.call_args_list]
    assert any("Last_run stored" in message for message in logged)
    connector.helper.set_state.assert_not_called()


@pytest.mark.parametrize(
    "failed_attempts, expected_delay",
    [(1, 60), (2, 120), (3, 240), (12, 122880), (14, 3 * 86400), (10_000, 3 * 86400)],
)
def test_retry_delay_doubles_and_is_capped_at_interval(
    connector, failed_attempts, expected_delay
):
    connector.threatfox_interval = 3

    assert connector.get_retry_delay(failed_attempts) == expected_delay


@pytest.mark.parametrize("previous_failures", [0, 2])
def test_failed_run_counts_the_failure_and_keeps_last_run(connector, previous_failures):
    connector.threatfox_interval = 3
    state = {"last_run": 1, "last_processed_entry": 5}
    if previous_failures:
        state.update(failed_attempts=previous_failures, last_failure=1)
    connector.helper.get_state.return_value = dict(state)
    connector.import_data = MagicMock(return_value=False)

    connector.loop()

    stored = connector.helper.set_state.call_args.args[0]
    assert stored["last_run"] == 1
    assert stored["last_processed_entry"] == 5
    assert stored["failed_attempts"] == previous_failures + 1
    assert stored["last_failure"] > 1
    logged = [c.args[0] for c in connector.helper.log_info.call_args_list]
    assert not any("Last_run stored" in message for message in logged)


@pytest.mark.parametrize(
    "seconds_since_failure, should_run",
    [(60, False), (121, True)],
    ids=["within_backoff", "backoff_elapsed"],
)
def test_loop_waits_for_the_backoff_after_failures(
    connector, seconds_since_failure, should_run
):
    connector.threatfox_interval = 3
    now_ts = datetime.now(UTC).timestamp()
    connector.helper.get_state.return_value = {
        "last_run": 1,
        "failed_attempts": 2,  # 2 minutes of backoff
        "last_failure": now_ts - seconds_since_failure,
    }
    connector.import_data = MagicMock(return_value=True)

    connector.loop()

    assert connector.import_data.called is should_run


VALID_ROW = (
    '"2026-11-10 10:00:00", "1", "1.2.3.4:80", "ip:port", "botnet_cc", '
    '"win.foo", "None", "Foo", "", "100", "False", "None", "tag", "0", "reporter"'
)


@pytest.mark.parametrize(
    "bad_row",
    [
        '"2026-11-10 10:00:00", "2", "1.2.3.4:81"',
        VALID_ROW.replace("2026-11-10 10:00:00", "not-a-date"),
        VALID_ROW.replace('"100"', '"high"'),
    ],
    ids=["short_row", "bad_date", "non_integer_field"],
)
def test_unparseable_row_is_skipped_and_run_succeeds(connector, bad_row):
    now_dt = datetime.now(UTC)
    connector.download_csv = MagicMock(return_value=iter([bad_row, VALID_ROW]))
    connector.process_row = MagicMock(return_value=[])

    result = connector.import_data({}, now_dt, now_dt.timestamp())

    assert result is True
    connector.process_row.assert_called_once()
    connector.helper.connector_logger.warning.assert_called_once()
    connector.helper.set_state.assert_called_once()


def test_download_error_is_an_sdk_data_retrieval_error(connector):
    error = urllib.error.HTTPError(SECRET_URL, 401, "Unauthorized", {}, None)

    with patch("urllib.request.urlopen", side_effect=error):
        with pytest.raises(DataRetrievalError) as raised:
            list(connector.download_csv())

    assert raised.value.__cause__ is None
    assert raised.value.__suppress_context__
    assert "my-secret-key" not in str(raised.value)

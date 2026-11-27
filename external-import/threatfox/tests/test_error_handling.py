"""Tests for run-level error handling.

A run in which the download or bundle send fails must mark the work as in
error and leave state untouched; a successful run must store state.
"""

from datetime import UTC, datetime
from unittest.mock import MagicMock

import stix2
from src.__main__ import ThreatFox

NOW_DT = datetime(2026, 1, 1, tzinfo=UTC)
NOW_TS = NOW_DT.timestamp()
_CSV_LINE = (
    '"2024-01-01 00:00:00", "12345", "bad.example.com", "domain", "botnet_cc", '
    '"win.example", "Example", "Example Malware", "", "75", "false", "None", '
    '"None", "0", "abuse_ch"'
)


def _connector() -> ThreatFox:
    connector = ThreatFox.__new__(ThreatFox)
    connector.identity = {"id": "identity--internal-0000-0000-000000000000"}
    connector.identity_id = "identity--d7f1c1a0-0000-4000-8000-000000000000"
    connector.helper = MagicMock()
    connector.helper.api.work.initiate_work.return_value = "work-id"
    connector.threatfox_import_offline = True
    connector.ioc_to_import = ["all_types"]
    return connector


class TestImportDataWorkStatus:
    def test_failed_bundle_send_marks_work_in_error_and_keeps_state(self):
        connector = _connector()
        connector.download_csv = MagicMock(return_value=iter([_CSV_LINE]))
        connector.process_row = MagicMock(
            return_value=[stix2.DomainName(value="bad.example.com")]
        )
        connector.helper.send_stix2_bundle.side_effect = RuntimeError("send failed")

        result = connector.import_data({}, NOW_DT, NOW_TS)

        assert result is False
        connector.helper.set_state.assert_not_called()
        _, kwargs = connector.helper.api.work.to_processed.call_args
        assert kwargs.get("in_error") is True

    def test_failed_download_marks_work_in_error_and_keeps_state(self):
        connector = _connector()
        connector.download_csv = MagicMock(side_effect=OSError("network down"))

        result = connector.import_data({}, NOW_DT, NOW_TS)

        assert result is False
        connector.helper.set_state.assert_not_called()
        _, kwargs = connector.helper.api.work.to_processed.call_args
        assert kwargs.get("in_error") is True

    def test_successful_run_stores_state_and_marks_work_processed(self):
        connector = _connector()
        connector.download_csv = MagicMock(return_value=iter([]))

        result = connector.import_data({"last_processed_entry": 123}, NOW_DT, NOW_TS)

        assert result is True
        connector.helper.set_state.assert_called_once_with(
            {"last_run": NOW_TS, "last_processed_entry": 123}
        )
        _, kwargs = connector.helper.api.work.to_processed.call_args
        assert not kwargs.get("in_error")

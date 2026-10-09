"""Tests for run-level error handling.

A run in which every OpenCTI API call of the post-pass fails (or the download
or bundle send fails) must mark the work as in error and leave state
untouched; partial failures must still complete successfully.
"""

from datetime import UTC, datetime
from unittest.mock import MagicMock

import pytest
from src.__main__ import PostPassError, ThreatFox

NOW_DT = datetime(2026, 1, 1, tzinfo=UTC)
NOW_TS = NOW_DT.timestamp()


def _entry(stix_id: str, url: str, malware_stix_id=None) -> dict:
    return {
        "entity_type": "Domain-Name",
        "value": "bad.example.com",
        "hash_field": None,
        "urls": [url],
        "indicator_id": None,
        "stix_id": stix_id,
        "malware_stix_id": malware_stix_id,
        "confidence": 50,
    }


def _connector() -> ThreatFox:
    connector = ThreatFox.__new__(ThreatFox)
    connector.identity = {"id": "identity--internal-0000-0000-000000000000"}
    connector.identity_id = "identity--d7f1c1a0-0000-4000-8000-000000000000"
    connector._pending_observables = []
    connector._cache_ext_ref_ids = {}
    connector.helper = MagicMock()
    connector.helper.api.work.initiate_work.return_value = "work-id"
    connector.threatfox_import_offline = True
    connector.ioc_to_import = ["all_types"]
    connector.postpass_delay = 0
    return connector


@pytest.fixture(autouse=True)
def no_sleep(monkeypatch):
    monkeypatch.setattr("src.__main__.time.sleep", lambda *_a, **_k: None)


class TestPostPassTotalFailure:
    def test_raises_when_every_api_call_fails(self):
        connector = _connector()
        connector._pending_observables = [
            _entry("domain-name--0001", "https://threatfox.abuse.ch/ioc/1/"),
            _entry("domain-name--0002", "https://threatfox.abuse.ch/ioc/2/"),
        ]
        api = connector.helper.api
        api.stix_cyber_observable.read.side_effect = RuntimeError("unauthorized")
        api.stix_cyber_observable.list.side_effect = RuntimeError("unauthorized")

        with pytest.raises(PostPassError):
            connector._attach_external_refs_to_observables()

    def test_raises_when_every_attach_fails_after_lookup(self):
        connector = _connector()
        connector._pending_observables = [
            _entry("domain-name--0001", "https://threatfox.abuse.ch/ioc/1/"),
        ]
        api = connector.helper.api
        api.stix_cyber_observable.read.return_value = {"id": "obs-id"}
        api.external_reference.create.side_effect = RuntimeError("forbidden")

        with pytest.raises(PostPassError):
            connector._attach_external_refs_to_observables()

    def test_partial_failure_does_not_raise(self):
        connector = _connector()
        connector._pending_observables = [
            _entry("domain-name--0001", "https://threatfox.abuse.ch/ioc/1/"),
            _entry("domain-name--0002", "https://threatfox.abuse.ch/ioc/2/"),
        ]
        api = connector.helper.api
        api.stix_cyber_observable.read.return_value = {"id": "obs-id"}
        api.external_reference.create.side_effect = [
            {"id": "ext-ref-1"},
            RuntimeError("transient"),
        ]

        connector._attach_external_refs_to_observables()

        api.stix_cyber_observable.add_external_reference.assert_called_once()

    def test_all_not_found_without_api_errors_does_not_raise(self):
        connector = _connector()
        connector._pending_observables = [
            _entry("domain-name--0001", "https://threatfox.abuse.ch/ioc/1/"),
        ]
        api = connector.helper.api
        api.stix_cyber_observable.read.return_value = None
        api.stix_cyber_observable.list.return_value = []

        connector._attach_external_refs_to_observables()

        assert connector.helper.log_warning.call_args_list

    def test_not_found_with_expected_lookup_errors_does_not_raise(self):
        """One filter shape raising while the other returns normally is the
        lookup ladder working as designed, not the API failing."""
        connector = _connector()
        connector._pending_observables = [
            _entry("domain-name--0001", "https://threatfox.abuse.ch/ioc/1/"),
        ]
        api = connector.helper.api
        api.stix_cyber_observable.read.side_effect = RuntimeError("bad filter shape")
        api.stix_cyber_observable.list.return_value = []

        connector._attach_external_refs_to_observables()


class TestImportDataWorkStatus:
    def test_failed_post_pass_marks_work_in_error_and_keeps_state(self):
        connector = _connector()
        connector.download_csv = MagicMock(return_value=iter([]))
        connector._attach_external_refs_to_observables = MagicMock(
            side_effect=PostPassError("all failed")
        )

        result = connector.import_data({}, NOW_DT, NOW_TS)

        assert result is False
        connector.helper.set_state.assert_not_called()
        connector.helper.api.work.to_processed.assert_called_once()
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
        connector._attach_external_refs_to_observables = MagicMock()

        result = connector.import_data({"last_processed_entry": 123}, NOW_DT, NOW_TS)

        assert result is True
        connector.helper.set_state.assert_called_once_with(
            {"last_run": NOW_TS, "last_processed_entry": 123}
        )
        _, kwargs = connector.helper.api.work.to_processed.call_args
        assert not kwargs.get("in_error")

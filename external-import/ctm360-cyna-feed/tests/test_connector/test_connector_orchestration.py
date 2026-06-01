"""Tests for the CYNA connector orchestration logic."""

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from connector.connector import CTM360CynaConnector
from pydantic import SecretStr


def make_config(**overrides):
    cyna = SimpleNamespace(
        api_base_url="https://cyna.example.com",
        api_key=SecretStr("secret"),
        import_interval=1,
        page_size=25,
        max_pages=100,
    )
    for key, value in overrides.items():
        setattr(cyna, key, value)
    return SimpleNamespace(ctm360_cyna=cyna)


@pytest.fixture
def helper():
    helper = MagicMock()
    helper.api.work.initiate_work.return_value = "work-1"
    return helper


def build_connector(helper):
    connector = CTM360CynaConnector(config=make_config(), helper=helper)
    connector.client = MagicMock()
    connector.converter = MagicMock()
    return connector


def _item(published):
    return {"_id": "x", "metadata": {"published_date": published}}


class TestInit:
    def test_api_key_secret_is_unwrapped_for_client(self, helper):
        # Should not raise: get_secret_value() must be called on a SecretStr.
        connector = CTM360CynaConnector(config=make_config(), helper=helper)
        assert connector.client.base_url == "https://cyna.example.com"


class TestImportData:
    def test_happy_path(self, helper):
        connector = build_connector(helper)
        helper.get_state.return_value = {}
        connector.client.get_all_news.return_value = [_item("2026-02-01T00:00:00Z")]
        connector.converter.news_to_stix.return_value = [object(), object()]
        connector._import_data()
        helper.send_stix2_bundle.assert_called_once()
        helper.set_state.assert_called_once()
        assert helper.api.work.to_processed.call_args.kwargs.get("in_error") in (
            None,
            False,
        )

    def test_no_data(self, helper):
        connector = build_connector(helper)
        helper.get_state.return_value = {}
        connector.client.get_all_news.return_value = []
        connector.converter.news_to_stix.return_value = []
        connector._import_data()
        helper.send_stix2_bundle.assert_not_called()
        helper.set_state.assert_called_once()

    def test_total_failure_guard_raises(self, helper):
        connector = build_connector(helper)
        helper.get_state.return_value = {}
        connector.client.get_all_news.return_value = [_item("2026-02-01T00:00:00Z")]
        # Only the author returned -> every item failed conversion.
        connector.converter.news_to_stix.return_value = [object()]
        with pytest.raises(ValueError, match="failed STIX conversion"):
            connector._import_data()
        helper.set_state.assert_not_called()

    def test_unexpected_error_marks_work_errored(self, helper):
        connector = build_connector(helper)
        helper.get_state.return_value = {}
        connector.client.get_all_news.side_effect = RuntimeError("api boom")
        with pytest.raises(RuntimeError, match="api boom"):
            connector._import_data()
        assert helper.api.work.to_processed.call_args.kwargs.get("in_error") is True
        helper.set_state.assert_not_called()

    def test_unexpected_error_message_containing_all_still_marks_errored(self, helper):
        # Error reporting must not depend on the exception message text: an
        # unrelated error whose message contains "All" must still mark the work
        # item errored (regression guard for the previous str(e) check).
        connector = build_connector(helper)
        helper.get_state.return_value = {}
        connector.client.get_all_news.side_effect = RuntimeError(
            "All connection attempts failed"
        )
        with pytest.raises(RuntimeError, match="All connection attempts failed"):
            connector._import_data()
        assert helper.api.work.to_processed.call_args.kwargs.get("in_error") is True
        helper.set_state.assert_not_called()

    def test_last_run_filtering(self, helper):
        connector = build_connector(helper)
        helper.get_state.return_value = {"last_run": "2026-01-15T00:00:00Z"}
        connector.client.get_all_news.return_value = [
            _item("2026-01-01T00:00:00Z"),  # older -> dropped
            _item("2026-02-01T00:00:00Z"),  # newer -> kept
        ]
        connector.converter.news_to_stix.return_value = [object(), object()]
        connector._import_data()
        passed_items = connector.converter.news_to_stix.call_args[0][0]
        assert len(passed_items) == 1
        assert passed_items[0]["metadata"]["published_date"] == "2026-02-01T00:00:00Z"

    def test_last_run_filter_tolerates_non_dict_items(self, helper):
        # A non-dict page entry must not raise AttributeError out of the
        # last_run filter and abort the whole cycle; it flows to the converter
        # (which skips it per-item).
        connector = build_connector(helper)
        helper.get_state.return_value = {"last_run": "2026-01-15T00:00:00Z"}
        connector.client.get_all_news.return_value = [
            "not-a-dict",
            _item("2026-02-01T00:00:00Z"),
        ]
        connector.converter.news_to_stix.return_value = [object(), object()]
        connector._import_data()
        passed_items = connector.converter.news_to_stix.call_args[0][0]
        assert "not-a-dict" in passed_items


class TestRun:
    def test_ping_failure_exits(self, helper):
        connector = build_connector(helper)
        connector.client.ping.side_effect = RuntimeError("no api")
        with pytest.raises(SystemExit):
            connector.run()

    def test_loop_breaks_on_keyboard_interrupt(self, helper, monkeypatch):
        connector = build_connector(helper)
        monkeypatch.setattr("connector.connector.time.sleep", lambda *_: None)
        connector._import_data = MagicMock(side_effect=KeyboardInterrupt())
        connector.run()
        connector._import_data.assert_called_once()

    def test_loop_continues_on_error(self, helper, monkeypatch):
        connector = build_connector(helper)
        monkeypatch.setattr("connector.connector.time.sleep", lambda *_: None)
        calls = {"n": 0}

        def flaky():
            calls["n"] += 1
            if calls["n"] == 1:
                raise RuntimeError("transient")
            raise KeyboardInterrupt()

        connector._import_data = MagicMock(side_effect=flaky)
        connector.run()
        assert calls["n"] == 2

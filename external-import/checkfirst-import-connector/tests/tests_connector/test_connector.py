"""Tests for the import loop of `CheckfirstImportConnector`.

The OpenCTI helper and the API client are mocked; STIX conversion and bundle
assembly run for real.
"""

from concurrent.futures import ProcessPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from unittest.mock import MagicMock

import pytest
from checkfirst_client.api_models import Article
from connector import CheckfirstImportConnector, ConnectorSettings
from connector.connector import BundleSendError
from connector.converter_to_stix import ConversionError
from connector.parallel_convert import init_convert_worker
from utils.run_reporter import SkipReason, run_reporter


def _settings(**checkfirst: Any) -> ConnectorSettings:
    class StubConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(
                {
                    "opencti": {"url": "http://localhost:8080", "token": "token"},
                    "connector": {"id": "connector-id", "name": "Test Connector"},
                    "checkfirst": {
                        "api_url": "https://api.checkfirst.example",
                        "api_key": "test-api-key",
                        "since": "2025-01-01T00:00:00Z",
                        **checkfirst,
                    },
                }
            )

    return StubConnectorSettings()


def _article(article_id: str, row_number: int = 1, year: int = 2025) -> Article:
    return Article(
        _id=article_id,
        row_number=row_number,
        url=f"https://france.news-pravda.com/{article_id}",
        source_title=f"Source {article_id}",
        source_url=f"https://t.me/source-{article_id}",
        published_date=datetime(year, 3, 15, tzinfo=timezone.utc),
        title=f"Article {article_id}",
    )


def _make_connector(rows: list[Article], **checkfirst: Any):
    """Build a connector whose API client yields `rows` and whose helper is a mock."""
    helper = MagicMock()
    helper.get_state.return_value = None
    helper.api.work.initiate_work.return_value = "work-id"
    helper.send_stix2_bundle.return_value = ["bundle"]

    connector = CheckfirstImportConnector(config=_settings(**checkfirst), helper=helper)

    api_client = MagicMock()
    api_client.last_seen_id = None

    def iter_api_rows(**_kwargs):
        for row in rows:
            api_client.last_seen_id = row.id
            yield row

    api_client.iter_api_rows.side_effect = iter_api_rows
    connector.api_client = api_client
    return connector, helper


def _saved_cursors(helper: MagicMock) -> list[str | None]:
    return [call.args[0]["last_cursor"] for call in helper.set_state.call_args_list]


@pytest.fixture(autouse=True)
def reset_reporter():
    run_reporter.reset()
    yield
    run_reporter.reset()


def test_rows_are_sent_in_bundles_and_cursor_follows_each_send():
    rows = [_article(f"id-{i}", row_number=i) for i in range(1, 4)]
    connector, helper = _make_connector(rows, bundle_size=1, convert_batch_size=2)

    connector._send_rows_bundles(after=None)

    assert helper.send_stix2_bundle.call_count == 3
    assert helper.api.work.to_processed.call_count == 3
    assert _saved_cursors(helper)[-1] == "id-3"
    assert run_reporter.rows_mapped == 3
    assert run_reporter.bundles_sent == 3


def test_remaining_rows_are_sent_in_a_final_bundle():
    rows = [_article(f"id-{i}", row_number=i) for i in range(1, 4)]
    connector, helper = _make_connector(rows)

    connector._send_rows_bundles(after="id-0")

    connector.api_client.iter_api_rows.assert_called_once()
    assert connector.api_client.iter_api_rows.call_args.kwargs["after"] == "id-0"
    assert helper.send_stix2_bundle.call_count == 1
    assert _saved_cursors(helper) == ["id-3"]


def test_conversion_error_skips_the_row_but_advances_the_cursor(monkeypatch):
    rows = [_article("ok", row_number=1), _article("bad", row_number=2)]
    connector, helper = _make_connector(rows)
    create = connector._create_row_entities

    def create_or_fail(row):
        if row.id == "bad":
            raise ConversionError("cannot convert")
        return create(row)

    monkeypatch.setattr(connector, "_create_row_entities", create_or_fail)

    connector._send_rows_bundles(after=None)

    assert run_reporter.rows_mapped == 1
    assert run_reporter.skipped == {SkipReason.ROW_MAPPING_ERROR.value: 1}
    assert _saved_cursors(helper) == ["bad"]


def test_failed_in_flight_send_stops_without_advancing_the_cursor():
    rows = [_article(f"id-{i}", row_number=i) for i in range(1, 4)]
    connector, helper = _make_connector(rows, bundle_size=1, convert_batch_size=1)
    helper.send_stix2_bundle.side_effect = RuntimeError("OpenCTI is down")

    with pytest.raises(BundleSendError):
        connector._send_rows_bundles(after=None)

    helper.set_state.assert_not_called()
    assert run_reporter.errors == {SkipReason.BUNDLE_SEND_ERROR.value: 1}


def test_unexpected_in_flight_failure_is_wrapped_as_bundle_send_error(monkeypatch):
    rows = [_article(f"id-{i}", row_number=i) for i in range(1, 3)]
    connector, helper = _make_connector(rows, bundle_size=1, convert_batch_size=1)
    monkeypatch.setattr(
        connector,
        "_prepare_rows_bundle",
        MagicMock(side_effect=ValueError("bad objects")),
    )

    with pytest.raises(BundleSendError):
        connector._send_rows_bundles(after=None)

    helper.set_state.assert_not_called()


def test_no_rows_neither_sends_nor_saves():
    connector, helper = _make_connector([])

    connector._send_rows_bundles(after="id-9")

    helper.send_stix2_bundle.assert_not_called()
    helper.set_state.assert_not_called()


def test_skipped_tail_still_advances_the_cursor():
    connector, helper = _make_connector([])
    connector.api_client.last_seen_id = "id-skipped"

    connector._send_rows_bundles(after="id-0")

    helper.send_stix2_bundle.assert_not_called()
    assert _saved_cursors(helper) == ["id-skipped"]


def test_final_cursor_includes_rows_skipped_after_the_last_valid_row():
    connector, helper = _make_connector([_article("id-1")])
    iter_rows = connector.api_client.iter_api_rows.side_effect

    def iter_rows_then_skip_tail(**kwargs):
        yield from iter_rows(**kwargs)
        # Rows fetched but dropped by the client (too large, invalid)
        connector.api_client.last_seen_id = "id-3"

    connector.api_client.iter_api_rows.side_effect = iter_rows_then_skip_tail

    connector._send_rows_bundles(after=None)

    assert helper.send_stix2_bundle.call_count == 1
    assert _saved_cursors(helper) == ["id-3"]


def test_convert_batch_uses_the_process_pool_in_row_order():
    rows = [_article(f"id-{i}", row_number=i) for i in range(1, 5)]
    connector, _helper = _make_connector(rows)

    with ProcessPoolExecutor(
        max_workers=2, initializer=init_convert_worker, initargs=("clear",)
    ) as pool:
        converted = connector._convert_batch(rows, pool)

    assert [row.id for row, _entities, _error in converted] == [r.id for r in rows]
    assert all(error is None and entities for _row, entities, error in converted)
    assert connector._convert_batch([], pool) == []


def test_send_bundle_with_no_objects_is_a_no_op():
    connector, helper = _make_connector([])

    timings = connector._send_bundle([])

    assert timings["objects_count"] == 0
    helper.api.work.initiate_work.assert_not_called()


@dataclass(eq=False)
class _Entity:
    id: str
    external_references: list[str] | None


def test_prepare_bundle_merges_channel_references_and_dedupes_by_id():
    connector, _helper = _make_connector([])
    channel_a = _Entity("channel--1", None)
    channel_b = _Entity("channel--1", ["ref-b"])
    channel_c = _Entity("channel--1", ["ref-c"])
    other_a = _Entity("domain-name--1", ["ref-x"])
    other_b = _Entity("domain-name--1", ["ref-y"])

    bundle = connector._prepare_rows_bundle(
        [channel_a, channel_b, channel_c, other_a, other_b]
    )

    assert bundle == [channel_a, other_a]
    assert channel_a.external_references == ["ref-b", "ref-c"]
    assert other_a.external_references == ["ref-x"]


def test_process_message_on_fresh_state_sends_infrastructure_then_rows():
    connector, helper = _make_connector([_article("id-1")])

    connector.process_message()

    assert connector.api_client.iter_api_rows.call_args.kwargs["after"] is None
    # Infrastructure bundle + rows bundle
    assert helper.send_stix2_bundle.call_count == 2
    final_state = helper.set_state.call_args.args[0]
    assert final_state["last_cursor"] == "id-1"
    assert "last_run" in final_state


def test_process_message_resumes_from_saved_cursor():
    connector, helper = _make_connector([_article("id-2")])
    helper.get_state.return_value = {
        "last_run": "2025-01-01T00:00:00+00:00",
        "last_cursor": "id-1",
    }

    connector.process_message()

    assert connector.api_client.iter_api_rows.call_args.kwargs["after"] == "id-1"
    # No infrastructure bundle on resume
    assert helper.send_stix2_bundle.call_count == 1


def test_process_message_force_reprocess_restarts_from_the_beginning():
    connector, helper = _make_connector([], force_reprocess=True)
    helper.get_state.return_value = {"last_cursor": "id-1"}

    connector.process_message()

    assert connector.api_client.iter_api_rows.call_args.kwargs["after"] is None
    assert helper.set_state.call_args.args[0]["last_cursor"] is None


def test_process_message_runs_conversion_in_a_process_pool():
    rows = [_article(f"id-{i}", row_number=i) for i in range(1, 4)]
    connector, helper = _make_connector(rows, convert_workers=2)
    helper.get_state.return_value = {"last_cursor": "id-0"}

    connector.process_message()

    assert helper.send_stix2_bundle.call_count == 1
    sent_objects = "".join(
        obj.serialize() for obj in helper.stix2_create_bundle.call_args.args[0]
    )
    assert all(
        f"https://france.news-pravda.com/{row.id}" in sent_objects for row in rows
    )
    assert helper.set_state.call_args.args[0]["last_cursor"] == "id-3"


def test_process_message_ends_the_run_on_bundle_send_failure():
    connector, helper = _make_connector([_article("id-1")])
    helper.send_stix2_bundle.side_effect = RuntimeError("OpenCTI is down")

    connector.process_message()

    # Only the final `last_run` save, without a cursor
    assert _saved_cursors(helper) == [None]


def test_process_message_logs_unexpected_errors():
    connector, helper = _make_connector([])
    helper.get_state.return_value = {"last_cursor": "id-1"}
    connector.api_client.iter_api_rows.side_effect = RuntimeError("boom")

    connector.process_message()

    connector.logger.error.assert_called_once()
    helper.set_state.assert_called_once()


def test_process_message_exits_cleanly_on_interrupt():
    connector, helper = _make_connector([])
    helper.get_state.side_effect = KeyboardInterrupt

    with pytest.raises(SystemExit) as exit_info:
        connector.process_message()

    assert exit_info.value.code == 0
    helper.set_state.assert_called_once()


def test_run_schedules_process_message():
    connector, helper = _make_connector([])

    connector.run()

    helper.schedule_iso.assert_called_once()
    kwargs = helper.schedule_iso.call_args.kwargs
    assert kwargs["message_callback"] == connector.process_message

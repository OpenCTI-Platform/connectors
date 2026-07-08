from datetime import timedelta
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from connector.connector import SpurConnector


def make_config(feed_urls=None, batch_size=5000, duration_period=timedelta(hours=24)):
    spur = SimpleNamespace(
        api_key=MagicMock(),
        feed_urls=feed_urls if feed_urls is not None else ["https://feed"],
        batch_size=batch_size,
    )
    connector = SimpleNamespace(duration_period=duration_period)
    return SimpleNamespace(spur=spur, connector=connector)


@pytest.fixture
def connector():
    with patch("connector.connector.SpurClient") as client_cls, patch(
        "connector.connector.ConverterToStix"
    ) as conv_cls:
        helper = MagicMock()
        conn = SpurConnector(config=make_config(), helper=helper)
        conn.client = client_cls.return_value
        conn.converter = conv_cls.return_value
        conn.converter.author = "author"
        conn.converter.tlp_marking = "tlp"
        yield conn


def test_flush_batch_empty_does_nothing(connector):
    connector._flush_batch([], "work-1")
    connector.helper.send_stix2_bundle.assert_not_called()


def test_flush_batch_sends_bundle(connector):
    connector.helper.stix2_create_bundle.return_value = "bundle"
    connector._flush_batch(["obj-a", "obj-b"], "work-1")

    connector.helper.stix2_create_bundle.assert_called_once_with(
        ["author", "tlp", "obj-a", "obj-b"]
    )
    connector.helper.send_stix2_bundle.assert_called_once_with(
        "bundle", work_id="work-1", cleanup_inconsistent_bundle=True
    )


def test_collect_intelligence_batches_by_size(connector):
    connector.config.spur.batch_size = 2
    connector.config.spur.feed_urls = ["https://feed"]
    connector.client.stream_feed.return_value = iter(
        [{"ip": "1"}, {"ip": "2"}, {"ip": "3"}]
    )
    connector.converter.convert_ip_context.side_effect = lambda r: [r["ip"]]

    connector._collect_intelligence("work-1")

    # 3 records, batch_size 2 -> flush at record 2, final flush of remainder
    assert connector.helper.send_stix2_bundle.call_count == 2


def test_collect_intelligence_no_records(connector):
    connector.client.stream_feed.return_value = iter([])

    connector._collect_intelligence("work-1")

    # only the final (empty) flush attempt -> no send
    connector.helper.send_stix2_bundle.assert_not_called()


def test_process_message_first_run(connector):
    connector.helper.get_state.return_value = None
    connector.helper.connect_id = "cid"
    connector.helper.api.work.initiate_work.return_value = "work-1"
    connector.client.stream_feed.return_value = iter([])

    connector.process_message()

    connector.helper.api.work.initiate_work.assert_called_once()
    connector.helper.set_state.assert_called_once()
    state = connector.helper.set_state.call_args[0][0]
    assert "last_run" in state
    connector.helper.api.work.to_processed.assert_called_once()


def test_process_message_with_previous_state(connector):
    connector.helper.get_state.return_value = {"last_run": "2020-01-01T00:00:00"}
    connector.helper.api.work.initiate_work.return_value = "work-1"
    connector.client.stream_feed.return_value = iter([])

    connector.process_message()

    connector.helper.set_state.assert_called_once()


def test_process_message_keyboard_interrupt_exits(connector):
    connector.helper.get_state.side_effect = KeyboardInterrupt()

    with pytest.raises(SystemExit):
        connector.process_message()


def test_process_message_reraises_exception(connector):
    connector.helper.get_state.side_effect = RuntimeError("boom")

    with pytest.raises(RuntimeError):
        connector.process_message()
    connector.helper.connector_logger.error.assert_called_once()


def test_run_schedules_process(connector):
    connector.run()

    connector.helper.schedule_process.assert_called_once()
    kwargs = connector.helper.schedule_process.call_args.kwargs
    assert kwargs["message_callback"] == connector.process_message
    assert kwargs["duration_period"] == timedelta(hours=24).total_seconds()

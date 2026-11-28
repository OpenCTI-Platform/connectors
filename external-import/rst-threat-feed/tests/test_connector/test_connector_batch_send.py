from unittest.mock import MagicMock, patch

import pytest
from connector.connector import RSTThreatFeed
from connector.feed_converter import FeedType
from connector.settings import ConnectorSettings


class StubConnectorSettings(ConnectorSettings):
    @classmethod
    def _load_config_dict(cls, _, handler):
        return handler(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                "connector": {
                    "id": "connector-id",
                    "name": "RST Threat Feed",
                    "scope": "application/json",
                    "log_level": "error",
                    "duration_period": "PT24H",
                },
                "rst_threat_feed": {
                    "baseurl": "http://test.com",
                    "apikey": "test-api-key",
                    "domain": True,
                    "ip": False,
                    "url": False,
                    "hash": False,
                },
            }
        )


@pytest.fixture
def connector():
    settings = StubConnectorSettings()
    helper = MagicMock()
    helper.connector_logger = MagicMock()
    helper.connect_id = "connector-id"
    helper.connect_run_and_terminate = False
    helper.get_state.return_value = {}
    helper.api.work.initiate_work.return_value = "work-1"
    helper.stix2_create_bundle.return_value = '{"type":"bundle","objects":[]}'
    helper.send_stix2_bundle.return_value = ["bundle-sent"]
    return RSTThreatFeed(config=settings, helper=helper)


def test_batch_send_uses_helper_bundle_pattern(connector):
    stix_object = MagicMock()
    stix_object.type = "indicator"
    stix_object.id = "indicator--1"
    stix_object.serialize.return_value = '{"type":"indicator","id":"indicator--1"}'

    ok = connector._batch_send_one(
        [stix_object], timestamp=1_700_000_000, feed_type="domain"
    )

    assert ok is True
    connector.helper.stix2_create_bundle.assert_called_once()
    kwargs = connector.helper.send_stix2_bundle.call_args.kwargs
    assert kwargs["cleanup_inconsistent_bundle"] is True
    assert kwargs["work_id"] == "work-1"


def test_batch_send_marks_failed_work_on_retry(connector, monkeypatch):
    stix_object = MagicMock()
    stix_object.type = "indicator"
    stix_object.id = "indicator--1"
    connector._max_retries = 2
    connector.helper.send_stix2_bundle.side_effect = [
        ConnectionError("temporary"),
        ["bundle-sent"],
    ]
    monkeypatch.setattr("connector.connector.time.sleep", lambda _: None)

    ok = connector._batch_send_one(
        [stix_object], timestamp=1_700_000_000, feed_type="domain"
    )

    assert ok is True
    assert connector.helper.send_stix2_bundle.call_count == 2
    first = connector.helper.api.work.to_processed.call_args_list[0]
    assert first.kwargs.get("in_error") is True


def test_batch_send_returns_false_after_retries_exhausted(connector, monkeypatch):
    stix_object = MagicMock(type="indicator", id="indicator--1")
    connector._max_retries = 2
    connector.helper.send_stix2_bundle.side_effect = ConnectionError("down")
    monkeypatch.setattr("connector.connector.time.sleep", lambda _: None)

    ok = connector._batch_send_one(
        [stix_object], timestamp=1_700_000_000, feed_type="domain"
    )

    assert ok is False
    assert connector.helper.send_stix2_bundle.call_count == 2


def test_batch_send_raises_on_non_retryable_error(connector):
    stix_object = MagicMock(type="indicator", id="indicator--1")
    connector.helper.send_stix2_bundle.side_effect = ValueError("bad bundle")

    with pytest.raises(ValueError, match="bad bundle"):
        connector._batch_send_one(
            [stix_object], timestamp=1_700_000_000, feed_type="domain"
        )


def test_order_stix_objects_author_marking_entities_relationships(connector):
    author = MagicMock(
        type="identity", id="identity--author", identity_class="organization"
    )
    sector = MagicMock(type="identity", id="identity--sector", identity_class="class")
    marking = MagicMock(type="marking-definition", id="marking--1")
    indicator = MagicMock(type="indicator", id="indicator--1")
    relationship = MagicMock(type="relationship", id="relationship--1")

    ordered = connector._order_stix_objects(
        [relationship, indicator, sector, marking, author]
    )
    assert [obj.id for obj in ordered] == [
        "identity--author",
        "marking--1",
        "identity--sector",
        "indicator--1",
        "relationship--1",
    ]


def test_batch_send_sends_one_ordered_bundle(connector):
    author = MagicMock(
        type="identity", id="identity--author", identity_class="organization"
    )
    marking = MagicMock(type="marking-definition", id="marking--1")
    indicators = [MagicMock(type="indicator", id=f"indicator--{i}") for i in range(8)]
    objects = indicators + [marking, author]

    sent = []

    def capture(chunk, timestamp, feed_type):
        sent.append(chunk)
        return True

    connector._batch_send_one = capture
    ok = connector._batch_send(objects, timestamp=1_700_000_000, feed_type="domain")

    assert ok is True
    assert len(sent) == 1
    assert [obj.id for obj in sent[0]] == [
        "identity--author",
        "marking--1",
        *[f"indicator--{i}" for i in range(8)],
    ]


def test_batch_send_empty_list_is_noop(connector):
    assert connector._batch_send([], timestamp=1, feed_type="domain") is True
    connector.helper.send_stix2_bundle.assert_not_called()


def test_feed_enabled_and_rejects_unknown(connector):
    assert connector.feed_enabled(FeedType.DOMAIN) is True
    assert connector.feed_enabled(FeedType.IP) is False
    with pytest.raises(ValueError, match="Only"):
        connector.feed_enabled("email")


def test_process_feed_success_sends_and_cleans_file(connector, tmp_path):
    feed_file = tmp_path / "feed.json"
    feed_file.write_text("{}\n", encoding="utf-8")
    stix_object = MagicMock(type="indicator", id="indicator--1")

    mock_client = MagicMock()
    mock_client.get_feed.return_value = {
        "status": "ok",
        "message": str(feed_file),
    }

    with patch("connector.connector.ThreatFeedClient", return_value=mock_client):
        with patch.object(
            connector, "_create_stix_objects", return_value=[stix_object]
        ) as create:
            with patch.object(connector, "_batch_send", return_value=True) as send:
                connector._process_feed(FeedType.DOMAIN, timestamp=1_700_000_000)

    create.assert_called_once_with(str(feed_file), FeedType.DOMAIN)
    send.assert_called_once()
    assert not feed_file.exists()


def test_process_feed_download_error_skips_send(connector):
    mock_client = MagicMock()
    mock_client.get_feed.return_value = {"status": "error", "message": "denied"}

    with patch("connector.connector.ThreatFeedClient", return_value=mock_client):
        with patch.object(connector, "_batch_send") as send:
            connector._process_feed(FeedType.DOMAIN, timestamp=1_700_000_000)

    send.assert_not_called()
    connector.helper.connector_logger.error.assert_called()


def test_process_feed_no_stix_objects(connector, tmp_path):
    feed_file = tmp_path / "feed.json"
    feed_file.write_text("{}\n", encoding="utf-8")
    mock_client = MagicMock()
    mock_client.get_feed.return_value = {
        "status": "ok",
        "message": str(feed_file),
    }

    with patch("connector.connector.ThreatFeedClient", return_value=mock_client):
        with patch.object(connector, "_create_stix_objects", return_value=[]):
            with patch.object(connector, "_batch_send") as send:
                connector._process_feed(FeedType.DOMAIN, timestamp=1_700_000_000)

    send.assert_not_called()
    assert not feed_file.exists()


def test_process_message_runs_enabled_feeds(connector):
    connector.mitre_downloader = MagicMock()
    connector.mitre_downloader.download_mitre_ttps.return_value = "map.json"
    connector.mitre_downloader.load_ttp_mapping.return_value = {"T1059": "Cmd"}

    with patch.object(connector, "_publish_connector_info"):
        with patch.object(connector, "_process_feed") as process_feed:
            connector.process_message()

    process_feed.assert_called_once_with(FeedType.DOMAIN, process_feed.call_args[0][1])
    connector.helper.set_state.assert_called_once()
    assert "last_run" in connector.helper.set_state.call_args[0][0]


def test_stix_type_and_id_falls_back_to_serialize(connector):
    obj = MagicMock(spec=[])
    obj.serialize.return_value = '{"type":"indicator","id":"indicator--9"}'
    assert connector._stix_type_and_id(obj) == ("indicator", "indicator--9")

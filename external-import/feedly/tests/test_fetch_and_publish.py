import json
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

from feedly.opencti_connector.connector import FeedlyConnector


def _make_batch(objects):
    return {"type": "bundle", "id": "bundle--batch", "objects": objects}


def _report(report_id, published, source_name="TestSource"):
    return {
        "type": "report",
        "id": f"report--{report_id}",
        "name": f"Report {report_id}",
        "description": "Some description",
        "published": published,
        "external_references": [
            {"source_name": "Feedly"},
            {"source_name": source_name},
        ],
        "object_refs": [],
    }


def _indicator(indicator_id):
    return {
        "type": "indicator",
        "id": f"indicator--{indicator_id}",
        "pattern": "[ipv4-addr:value = '1.2.3.4']",
    }


@patch("feedly.opencti_connector.connector.FeedlySession")
@patch("feedly.opencti_connector.connector.StixIoCDownloader")
class TestFetchAndPublish:
    def test_sends_each_batch_separately(self, mock_downloader_cls, mock_session_cls):
        batch1 = _make_batch([_report("1", "2026-01-01T00:00:00Z"), _indicator("a")])
        batch2 = _make_batch([_report("2", "2026-01-02T00:00:00Z"), _indicator("b")])
        mock_downloader_cls.return_value.stream_bundles.return_value = iter(
            [batch1, batch2]
        )
        helper = MagicMock()

        connector = FeedlyConnector("fake-key", helper)
        connector.fetch_and_publish(
            "stream-1", datetime(2026, 1, 1, tzinfo=timezone.utc)
        )

        assert helper.send_stix2_bundle.call_count == 2

    def test_returns_latest_published_date_across_batches(
        self, mock_downloader_cls, mock_session_cls
    ):
        batch1 = _make_batch([_report("1", "2026-01-05T00:00:00Z")])
        batch2 = _make_batch([_report("2", "2026-01-03T00:00:00Z")])
        batch3 = _make_batch([_report("3", "2026-01-07T00:00:00Z")])
        mock_downloader_cls.return_value.stream_bundles.return_value = iter(
            [batch1, batch2, batch3]
        )
        helper = MagicMock()

        connector = FeedlyConnector("fake-key", helper)
        result = connector.fetch_and_publish(
            "stream-1", datetime(2026, 1, 1, tzinfo=timezone.utc)
        )

        assert result == "2026-01-07T00:00:00Z"

    def test_returns_none_when_no_objects(self, mock_downloader_cls, mock_session_cls):
        empty_batch = _make_batch([])
        mock_downloader_cls.return_value.stream_bundles.return_value = iter(
            [empty_batch]
        )
        helper = MagicMock()

        connector = FeedlyConnector("fake-key", helper)
        result = connector.fetch_and_publish(
            "stream-1", datetime(2026, 1, 1, tzinfo=timezone.utc)
        )

        assert result is None
        helper.send_stix2_bundle.assert_not_called()

    def test_returns_none_when_no_batches(self, mock_downloader_cls, mock_session_cls):
        mock_downloader_cls.return_value.stream_bundles.return_value = iter([])
        helper = MagicMock()

        connector = FeedlyConnector("fake-key", helper)
        result = connector.fetch_and_publish(
            "stream-1", datetime(2026, 1, 1, tzinfo=timezone.utc)
        )

        assert result is None
        helper.send_stix2_bundle.assert_not_called()

    def test_skips_batches_with_empty_objects_after_processing(
        self, mock_downloader_cls, mock_session_cls
    ):
        non_empty = _make_batch([_report("1", "2026-02-01T00:00:00Z")])
        empty = _make_batch([])
        mock_downloader_cls.return_value.stream_bundles.return_value = iter(
            [empty, non_empty, empty]
        )
        helper = MagicMock()

        connector = FeedlyConnector("fake-key", helper)
        connector.fetch_and_publish(
            "stream-1", datetime(2026, 1, 1, tzinfo=timezone.utc)
        )

        assert helper.send_stix2_bundle.call_count == 1

    def test_bundles_are_valid_json_with_correct_objects(
        self, mock_downloader_cls, mock_session_cls
    ):
        report = _report("1", "2026-03-01T00:00:00Z")
        indicator = _indicator("a")
        batch = _make_batch([report, indicator])
        mock_downloader_cls.return_value.stream_bundles.return_value = iter([batch])
        helper = MagicMock()

        connector = FeedlyConnector("fake-key", helper)
        connector.fetch_and_publish(
            "stream-1", datetime(2026, 1, 1, tzinfo=timezone.utc)
        )

        sent_json = helper.send_stix2_bundle.call_args[0][0]
        sent_bundle = json.loads(sent_json)
        types = {o["type"] for o in sent_bundle["objects"]}
        assert "report" in types
        assert "indicator" in types

    def test_logs_total_report_count(self, mock_downloader_cls, mock_session_cls):
        batch1 = _make_batch(
            [_report("1", "2026-01-01T00:00:00Z"), _report("2", "2026-01-02T00:00:00Z")]
        )
        batch2 = _make_batch([_report("3", "2026-01-03T00:00:00Z")])
        mock_downloader_cls.return_value.stream_bundles.return_value = iter(
            [batch1, batch2]
        )
        helper = MagicMock()

        connector = FeedlyConnector("fake-key", helper)
        connector.fetch_and_publish(
            "stream-1", datetime(2026, 1, 1, tzinfo=timezone.utc)
        )

        helper.log_info.assert_called_with("Found 3 new reports")

    def test_downloader_receives_correct_parameters(
        self, mock_downloader_cls, mock_session_cls
    ):
        mock_downloader_cls.return_value.stream_bundles.return_value = iter([])
        helper = MagicMock()
        newer_than = datetime(2026, 5, 1, 12, 0, 0, tzinfo=timezone.utc)

        connector = FeedlyConnector("fake-key", helper)
        connector.fetch_and_publish("my-stream-id", newer_than)

        mock_downloader_cls.assert_called_once_with(
            session=connector.feedly_session,
            newer_than=newer_than,
            older_than=None,
            stream_id="my-stream-id",
        )

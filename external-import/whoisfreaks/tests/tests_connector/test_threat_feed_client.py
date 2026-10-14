from datetime import date
from io import BytesIO
from unittest.mock import MagicMock

from whoisfreaks_client.api_client import ThreatFeedPage, WhoisFreaksClient


class _AutoClosingBytesIO(BytesIO):
    """BytesIO that closes itself after EOF, like urllib3 response.raw."""

    def read(self, size=-1):
        data = super().read(size)
        if not data:
            self.close()
        return data


def test_parse_csv_stream_survives_auto_closed_raw():
    payload = (
        "domain,threat_type,confidence,first_seen,last_seen,"
        "No_of_threat_matched_pivots\n"
        "example.com,malware,1,2026-09-01 10:00:00+00,"
        "2026-09-02 10:00:00+00,3\n"
    )
    response = MagicMock()
    response.encoding = "utf-8"
    response.raw = _AutoClosingBytesIO(payload.encode("utf-8"))
    response.close.return_value = None

    client = WhoisFreaksClient("test-api-key")
    records = client._parse_csv_stream(response)

    assert len(records) == 1
    assert records[0].domain == "example.com"
    response.close.assert_called_once()


def test_parse_csv_skips_repeated_header():
    payload = (
        "domain,threat_type,confidence,first_seen,last_seen,response_detail,empty_column,"
        "No_of_threat_matched_pivots\n"
        "example.com,malware,1,2026-09-01 10:00:00+00,"
        "2026-09-02 10:00:00.123456+00,source value,,3\n"
        "domain,threat_type,confidence,first_seen,last_seen,response_detail,empty_column,"
        "No_of_threat_matched_pivots\n"
        "example.org,malware,0.75,2026-09-01 11:00:00+00,"
        "2026-09-02 11:00:00+00,another value,,1\n"
    )
    records = WhoisFreaksClient._parse_csv(payload)
    assert len(records) == 2
    assert records[0].domain == "example.com"
    assert records[0].confidence_score == 1
    assert records[0].source_fields["response_detail"] == "source value"
    assert records[0].source_fields["empty_column"] == ""
    assert records[1].no_of_threat_matched_pivots == 1


def test_parse_csv_logs_malformed_record_and_keeps_valid_ones(caplog):
    """Malformed rows are logged and skipped without aborting the page."""
    payload = (
        "domain,threat_type,confidence,first_seen,last_seen,"
        "No_of_threat_matched_pivots\n"
        "example.com,malware,not-a-number,2026-09-01 10:00:00+00,"
        "2026-09-02 10:00:00+00,1\n"
        "example.org,malware,0.9,2026-09-01 11:00:00+00,"
        "2026-09-02 11:00:00+00,2\n"
    )
    records = WhoisFreaksClient._parse_csv(payload)
    assert len(records) == 1
    assert records[0].domain == "example.org"
    assert records.source_record_count == 2
    assert "Skipping malformed" in caplog.text


def test_iter_retries_rate_limit_then_succeeds(monkeypatch):
    payload = (
        "domain,threat_type,confidence,first_seen,last_seen,"
        "No_of_threat_matched_pivots\n"
        "example.com,malware,1,2026-09-01 10:00:00+00,"
        "2026-09-02 10:00:00+00,1\n"
    )
    rate_limited = MagicMock(status_code=429)
    response = MagicMock(status_code=200)
    response.encoding = "utf-8"
    response.raw = BytesIO(payload.encode("utf-8"))
    response.raise_for_status.return_value = None
    response.close.return_value = None
    client = WhoisFreaksClient(
        "test-api-key",
        max_retries=1,
        retry_backoff_seconds=0.25,
    )
    monkeypatch.setattr(
        client._session, "get", MagicMock(side_effect=[rate_limited, response])
    )
    sleep = MagicMock()
    monkeypatch.setattr("whoisfreaks_client.api_client.time.sleep", sleep)

    pages = list(
        client.iter_threat_feed(
            feed_type="malware",
            feed_date=date(2026, 9, 1),
            limit=10,
        )
    )

    assert len(pages) == 1
    assert pages[0][0].domain == "example.com"
    assert client._session.get.call_count == 2
    rate_limited.close.assert_called_once()
    sleep.assert_called_once_with(0.25)


def test_iter_continues_after_malformed_only_page():
    client = WhoisFreaksClient("test-api-key", max_retries=0)
    client._fetch_page = MagicMock(
        side_effect=[ThreatFeedPage([], 2), ThreatFeedPage([], 1)]
    )

    pages = list(
        client.iter_threat_feed(
            feed_type="malware",
            feed_date=date(2026, 9, 1),
            limit=2,
        )
    )

    assert [page.source_record_count for page in pages] == [2, 1]
    assert [call.kwargs["offset"] for call in client._fetch_page.call_args_list] == [
        0,
        2,
    ]

from datetime import date
from io import BytesIO
from unittest.mock import MagicMock

import pytest
import requests
from whoisfreaks_client.api_client import (
    ThreatFeedPage,
    WhoisFreaksClient,
    WhoisFreaksClientError,
)


class _AutoClosingBytesIO(BytesIO):
    """BytesIO that closes as soon as its last byte is read, like urllib3.

    urllib3 closes response.raw on the read that returns the final bytes
    (not on a later empty read) unless ``auto_close`` is False. TextIOWrapper
    reads through ``read1()``, so both methods are covered.
    """

    auto_close = True

    def _close_at_end(self, data):
        if self.auto_close and data and self.tell() == len(self.getbuffer()):
            self.close()
        return data

    def read(self, size=-1):
        return self._close_at_end(super().read(size))

    def read1(self, size=-1):
        return self._close_at_end(super().read1(size))


def test_parse_csv_stream_survives_auto_closed_raw():
    payload = (
        "domain,threat_type,confidence,first_seen,last_seen,"
        "No_of_threat_matched_pivots\n"
        "example.com,malware,1,2026-09-01 10:00:00+00,"
        "2026-09-02 10:00:00+00,3\n"
        "example.org,phishing,0.5,2026-09-01 11:00:00+00,"
        "2026-09-02 11:00:00+00,1\n"
    )
    response = MagicMock()
    response.encoding = "utf-8"
    response.raw = _AutoClosingBytesIO(payload.encode("utf-8"))
    response.close.return_value = None

    client = WhoisFreaksClient("test-api-key")
    records = client._parse_csv_stream(response)

    # Rows still buffered in TextIOWrapper after the raw stream hit EOF.
    assert [r.domain for r in records] == ["example.com", "example.org"]
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


def test_parse_csv_skips_row_with_missing_timestamp(caplog):
    payload = (
        "domain,threat_type,confidence,first_seen,last_seen,"
        "No_of_threat_matched_pivots\n"
        "example.com,malware,0.9\n"
        "example.org,malware,0.9,2026-09-01 11:00:00+00,"
        "2026-09-02 11:00:00+00,2\n"
    )

    records = WhoisFreaksClient._parse_csv(payload)

    assert [record.domain for record in records] == ["example.org"]
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


@pytest.mark.parametrize("status_code", [400, 404])
def test_iter_does_not_retry_permanent_http_errors(monkeypatch, status_code):
    response = MagicMock(status_code=status_code)
    response.raise_for_status.side_effect = requests.HTTPError(response=response)
    client = WhoisFreaksClient("test-api-key", max_retries=3)
    get = MagicMock(return_value=response)
    monkeypatch.setattr(client._session, "get", get)
    sleep = MagicMock()
    monkeypatch.setattr("whoisfreaks_client.api_client.time.sleep", sleep)

    with pytest.raises(WhoisFreaksClientError, match=f"HTTP {status_code}"):
        list(
            client.iter_threat_feed(
                feed_type="malware",
                feed_date=date(2026, 9, 1),
                limit=10,
            )
        )

    assert get.call_count == 1
    sleep.assert_not_called()
    response.close.assert_called_once()


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


def test_client_does_not_advertise_compression():
    """Feeds are plain-text CSV read from undecoded response.raw."""
    client = WhoisFreaksClient("test-api-key")
    assert client._session.headers["Accept-Encoding"] == "identity"


def test_parse_csv_raises_on_missing_domain_header():
    """A nonempty CSV response without a 'domain' header must raise, not silently return empty."""
    payload = "threat_type,confidence,first_seen,last_seen,No_of_threat_matched_pivots\nmalware,1,2026-09-01 10:00:00+00,2026-09-02 10:00:00+00,1\n"
    with pytest.raises(
        WhoisFreaksClientError, match="missing required 'domain' header"
    ):
        WhoisFreaksClient._parse_csv(payload)


def test_iter_retries_threat_feed_stream_transport_error(monkeypatch):
    """urllib3 transport errors raised during threat-feed stream reads are retried."""
    import urllib3.exceptions

    good_payload = (
        "domain,threat_type,confidence,first_seen,last_seen,No_of_threat_matched_pivots\n"
        "example.com,malware,1,2026-09-01 10:00:00+00,2026-09-02 10:00:00+00,1\n"
    )

    class _FailingRaw(BytesIO):
        auto_close = True

        def read(self, size=-1):
            raise urllib3.exceptions.ProtocolError("connection broken")

        def read1(self, size=-1):
            raise urllib3.exceptions.ProtocolError("connection broken")

    call_count = 0

    def fake_get(url, params=None, timeout=None, stream=False):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            response = MagicMock()
            response.status_code = 200
            response.encoding = "utf-8"
            response.raise_for_status.return_value = None
            response.close.return_value = None
            response.raw = _FailingRaw(b"domain,threat_type\n")
            return response
        resp = MagicMock(status_code=200)
        resp.encoding = "utf-8"
        resp.raw = BytesIO(good_payload.encode())
        resp.raise_for_status.return_value = None
        resp.close.return_value = None
        return resp

    client = WhoisFreaksClient("test-api-key", max_retries=1, retry_backoff_seconds=0)
    monkeypatch.setattr(client._session, "get", fake_get)
    sleep = MagicMock()
    monkeypatch.setattr("whoisfreaks_client.api_client.time.sleep", sleep)

    pages = list(
        client.iter_threat_feed(
            feed_type="malware",
            feed_date=date(2026, 9, 1),
            limit=10,
        )
    )

    assert call_count == 2
    assert [r.domain for r in pages[0]] == ["example.com"]

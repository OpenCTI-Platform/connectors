from datetime import date
from io import BytesIO
from unittest.mock import MagicMock

import pytest
import requests
from whoisfreaks_client.nrd_client import (
    NRDPage,
    WhoisFreaksNRDClient,
    WhoisFreaksNRDError,
)


def test_parse_whois_csv():
    payload = (
        "domain_name,domain_registrar_id,domain_registrar_name,"
        "registrant_name,registrant_company,registrant_country_code,"
        "name_server_1,name_server_2,domain_status_1\n"
        '"example.co.uk","1515","123-Reg Limited",'
        '"Example Owner","Example Ltd","GB",'
        '"ns1.example.com","ns2.example.com",'
        '"clienttransferprohibited"\n'
    )

    records = WhoisFreaksNRDClient._parse_whois_csv(payload)

    assert len(records) == 1

    record = records[0]

    assert record.domain_name == "example.co.uk"
    assert record.fields["domain_name"] == "example.co.uk"
    assert record.fields["domain_registrar_id"] == "1515"
    assert record.fields["domain_registrar_name"] == "123-Reg Limited"
    assert record.fields["registrant_name"] == "Example Owner"
    assert record.fields["registrant_company"] == "Example Ltd"
    assert record.fields["registrant_country_code"] == "GB"
    assert record.fields["name_server_1"] == "ns1.example.com"
    assert record.fields["name_server_2"] == "ns2.example.com"
    assert record.fields["domain_status_1"] == "clienttransferprohibited"


def test_parse_domains_without_whois_header():
    payload = """thecostumecreative.co.uk
rpff-ayxtiyu.com.cn
vybely.io
sitesbyoliver.ca
apotheke-zollstock.de
"""

    records = WhoisFreaksNRDClient._parse_domains(payload)

    assert len(records) == 5

    assert [record.domain_name for record in records] == [
        "thecostumecreative.co.uk",
        "rpff-ayxtiyu.com.cn",
        "vybely.io",
        "sitesbyoliver.ca",
        "apotheke-zollstock.de",
    ]


def test_domains_without_whois_do_not_treat_first_domain_as_header():
    payload = "example.com\nexample.org\n"

    records = WhoisFreaksNRDClient._parse_domains(payload)

    assert len(records) == 2
    assert records[0].domain_name == "example.com"
    assert records[1].domain_name == "example.org"


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


def _fake_response(payload: str, status_code: int = 200):
    response = MagicMock()
    response.status_code = status_code
    response.encoding = "utf-8"
    response.raw = BytesIO(payload.encode("utf-8"))
    response.raise_for_status.return_value = None
    response.close.return_value = None
    return response


def test_parse_whois_stream_survives_auto_closed_raw():
    payload = (
        "domain_name,create_date\nexample.com,2026-09-01\nexample.org,2026-09-02\n"
    )
    response = MagicMock()
    response.encoding = "utf-8"
    response.raw = _AutoClosingBytesIO(payload.encode("utf-8"))
    response.close.return_value = None

    client = WhoisFreaksNRDClient("test-api-key")
    records = client._parse_whois_stream(response)

    assert [r.domain_name for r in records] == ["example.com", "example.org"]
    response.close.assert_called_once()


def test_parse_domains_stream_survives_auto_closed_raw():
    payload = "example.com\nexample.org\n"
    response = MagicMock()
    response.encoding = "utf-8"
    response.raw = _AutoClosingBytesIO(payload.encode("utf-8"))
    response.close.return_value = None

    client = WhoisFreaksNRDClient("test-api-key")
    records = client._parse_domains_stream(response)

    assert [r.domain_name for r in records] == ["example.com", "example.org"]
    response.close.assert_called_once()


def test_iter_whois_feed_uses_expected_parameters(monkeypatch):
    payload = "domain_name,create_date\n" "example.com,2026-09-01\n"

    calls = []

    def fake_get(url, params=None, timeout=None, stream=False):
        calls.append(
            {
                "url": url,
                "params": params,
                "timeout": timeout,
                "stream": stream,
            }
        )
        return _fake_response(payload)

    client = WhoisFreaksNRDClient("test-api-key")
    monkeypatch.setattr(client._session, "get", fake_get)

    pages = list(
        client.iter_feed(
            feed_type="gtld",
            whois=True,
            feed_date=date(2026, 9, 1),
            limit=100,
        )
    )

    assert len(pages) == 1
    assert pages[0][0].domain_name == "example.com"

    assert calls[0]["url"].endswith("/gtld")
    assert calls[0]["params"]["whois"] == "true"
    assert calls[0]["params"]["date"] == "2026-09-01"
    assert calls[0]["params"]["offset"] == 0
    assert calls[0]["params"]["limit"] == 100
    assert "apiKey" not in calls[0]["params"]
    assert client._session.headers.get("X-API-KEY") == "test-api-key"
    assert calls[0]["stream"] is True


def test_iter_domains_only_feed_uses_whois_false(monkeypatch):
    payload = "example.com\nexample.org\n"

    calls = []

    def fake_get(url, params=None, timeout=None, stream=False):
        calls.append(params)
        return _fake_response(payload)

    client = WhoisFreaksNRDClient("test-api-key")
    monkeypatch.setattr(client._session, "get", fake_get)

    pages = list(
        client.iter_feed(
            feed_type="cctld",
            whois=False,
            feed_date=date(2026, 9, 2),
            limit=50,
        )
    )

    assert len(pages) == 1
    assert [r.domain_name for r in pages[0]] == [
        "example.com",
        "example.org",
    ]
    assert calls[0]["whois"] == "false"


def test_iter_retries_rate_limit_then_succeeds(monkeypatch):
    rate_limited = MagicMock(status_code=429)
    response = _fake_response("example.com\n")
    client = WhoisFreaksNRDClient(
        "test-api-key",
        max_retries=1,
        retry_backoff_seconds=0.5,
    )
    get = MagicMock(side_effect=[rate_limited, response])
    monkeypatch.setattr(client._session, "get", get)
    sleep = MagicMock()
    monkeypatch.setattr("whoisfreaks_client.nrd_client.time.sleep", sleep)

    pages = list(
        client.iter_feed(
            feed_type="gtld",
            whois=False,
            feed_date=date(2026, 9, 1),
            limit=10,
        )
    )

    assert [record.domain_name for record in pages[0]] == ["example.com"]
    assert get.call_count == 2
    rate_limited.close.assert_called_once()
    sleep.assert_called_once_with(0.5)


@pytest.mark.parametrize("status_code", [400, 404])
def test_iter_does_not_retry_permanent_http_errors(monkeypatch, status_code):
    response = _fake_response("", status_code=status_code)
    response.raise_for_status.side_effect = requests.HTTPError(response=response)
    client = WhoisFreaksNRDClient("test-api-key", max_retries=3)
    get = MagicMock(return_value=response)
    monkeypatch.setattr(client._session, "get", get)
    sleep = MagicMock()
    monkeypatch.setattr("whoisfreaks_client.nrd_client.time.sleep", sleep)

    with pytest.raises(WhoisFreaksNRDError, match=f"HTTP {status_code}"):
        list(
            client.iter_feed(
                feed_type="gtld",
                whois=False,
                feed_date=date(2026, 9, 1),
                limit=10,
            )
        )

    assert get.call_count == 1
    sleep.assert_not_called()
    response.close.assert_called_once()


def test_iter_continues_after_malformed_only_page():
    client = WhoisFreaksNRDClient("test-api-key", max_retries=0)
    client._fetch_page = MagicMock(side_effect=[NRDPage([], 2), NRDPage([], 1)])

    pages = list(
        client.iter_feed(
            feed_type="gtld",
            whois=True,
            feed_date=date(2026, 9, 1),
            limit=2,
        )
    )

    assert [page.source_record_count for page in pages] == [2, 1]


def test_client_does_not_advertise_compression():
    """Feeds are plain-text CSV read from undecoded response.raw."""
    client = WhoisFreaksNRDClient("test-api-key")
    assert client._session.headers["Accept-Encoding"] == "identity"


def test_parse_whois_rows_raises_on_missing_domain_name_header():
    """A nonempty WHOIS CSV response without 'domain_name' header must raise."""
    payload = "create_date,registrant_name\n2026-09-01,Example\n"
    with pytest.raises(
        WhoisFreaksNRDError, match="missing required 'domain_name' header"
    ):
        WhoisFreaksNRDClient._parse_whois_csv(payload)


def test_iter_retries_whois_stream_transport_error(monkeypatch):
    """urllib3 transport errors raised during stream body reads are retried."""
    import urllib3.exceptions

    good_payload = "domain_name,create_date\nexample.com,2026-09-01\n"

    class _FailingRaw(BytesIO):
        """Proper BytesIO subclass that raises a urllib3 error when read."""

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
            response.raw = _FailingRaw(b"domain_name,create_date\n")
            return response
        return _fake_response(good_payload)

    client = WhoisFreaksNRDClient(
        "test-api-key", max_retries=1, retry_backoff_seconds=0
    )
    monkeypatch.setattr(client._session, "get", fake_get)
    sleep = MagicMock()
    monkeypatch.setattr("whoisfreaks_client.nrd_client.time.sleep", sleep)

    pages = list(
        client.iter_feed(
            feed_type="gtld",
            whois=True,
            feed_date=date(2026, 9, 1),
            limit=10,
        )
    )

    assert call_count == 2
    assert [r.domain_name for r in pages[0]] == ["example.com"]

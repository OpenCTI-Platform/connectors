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
    """BytesIO that closes itself after EOF, like urllib3 response.raw."""

    def read(self, size=-1):
        data = super().read(size)
        if not data:
            self.close()
        return data


def _fake_response(payload: str, status_code: int = 200):
    response = MagicMock()
    response.status_code = status_code
    response.encoding = "utf-8"
    response.raw = BytesIO(payload.encode("utf-8"))
    response.raise_for_status.return_value = None
    response.close.return_value = None
    return response


def test_parse_whois_stream_survives_auto_closed_raw():
    payload = "domain_name,create_date\nexample.com,2026-09-01\n"
    response = MagicMock()
    response.encoding = "utf-8"
    response.raw = _AutoClosingBytesIO(payload.encode("utf-8"))
    response.close.return_value = None

    client = WhoisFreaksNRDClient("test-api-key")
    records = client._parse_whois_stream(response)

    assert len(records) == 1
    assert records[0].domain_name == "example.com"
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

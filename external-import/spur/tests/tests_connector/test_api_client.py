import gzip
import io
from unittest.mock import MagicMock

import requests
from pydantic import SecretStr
from spur_client import SpurClient


def make_client():
    return SpurClient(helper=MagicMock(), api_key=SecretStr("secret-token"))


def gzip_response(payload: bytes) -> MagicMock:
    response = MagicMock()
    response.raw = io.BytesIO(gzip.compress(payload))
    response.raise_for_status = MagicMock()
    return response


def test_init_sets_token_header():
    client = make_client()
    assert client.session.headers["Token"] == "secret-token"


def test_stream_feed_yields_records():
    client = make_client()
    payload = b'{"ip": "1.1.1.1"}\n\n{"ip": "2.2.2.2"}\n'
    client.session.get = MagicMock(return_value=gzip_response(payload))

    records = list(client.stream_feed("https://feed"))

    assert records == [{"ip": "1.1.1.1"}, {"ip": "2.2.2.2"}]


def test_stream_feed_skips_malformed_json():
    client = make_client()
    payload = b'{"ip": "1.1.1.1"}\nnot-json\n{"ip": "3.3.3.3"}\n'
    client.session.get = MagicMock(return_value=gzip_response(payload))

    records = list(client.stream_feed("https://feed"))

    assert records == [{"ip": "1.1.1.1"}, {"ip": "3.3.3.3"}]
    client.helper.connector_logger.warning.assert_called_once()


def test_stream_feed_request_exception_returns_empty():
    client = make_client()
    client.session.get = MagicMock(side_effect=requests.RequestException("boom"))

    records = list(client.stream_feed("https://feed"))

    assert records == []
    client.helper.connector_logger.error.assert_called_once()


def test_stream_feed_http_error_returns_empty():
    client = make_client()
    response = MagicMock()
    response.raise_for_status = MagicMock(side_effect=requests.HTTPError("404"))
    client.session.get = MagicMock(return_value=response)

    records = list(client.stream_feed("https://feed"))

    assert records == []
    client.helper.connector_logger.error.assert_called_once()


def test_stream_feed_bad_gzip_logs_error():
    client = make_client()
    response = MagicMock()
    response.raw = io.BytesIO(b"not-gzip-data")
    response.raise_for_status = MagicMock()
    client.session.get = MagicMock(return_value=response)

    records = list(client.stream_feed("https://feed"))

    assert records == []
    client.helper.connector_logger.error.assert_called_once()

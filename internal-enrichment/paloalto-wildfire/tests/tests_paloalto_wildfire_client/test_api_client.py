from unittest.mock import MagicMock

import pytest
import requests
from paloalto_wildfire_client import PaloaltoWildfireClient, WildfireAPIError

VERDICT_XML = (
    "<wildfire><get-verdict-info><sha256>abc</sha256>"
    "<verdict>1</verdict><md5>def</md5></get-verdict-info></wildfire>"
)
VERDICT_UNKNOWN_XML = (
    "<wildfire><get-verdict-info><verdict>-102</verdict>"
    "</get-verdict-info></wildfire>"
)
REPORT_XML = (
    "<wildfire><file_info><malware>yes</malware><md5>def</md5>"
    "<sha1>ghi</sha1><sha256>abc</sha256><size>1024</size>"
    "<filetype>PE32</filetype></file_info></wildfire>"
)


def _make_client() -> PaloaltoWildfireClient:
    client = PaloaltoWildfireClient(MagicMock(), api_key="key")
    client.session = MagicMock()
    return client


def _response(text: str, status: int = 200) -> MagicMock:
    response = MagicMock()
    response.status_code = status
    response.text = text
    response.raise_for_status.return_value = None
    return response


def test_get_verdict_returns_code():
    client = _make_client()
    client.session.post.return_value = _response(VERDICT_XML)
    assert client.get_verdict("abc") == 1


def test_get_verdict_unknown_returns_none():
    client = _make_client()
    client.session.post.return_value = _response(VERDICT_UNKNOWN_XML)
    assert client.get_verdict("abc") is None


def test_get_verdict_404_returns_none():
    client = _make_client()
    client.session.post.return_value = _response("", status=404)
    assert client.get_verdict("abc") is None


def test_get_report_parses_file_info():
    client = _make_client()
    client.session.post.return_value = _response(REPORT_XML)

    report = client.get_report("abc")
    assert report["sha256"] == "abc"
    assert report["md5"] == "def"
    assert report["size"] == "1024"
    assert report["malware"] == "yes"


def test_apikey_injected_in_payload():
    client = _make_client()
    client.session.post.return_value = _response(VERDICT_XML)

    client.get_verdict("hashvalue")
    _, kwargs = client.session.post.call_args
    assert kwargs["data"]["apikey"] == "key"
    assert kwargs["data"]["hash"] == "hashvalue"


def test_get_report_404_returns_none():
    client = _make_client()
    client.session.post.return_value = _response("", status=404)
    assert client.get_report("abc") is None


def test_get_verdict_bad_xml_returns_none():
    client = _make_client()
    client.session.post.return_value = _response("not-xml")
    assert client.get_verdict("abc") is None


def test_get_report_bad_xml_returns_none():
    client = _make_client()
    client.session.post.return_value = _response("not-xml")
    assert client.get_report("abc") is None


def test_get_report_without_file_info_returns_none():
    client = _make_client()
    client.session.post.return_value = _response("<wildfire></wildfire>")
    assert client.get_report("abc") is None


def test_post_raises_on_http_error():
    client = _make_client()
    err_response = MagicMock()
    err_response.status_code = 500
    err_response.reason = "Server Error"
    bad = MagicMock()
    bad.status_code = 500
    bad.raise_for_status.side_effect = requests.HTTPError(response=err_response)
    client.session.post.return_value = bad

    with pytest.raises(WildfireAPIError):
        client.get_verdict("abc")

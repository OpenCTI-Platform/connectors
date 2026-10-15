from unittest.mock import Mock

import pytest
import requests
from whoisfreaks_client.status import (
    FeedStatus,
    WhoisFreaksStatusClient,
    WhoisFreaksStatusError,
)

STATUS_PAYLOAD = {
    "newly": {
        "gtld": {
            "last_update": "2026-09-27",
            "available_from": "2026-06-27",
        },
        "cctld": {
            "last_update": "2026-09-27",
            "available_from": "2026-06-26",
        },
    },
    "threat_feed": {
        "phishing": {
            "last_update": "2026-09-28",
            "available_from": "2026-07-20",
        },
        "malware": {
            "last_update": "2026-09-28",
            "available_from": "2026-07-20",
        },
        "spam": {
            "last_update": "2026-09-28",
            "available_from": "2026-07-20",
        },
    },
}


def _response(payload):
    response = Mock()
    response.raise_for_status.return_value = None
    response.json.return_value = payload
    return response


def test_get_status_parses_relevant_feeds():
    client = WhoisFreaksStatusClient(
        api_key="test-key",
    )

    client._session.get = Mock(
        return_value=_response(STATUS_PAYLOAD),
    )

    status = client.get_status()

    assert status.malware == FeedStatus(
        last_update="2026-09-28",
        available_from="2026-07-20",
    )
    assert status.phishing.last_update == "2026-09-28"
    assert status.spam.available_from == "2026-07-20"

    assert status.gtld.last_update == "2026-09-27"
    assert status.cctld.available_from == "2026-06-26"


def test_get_threat_feed_status():
    client = WhoisFreaksStatusClient(api_key="test-key")
    status = client._parse_status(STATUS_PAYLOAD)

    assert status.get_threat_feed_status("malware").last_update == ("2026-09-28")
    assert status.get_threat_feed_status("phishing").last_update == ("2026-09-28")
    assert status.get_threat_feed_status("spam").last_update == ("2026-09-28")


def test_get_nrd_feed_status():
    client = WhoisFreaksStatusClient(api_key="test-key")
    status = client._parse_status(STATUS_PAYLOAD)

    assert status.get_nrd_feed_status("gtld").last_update == ("2026-09-27")
    assert status.get_nrd_feed_status("cctld").last_update == ("2026-09-27")


def test_invalid_threat_feed_raises():
    client = WhoisFreaksStatusClient(api_key="test-key")
    status = client._parse_status(STATUS_PAYLOAD)

    with pytest.raises(ValueError, match="Unsupported threat feed"):
        status.get_threat_feed_status("unknown")


def test_invalid_nrd_feed_raises():
    client = WhoisFreaksStatusClient(api_key="test-key")
    status = client._parse_status(STATUS_PAYLOAD)

    with pytest.raises(ValueError, match="Unsupported NRD feed type"):
        status.get_nrd_feed_status("unknown")


def test_invalid_status_structure_raises():
    client = WhoisFreaksStatusClient(api_key="test-key")

    with pytest.raises(
        WhoisFreaksStatusError,
        match="invalid structure",
    ):
        client._parse_status(
            {
                "threat_feed": {},
                "newly": {},
            }
        )


def test_non_json_response_raises():
    client = WhoisFreaksStatusClient(api_key="test-key")

    response = Mock()
    response.raise_for_status.return_value = None
    response.json.side_effect = ValueError("invalid json")

    client._session.get = Mock(return_value=response)

    with pytest.raises(
        WhoisFreaksStatusError,
        match="not valid JSON",
    ):
        client.get_status()


def test_http_error_raises():
    client = WhoisFreaksStatusClient(api_key="test-key")

    response = Mock()
    response.status_code = 401

    error = requests.HTTPError(
        "401 Unauthorized",
        response=response,
    )

    client._session.get = Mock(side_effect=error)

    with pytest.raises(
        WhoisFreaksStatusError,
        match="HTTP 401",
    ):
        client.get_status()


def test_status_endpoint_url():
    client = WhoisFreaksStatusClient(
        api_key="test-key",
        base_url="https://example.test/",
    )

    response = _response(STATUS_PAYLOAD)
    client._session.get = Mock(return_value=response)

    client.get_status()

    client._session.get.assert_called_once()
    args, kwargs = client._session.get.call_args
    assert args[0] == "https://example.test/v3.4/status"
    assert kwargs.get("timeout") == 120
    assert "params" not in kwargs or "apiKey" not in kwargs.get("params", {})
    assert client._session.headers.get("X-API-KEY") == "test-key"

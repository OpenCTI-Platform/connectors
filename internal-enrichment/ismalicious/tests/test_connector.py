"""Tests for isMalicious connector API client."""

from unittest.mock import MagicMock, patch

import requests
from connector import IsMaliciousConnector
from connector.ismalicious import USER_AGENT
from connector.models import (
    ConfigLoader,
    ConnectorConfig,
    IsMaliciousConfig,
    OpenCTIConfig,
)
from pydantic import SecretStr


def _make_connector(
    api_key: str = "test-credential",
) -> tuple[IsMaliciousConnector, MagicMock]:
    config = ConfigLoader(
        opencti=OpenCTIConfig(
            url="http://localhost:8080",
            token=SecretStr("opencti-token"),
        ),
        connector=ConnectorConfig(id="ismalicious-enrichment"),
        ismalicious=IsMaliciousConfig(api_key=SecretStr(api_key)),
    )
    helper = MagicMock()
    helper.api.label.read_or_create_unchecked = MagicMock()
    return IsMaliciousConnector(config, helper), helper


@patch("connector.ismalicious.requests.get")
def test_call_api_uses_check_endpoint_and_x_api_key(mock_get):
    mock_response = MagicMock()
    mock_response.json.return_value = {"malicious": False}
    mock_get.return_value = mock_response

    connector, _helper = _make_connector(api_key="base64-credential")

    result = connector._call_api("8.8.8.8")

    mock_get.assert_called_once_with(
        "https://api.ismalicious.com/check",
        params={"query": "8.8.8.8", "enrichment": "standard"},
        headers={
            "X-API-KEY": "base64-credential",
            "Accept": "application/json",
            "User-Agent": USER_AGENT,
        },
        timeout=30,
    )
    assert result == {"malicious": False}


@patch("connector.ismalicious.requests.get")
def test_call_api_strips_trailing_slash_from_api_url(mock_get):
    mock_response = MagicMock()
    mock_response.json.return_value = {"malicious": True}
    mock_get.return_value = mock_response

    config = ConfigLoader(
        opencti=OpenCTIConfig(
            url="http://localhost:8080",
            token=SecretStr("opencti-token"),
        ),
        connector=ConnectorConfig(id="ismalicious-enrichment"),
        ismalicious=IsMaliciousConfig(
            api_url="https://api.ismalicious.com/",
            api_key=SecretStr("test-key"),
        ),
    )
    helper = MagicMock()
    helper.api.label.read_or_create_unchecked = MagicMock()
    connector = IsMaliciousConnector(config, helper)

    connector._call_api("evil.example")

    mock_get.assert_called_once_with(
        "https://api.ismalicious.com/check",
        params={"query": "evil.example", "enrichment": "standard"},
        headers={
            "X-API-KEY": "test-key",
            "Accept": "application/json",
            "User-Agent": USER_AGENT,
        },
        timeout=30,
    )


@patch("connector.ismalicious.requests.get")
def test_call_api_returns_none_on_request_error(mock_get, capsys):
    mock_get.side_effect = requests.exceptions.HTTPError("401 Unauthorized")

    connector, helper = _make_connector()

    result = connector._call_api("8.8.8.8")

    assert result is None
    helper.log_error.assert_called_once()


def _http_error(status_code: int) -> requests.exceptions.HTTPError:
    response = requests.Response()
    response.status_code = status_code
    return requests.exceptions.HTTPError(f"{status_code} error", response=response)


@patch("connector.ismalicious.requests.get")
def test_call_api_logs_actionable_message_on_401_and_429(mock_get):
    connector, helper = _make_connector()

    for status_code, expected in [(401, "ISMALICIOUS_API_KEY"), (429, "quota")]:
        mock_response = MagicMock()
        mock_response.raise_for_status.side_effect = _http_error(status_code)
        mock_get.return_value = mock_response
        helper.log_error.reset_mock()

        assert connector._call_api("8.8.8.8") is None
        assert expected in helper.log_error.call_args.args[0]


def test_user_agent_identifies_the_connector():
    assert USER_AGENT.startswith("ismalicious-opencti/")


MIXED_RESPONSE = {
    "malicious": True,
    "riskScore": {"score": 72, "level": "high"},
    "sources": [
        {"name": "Feed A", "category": "botnet"},
        {
            "name": "Cloud ranges",
            "category": "infrastructure",
            "threatClass": "infrastructure",
        },
        {"name": "Ad hosts", "category": "adware", "threatClass": "policy"},
        {"name": "Feed B", "category": "phishing", "threatClass": "threat"},
    ],
    "infrastructure": {"attributes": ["cloud"], "sources": []},
}

INFRASTRUCTURE_ONLY_RESPONSE = {
    "malicious": False,
    "riskScore": {"score": 12, "level": "low"},
    "sources": [
        {
            "name": "Cloud ranges",
            "category": "infrastructure",
            "threatClass": "infrastructure",
        }
    ],
    "infrastructure": {"attributes": ["cloud"], "sources": []},
}


def test_score_uses_risk_score():
    connector, _helper = _make_connector()

    assert connector._calculate_score(MIXED_RESPONSE) == 72
    assert connector._calculate_score(INFRASTRUCTURE_ONLY_RESPONSE) == 12
    assert connector._calculate_score({"riskScore": {"score": 140}}) == 100


def test_score_falls_back_without_risk_score():
    connector, _helper = _make_connector()

    assert connector._calculate_score({"malicious": False}) == 10
    assert connector._calculate_score({"malicious": True, "riskScore": None}) == 50
    assert (
        connector._calculate_score(
            {"malicious": True, "reputation": {"malicious": 3, "harmless": 1}}
        )
        == 75
    )


def test_labels_come_from_threat_listings_only():
    connector, _helper = _make_connector()

    assert connector._get_labels(MIXED_RESPONSE) == ["malicious", "botnet", "phishing"]
    assert connector._get_labels(INFRASTRUCTURE_ONLY_RESPONSE) == []
    assert connector._get_labels({"malicious": False, "sources": None}) == []


def test_external_references_distinguish_detections_from_listings():
    connector, _helper = _make_connector()

    refs = connector._get_external_references(MIXED_RESPONSE, "203.0.113.7")

    assert refs[0]["source_name"] == "isMalicious"
    assert refs[0]["url"].startswith("https://ismalicious.com/report?query=203.0.113.7")
    by_name = {ref["source_name"]: ref for ref in refs[1:]}
    assert by_name["Feed A"]["description"] == "Detected as: botnet"
    assert by_name["Cloud ranges"]["description"] == (
        "Listed as: infrastructure (infrastructure)"
    )
    assert by_name["Ad hosts"]["description"] == "Listed as: adware (policy)"


def _enrich(connector, api_data, value="203.0.113.7"):
    """Run _process_message and return its result and the description set."""
    stix_entity = {"id": "ipv4-addr--test", "value": value}
    with (
        patch.object(connector, "_call_api", return_value=api_data),
        patch("connector.ismalicious.OpenCTIConnectorHelper") as helper_cls,
        patch("connector.ismalicious.OpenCTIStix2") as stix2_cls,
    ):
        helper_cls.check_max_tlp.return_value = True
        result = connector._process_message(
            {
                "enrichment_entity": {"entity_type": "IPv4-Addr", "objectMarking": []},
                "stix_entity": stix_entity,
                "stix_objects": [],
            }
        )
    descriptions = [
        call.args[3]
        for call in stix2_cls.put_attribute_in_extension.call_args_list
        if call.args[2] == "x_opencti_description"
    ]
    return result, descriptions[-1]


def test_description_counts_threat_listings_only():
    connector, _helper = _make_connector()

    result, description = _enrich(connector, MIXED_RESPONSE)

    assert result == "Enrichment complete: 203.0.113.7 is malicious (score: 72)"
    assert "**Malicious** - Detected by 2 source(s)" in description
    assert "Categories: botnet, phishing" in description
    assert "Infrastructure: cloud" in description


def test_infrastructure_only_observable_is_not_reported_as_threat():
    connector, _helper = _make_connector()

    result, description = _enrich(connector, INFRASTRUCTURE_ONLY_RESPONSE)

    assert result == "Enrichment complete: 203.0.113.7 is clean (score: 12)"
    assert description.startswith("No threats detected")
    assert "Infrastructure: cloud" in description
    assert "Detected by" not in description

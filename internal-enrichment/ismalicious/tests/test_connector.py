"""Tests for isMalicious connector API client."""

from typing import Any
from unittest.mock import MagicMock, patch

import pytest
import requests
from connector import ConnectorSettings, IsMaliciousConnector
from connector.ismalicious import USER_AGENT


def _make_settings(**ismalicious: Any) -> ConnectorSettings:
    """Build connector settings from a config dict instead of the environment."""

    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(
                {
                    "opencti": {
                        "url": "http://localhost:8080",
                        "token": "opencti-token",
                    },
                    "connector": {},
                    "ismalicious": {"api_key": "test-credential", **ismalicious},
                }
            )

    return FakeConnectorSettings()


def _make_connector(
    api_key: str = "test-credential", **ismalicious: Any
) -> tuple[IsMaliciousConnector, MagicMock]:
    config = _make_settings(api_key=api_key, **ismalicious)
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

    config = _make_settings(
        api_url="https://api.ismalicious.com/",
        api_key="test-key",
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


@pytest.mark.parametrize(
    "api_data",
    [
        {},
        {"malicious": False},
        {"malicious": True, "riskScore": None},
        {"malicious": True, "reputation": {"malicious": 3, "harmless": 1}},
        {"riskScore": {"score": True}},
        {"riskScore": {"score": False}},
        {"riskScore": {"score": "42"}},
        {"riskScore": {"score": float("nan")}},
        {"riskScore": {"score": float("inf")}},
    ],
)
def test_missing_or_invalid_risk_score_is_unknown(api_data):
    connector, _helper = _make_connector()
    assert connector._calculate_score(api_data) is None


@pytest.mark.parametrize("score, expected", [(0, 0), (-5, 0), (42.8, 42), (101, 100)])
def test_valid_score_including_zero_is_preserved(score, expected):
    connector, _helper = _make_connector()
    assert connector._calculate_score({"riskScore": {"score": score}}) == expected


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
                "event_type": "INTERNAL_ENRICHMENT",
                "entity_id": stix_entity["id"],
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

    assert result == (
        "Enrichment complete: 203.0.113.7 is not flagged as malicious (score: 12)"
    )
    assert "not proof of safety" in description
    assert "Infrastructure: cloud" in description
    assert "Detected by" not in description


def _message(entity_type="IPv4-Addr", value="203.0.113.7", from_playbook=False):
    from connector.ismalicious import STIX_EXT_OCTI_SCO

    entity = {
        "id": f"{entity_type.lower()}--test",
        "value": value,
        "extensions": {STIX_EXT_OCTI_SCO: {"score": 85}},
    }
    message = {
        "entity_id": entity["id"],
        "enrichment_entity": {"entity_type": entity_type, "objectMarking": []},
        "stix_entity": entity,
        "stix_objects": [entity],
    }
    if not from_playbook:
        message["event_type"] = "INTERNAL_ENRICHMENT"
    return message


@pytest.mark.parametrize(
    "api_data, expected_verdict",
    [({}, "unknown"), ({"malicious": False}, "not flagged as malicious")],
)
def test_unknown_score_does_not_downgrade_existing_score(api_data, expected_verdict):
    from connector.ismalicious import STIX_EXT_OCTI_SCO

    connector, helper = _make_connector()
    message = _message()
    with (
        patch.object(connector, "_call_api", return_value=api_data),
        patch("connector.ismalicious.OpenCTIConnectorHelper") as helper_cls,
        patch("connector.ismalicious.OpenCTIStix2") as stix2_cls,
    ):
        helper_cls.check_max_tlp.return_value = True
        result = connector._process_message(message)
    assert message["stix_entity"]["extensions"][STIX_EXT_OCTI_SCO]["score"] == 85
    assert all(
        call.args[2] != "score"
        for call in stix2_cls.put_attribute_in_extension.call_args_list
    )
    assert f"is {expected_verdict} (score: unavailable)" in result
    assert "clean" not in result
    assert "safe" not in connector._get_labels(api_data)
    helper.send_stix2_bundle.assert_called_once()


@pytest.mark.parametrize(
    "api_data", [{"malicious": False}, {"riskScore": {"score": 59}}]
)
def test_missing_or_below_threshold_score_does_not_enrich(api_data):
    connector, helper = _make_connector(min_score=60)
    with (
        patch.object(connector, "_call_api", return_value=api_data),
        patch("connector.ismalicious.OpenCTIConnectorHelper") as helper_cls,
        patch("connector.ismalicious.OpenCTIStix2") as stix2_cls,
    ):
        helper_cls.check_max_tlp.return_value = True
        result = connector._process_message(_message())
    assert "skipping" in result
    stix2_cls.put_attribute_in_extension.assert_not_called()
    helper.send_stix2_bundle.assert_not_called()


@pytest.mark.parametrize(
    "entity_type, value",
    [
        ("IPv4-Addr", "203.0.113.7"),
        ("IPv6-Addr", "2001:db8::1"),
        ("Domain-Name", "example.org"),
    ],
)
def test_non_malicious_response_keeps_api_score_for_supported_types(entity_type, value):
    connector, helper = _make_connector()
    with (
        patch.object(
            connector,
            "_call_api",
            return_value={"malicious": False, "riskScore": {"score": 42}},
        ),
        patch("connector.ismalicious.OpenCTIConnectorHelper") as helper_cls,
        patch("connector.ismalicious.OpenCTIStix2") as stix2_cls,
    ):
        helper_cls.check_max_tlp.return_value = True
        result = connector._process_message(_message(entity_type, value))
    written_scores = [
        call.args[3]
        for call in stix2_cls.put_attribute_in_extension.call_args_list
        if call.args[2] == "score"
    ]
    assert written_scores == [42]
    assert "not flagged as malicious (score: 42)" in result
    helper.send_stix2_bundle.assert_called_once()


def test_tlp_exclusion_never_calls_api():
    connector, helper = _make_connector()
    with (
        patch.object(connector, "_call_api") as api_call,
        patch("connector.ismalicious.OpenCTIConnectorHelper") as helper_cls,
    ):
        helper_cls.check_max_tlp.return_value = False
        result = connector._process_message(_message())
    assert result == "TLP too high, skipping enrichment"
    api_call.assert_not_called()
    helper.send_stix2_bundle.assert_not_called()


def test_api_failure_leaves_observable_unchanged():
    connector, helper = _make_connector()
    with (
        patch.object(connector, "_call_api", return_value=None),
        patch("connector.ismalicious.OpenCTIConnectorHelper") as helper_cls,
        patch("connector.ismalicious.OpenCTIStix2") as stix2_cls,
    ):
        helper_cls.check_max_tlp.return_value = True
        result = connector._process_message(_message())
    assert result == "API call failed for 203.0.113.7"
    stix2_cls.put_attribute_in_extension.assert_not_called()
    helper.send_stix2_bundle.assert_not_called()


def _playbook_skip(connector, message, api_data=None, tlp_ok=True):
    """Run a playbook message through _process_message with the given API answer."""
    with (
        patch.object(connector, "_call_api", return_value=api_data) as api_call,
        patch("connector.ismalicious.OpenCTIConnectorHelper") as helper_cls,
        patch("connector.ismalicious.OpenCTIStix2") as stix2_cls,
    ):
        helper_cls.check_max_tlp.return_value = tlp_ok
        result = connector._process_message(message)
    return result, api_call, stix2_cls


@pytest.mark.parametrize(
    "settings, message_kwargs, api_data, tlp_ok, expected",
    [
        pytest.param(
            {},
            {"entity_type": "Url", "value": "https://example.org"},
            None,
            True,
            "Entity not in connector scope, skipping",
            id="out_of_scope",
        ),
        pytest.param(
            {}, {}, None, False, "TLP too high, skipping enrichment", id="tlp_too_high"
        ),
        pytest.param(
            {}, {"value": ""}, None, True, "No observable value found", id="no_value"
        ),
        pytest.param(
            {"enrich_ipv4": False},
            {},
            None,
            True,
            "IPv4 enrichment disabled",
            id="type_disabled",
        ),
        pytest.param(
            {}, {}, None, True, "API call failed for 203.0.113.7", id="api_failure"
        ),
        pytest.param(
            {"min_score": 60},
            {},
            {"riskScore": {"score": 59}},
            True,
            "Score 59 below threshold, skipping",
            id="below_threshold",
        ),
    ],
)
def test_skipped_entity_from_playbook_sends_original_bundle(
    settings, message_kwargs, api_data, tlp_ok, expected
):
    """A playbook MUST get the original bundle back, otherwise it stalls."""
    connector, helper = _make_connector(**settings)
    message = _message(**message_kwargs, from_playbook=True)

    result, _api_call, stix2_cls = _playbook_skip(connector, message, api_data, tlp_ok)

    assert result == expected
    stix2_cls.put_attribute_in_extension.assert_not_called()
    helper.stix2_create_bundle.assert_called_once_with(message["stix_objects"])
    helper.send_stix2_bundle.assert_called_once_with(
        helper.stix2_create_bundle.return_value
    )


def test_out_of_scope_entity_never_calls_api():
    """An entity outside the connector scope MUST NOT be sent to the isMalicious API."""
    connector, helper = _make_connector()
    message = _message("Url", "https://example.org")

    result, api_call, _stix2_cls = _playbook_skip(connector, message)

    assert result == "Entity not in connector scope, skipping"
    api_call.assert_not_called()
    helper.send_stix2_bundle.assert_not_called()

"""Additional unit tests for cyfirma_client.api_client.CyfirmaClient."""

from unittest.mock import MagicMock, call, patch

import pytest
import requests
from connector.utils import (
    _IOC_GENERIC_PATH,
    _IOC_TAILORED_PATH,
    _TA_SEARCH_PATH,
    _VUL_GENERIC_PATH,
    _VUL_TAILORED_PATH,
    CYFIRMA_EXTENSION_DEFINITION_ID,
    CYFIRMA_INDICATOR_EXTENSION_DEFINITION_ID,
    OPENCTI_EXTENSION_DEFINITION_ID,
)
from cyfirma_client import CyfirmaClient
from pydantic import SecretStr

BASE_URL = "https://api.cyfirma.test"
RETRY_STATUS = {429, 500, 502, 503, 504}


# --------------------------------------------------------------------------- #
# helpers / fixtures
# --------------------------------------------------------------------------- #


def _resp(status=200, payload=None, content=b"{}", headers=None):
    response = MagicMock()
    response.status_code = status
    response.content = content
    response.headers = headers or {}
    response.url = f"{BASE_URL}/endpoint"
    response.json.return_value = {} if payload is None else payload
    if status >= 400 and status not in RETRY_STATUS:
        response.raise_for_status.side_effect = requests.HTTPError(
            f"{status} error", response=response
        )
    return response


@pytest.fixture(autouse=True)
def no_sleep():
    """Never actually sleep and make the jitter deterministic."""
    with patch("cyfirma_client.api_client.time.sleep") as sleep, patch(
        "cyfirma_client.api_client.random.uniform", return_value=0
    ):
        yield sleep


@pytest.fixture
def helper():
    return MagicMock()


@pytest.fixture
def client(helper):
    return CyfirmaClient(
        helper=helper,
        base_url=BASE_URL + "/",
        api_key=SecretStr("secret"),
        tailored_iocs=True,
        look_back_days=3,
        tailored_vulnerabilities=True,
        last_run="2026-01-01 00:00:00",
    )


@pytest.fixture
def http_client(client):
    """Client whose HTTP session is fully mocked (for _request_data tests)."""
    client.session = MagicMock()
    return client


@pytest.fixture
def patched_helpers():
    with patch(
        "cyfirma_client.api_client.get_request_headers",
        return_value={"X-Key": "k"},
    ) as headers, patch(
        "cyfirma_client.api_client.get_request_params",
        side_effect=lambda *_args: {"page": 1},
    ) as params:
        yield headers, params


# --------------------------------------------------------------------------- #
# __init__
# --------------------------------------------------------------------------- #


def test_init_strips_trailing_slash_and_stores_options(client):
    assert client.base_url == BASE_URL
    assert client.api_key == SecretStr("secret")
    assert client.look_back_days == 3
    assert client.tailored_iocs is True
    assert client.tailored_vulnerabilities is True
    assert client.last_run == "2026-01-01 00:00:00"
    assert client.headers == {}


def test_init_defaults(helper):
    c = CyfirmaClient(
        helper=helper,
        base_url=BASE_URL,
        api_key=SecretStr("secret"),
    )

    assert c.tailored_iocs is True
    assert c.tailored_vulnerabilities is False
    assert c.look_back_days == 7
    assert c.last_run == ""


# --------------------------------------------------------------------------- #
# _retry_after
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "headers, expected",
    [
        ({}, None),
        ({"Retry-After": "30"}, 30.0),
        ({"Retry-After": "500"}, 120.0),  # capped at _BACKOFF_MAX
        ({"Retry-After": "Wed, 21 Oct 2026 07:28:00 GMT"}, None),  # HTTP-date
    ],
)
def test_retry_after(headers, expected):
    response = MagicMock()
    response.headers = headers

    assert CyfirmaClient._retry_after(response) == expected


# --------------------------------------------------------------------------- #
# _request_data
# --------------------------------------------------------------------------- #


def test_request_data_success(http_client):
    http_client.session.get.return_value = _resp(200, {"objects": [1]})

    result = http_client._request_data(f"{BASE_URL}/x", params={"p": 1}, headers={})

    assert result == {"objects": [1]}
    http_client.session.get.assert_called_once()


def test_request_data_empty_body_returns_empty_dict(http_client):
    http_client.session.get.return_value = _resp(200, content=b"")

    assert http_client._request_data(f"{BASE_URL}/x") == {}


def test_request_data_non_200_success_returns_empty_dict(http_client):
    http_client.session.get.return_value = _resp(204, content=b"")

    assert http_client._request_data(f"{BASE_URL}/x") == {}


def test_request_data_retries_then_succeeds(http_client, no_sleep):
    http_client.session.get.side_effect = [
        _resp(503),
        _resp(200, {"objects": [1]}),
    ]

    result = http_client._request_data(f"{BASE_URL}/x")

    assert result == {"objects": [1]}
    assert http_client.session.get.call_count == 2
    no_sleep.assert_called_once_with(5)
    http_client.helper.connector_logger.warning.assert_called_once()


def test_request_data_honours_retry_after_header(http_client, no_sleep):
    http_client.session.get.side_effect = [
        _resp(429, headers={"Retry-After": "30"}),
        _resp(200, {"ok": True}),
    ]

    assert http_client._request_data(f"{BASE_URL}/x") == {"ok": True}
    no_sleep.assert_called_once_with(30.0)


def test_request_data_exhausts_retries_with_exponential_backoff(http_client, no_sleep):
    http_client.session.get.return_value = _resp(503)

    with pytest.raises(requests.HTTPError):
        http_client._request_data(f"{BASE_URL}/x")

    assert http_client.session.get.call_count == 5
    assert no_sleep.call_args_list == [call(5), call(10), call(20), call(40)]
    http_client.helper.connector_logger.error.assert_called_once()


def test_request_data_retries_on_timeout(http_client):
    http_client.session.get.side_effect = [
        requests.Timeout("slow"),
        _resp(200, {"ok": True}),
    ]

    assert http_client._request_data(f"{BASE_URL}/x") == {"ok": True}
    assert http_client.session.get.call_count == 2


def test_request_data_connection_error_exhausted(http_client):
    http_client.session.get.side_effect = requests.ConnectionError("down")

    with pytest.raises(requests.ConnectionError):
        http_client._request_data(f"{BASE_URL}/x")

    assert http_client.session.get.call_count == 5


def test_request_data_client_error_fails_immediately(http_client, no_sleep):
    http_client.session.get.return_value = _resp(404)

    with pytest.raises(requests.HTTPError):
        http_client._request_data(f"{BASE_URL}/x")

    assert http_client.session.get.call_count == 1
    no_sleep.assert_not_called()
    http_client.helper.connector_logger.error.assert_called_once()


def test_request_data_other_request_exception_not_retried(http_client):
    http_client.session.get.side_effect = requests.exceptions.InvalidURL("bad url")

    with pytest.raises(requests.exceptions.InvalidURL):
        http_client._request_data("not-a-url")

    assert http_client.session.get.call_count == 1


# --------------------------------------------------------------------------- #
# _fetch_all_pages
# --------------------------------------------------------------------------- #


def test_fetch_all_pages_paginates_until_empty(client, no_sleep):
    pages = [
        {"objects": [{"id": "a"}, {"id": "b"}]},
        {"objects": [{"id": "c"}]},
        {"objects": []},
    ]
    params = {"page": 1}

    with patch.object(client, "_request_data", side_effect=pages) as request:
        result = client._fetch_all_pages(f"{BASE_URL}/x", params, "Indicators")

    assert [o["id"] for o in result] == ["a", "b", "c"]
    assert params["page"] == 3
    assert request.call_count == 3
    assert no_sleep.call_count == 2


def test_fetch_all_pages_missing_objects_key(client):
    with patch.object(client, "_request_data", return_value={}):
        assert client._fetch_all_pages(f"{BASE_URL}/x", {"page": 1}, "X") == []


# --------------------------------------------------------------------------- #
# get_indicators_feeds
# --------------------------------------------------------------------------- #


def _indicator(threat_actors):
    return {
        "type": "indicator",
        "id": "indicator--1",
        "extensions": {
            CYFIRMA_INDICATOR_EXTENSION_DEFINITION_ID: {"threat_actors": threat_actors}
        },
    }


def test_get_indicators_feeds_enriches_with_threat_actor_objects(
    client, patched_helpers
):
    indicators = [
        _indicator("APT1, APT2 ,"),
        _indicator("APT1"),
        {"type": "indicator", "id": "indicator--no-ext"},
        {"type": "indicator", "id": "indicator--none-ext", "extensions": None},
        {"type": "malware", "id": "malware--1"},
    ]
    ta_response = {
        "objects": [
            {"type": "threat-actor", "id": "threat-actor--1"},
            {"type": "intrusion-set", "id": "intrusion-set--1"},
        ]
    }

    with patch.object(
        client, "_fetch_all_pages", return_value=list(indicators)
    ) as fetch, patch.object(
        client, "_request_data", return_value=ta_response
    ) as request:
        result = client.get_indicators_feeds()

    # indicators first, then every enrichment object (threat actors included)
    assert result[: len(indicators)] == indicators
    assert result[-2:] == ta_response["objects"]
    assert len(result) == len(indicators) + 2

    fetch.assert_called_once()
    assert fetch.call_args.args[0] == f"{BASE_URL}{_IOC_TAILORED_PATH}"

    request.assert_called_once()
    assert request.call_args.args[0] == f"{BASE_URL}{_TA_SEARCH_PATH}"
    assert set(request.call_args.kwargs["params"]["values"]) == {"APT1", "APT2"}
    assert client.headers == {"X-Key": "k"}


def test_get_indicators_feeds_generic_path_and_params(client, patched_helpers):
    client.tailored_iocs = False
    _, params = patched_helpers

    with patch.object(client, "_fetch_all_pages", return_value=[]) as fetch:
        client.get_indicators_feeds()

    assert fetch.call_args.args[0] == f"{BASE_URL}{_IOC_GENERIC_PATH}"
    params.assert_called_once_with(3, "2026-01-01 00:00:00")


def test_get_indicators_feeds_skips_ta_lookup_without_names(client, patched_helpers):
    with patch.object(
        client, "_fetch_all_pages", return_value=[{"type": "indicator", "id": "i"}]
    ), patch.object(client, "_request_data") as request:
        result = client.get_indicators_feeds()

    request.assert_not_called()
    assert result == [{"type": "indicator", "id": "i"}]


def test_get_indicators_feeds_ta_failure_is_tolerated(client, patched_helpers, helper):
    indicators = [_indicator("APT1")]

    with patch.object(
        client, "_fetch_all_pages", return_value=list(indicators)
    ), patch.object(
        client, "_request_data", side_effect=requests.RequestException("boom")
    ):
        result = client.get_indicators_feeds()

    assert result == indicators
    helper.connector_logger.error.assert_called_once()


def test_get_indicators_feeds_handles_empty_ta_response(client, patched_helpers):
    indicators = [_indicator("APT1")]

    with patch.object(
        client, "_fetch_all_pages", return_value=list(indicators)
    ), patch.object(client, "_request_data", return_value=None):
        assert client.get_indicators_feeds() == indicators


def test_get_indicators_feeds_logs_and_reraises(client, patched_helpers, helper):
    with patch.object(client, "_fetch_all_pages", side_effect=RuntimeError("fail")):
        with pytest.raises(RuntimeError, match="fail"):
            client.get_indicators_feeds()

    helper.connector_logger.error.assert_called_once_with("fail")


# --------------------------------------------------------------------------- #
# get_vulnerabilities_feeds
# --------------------------------------------------------------------------- #


def test_get_vulnerabilities_feeds_converts_only_vulnerabilities(
    client, patched_helpers
):
    vuln = {
        "type": "vulnerability",
        "id": "vulnerability--1",
        "extensions": {
            CYFIRMA_EXTENSION_DEFINITION_ID: {
                "cvss_version": "3.1",
                "cvss_base_score": "9.8",
            }
        },
    }
    other = {"type": "software", "id": "software--1"}

    with patch.object(client, "_fetch_all_pages", return_value=[vuln, other]) as fetch:
        result = client.get_vulnerabilities_feeds()

    assert fetch.call_args.args[0] == f"{BASE_URL}{_VUL_TAILORED_PATH}"
    assert result == [vuln, other]
    assert CYFIRMA_EXTENSION_DEFINITION_ID not in vuln["extensions"]
    assert vuln["extensions"][OPENCTI_EXTENSION_DEFINITION_ID]["cvss_base_score"] == 9.8
    assert "extensions" not in other


def test_get_vulnerabilities_feeds_generic_path(client, patched_helpers):
    client.tailored_vulnerabilities = False

    with patch.object(client, "_fetch_all_pages", return_value=[]) as fetch:
        assert client.get_vulnerabilities_feeds() == []

    assert fetch.call_args.args[0] == f"{BASE_URL}{_VUL_GENERIC_PATH}"


def test_get_vulnerabilities_feeds_logs_and_reraises(client, patched_helpers, helper):
    with patch.object(client, "_fetch_all_pages", side_effect=RuntimeError("fail")):
        with pytest.raises(RuntimeError, match="fail"):
            client.get_vulnerabilities_feeds()

    helper.connector_logger.error.assert_called_once_with("fail")


# --------------------------------------------------------------------------- #
# _convert_to_opencti_vulnerabilities
# --------------------------------------------------------------------------- #


def _vuln(**ext_props):
    return {
        "type": "vulnerability",
        "id": "vulnerability--1",
        "extensions": {CYFIRMA_EXTENSION_DEFINITION_ID: ext_props},
    }


FULL_PROPS = {
    "cvss_base_score": "7.5",
    "severity": "HIGH",
    "attack_vector": "NETWORK",
    "integrity_impact": "NONE",
    "cvss_vector": "CVSS:3.1/AV:N/AC:L",
    "attack_complexity": "LOW",
    "privileges_required": "NONE",
    "user_interaction": "NONE",
    "scope": "UNCHANGED",
    "confidentiality_impact": "HIGH",
    "availability_impact": "NONE",
}


def test_convert_cvss_v3(client):
    vuln = client._convert_to_opencti_vulnerabilities(
        _vuln(cvss_version="3.1", **FULL_PROPS)
    )

    ext = vuln["extensions"]
    assert CYFIRMA_EXTENSION_DEFINITION_ID not in ext
    octi = ext[OPENCTI_EXTENSION_DEFINITION_ID]
    assert octi["extension_type"] == "property-extension"
    assert octi["cvss_base_score"] == 7.5
    assert octi["cvss_base_severity"] == "HIGH"
    assert octi["cvss_attack_vector"] == "NETWORK"
    assert octi["cvss_integrity_impact"] == "NONE"
    assert octi["cvss_vector_string"] == "CVSS:3.1/AV:N/AC:L"
    assert octi["cvss_attack_complexity"] == "LOW"
    assert octi["cvss_privileges_required"] == "NONE"
    assert octi["cvss_user_interaction"] == "NONE"
    assert octi["cvss_scope"] == "UNCHANGED"
    assert octi["cvss_confidentiality_impact"] == "HIGH"
    assert octi["cvss_availability_impact"] == "NONE"
    assert not any(k.startswith("cvss_v2") for k in octi)


def test_convert_cvss_v2(client):
    vuln = client._convert_to_opencti_vulnerabilities(
        _vuln(cvss_version="2.0", **FULL_PROPS)
    )

    octi = vuln["extensions"][OPENCTI_EXTENSION_DEFINITION_ID]

    assert octi["cvss_v2_integrity_impact"] == "NONE"
    assert octi["cvss_v2_vector_string"] == "CVSS:3.1/AV:N/AC:L"
    assert octi["cvss_v2_confidentiality_impact"] == "HIGH"
    assert octi["cvss_v2_availability_impact"] == "NONE"


@pytest.mark.parametrize("version", ["3.1", "2.0"])
def test_convert_missing_base_score_is_left_unset(client, version):
    props = {k: v for k, v in FULL_PROPS.items() if k != "cvss_base_score"}

    vuln = client._convert_to_opencti_vulnerabilities(
        _vuln(cvss_version=version, **props)
    )

    octi = vuln["extensions"][OPENCTI_EXTENSION_DEFINITION_ID]


def test_convert_without_cvss_version_only_moves_extension(client):
    vuln = client._convert_to_opencti_vulnerabilities(_vuln())

    assert vuln["extensions"] == {
        OPENCTI_EXTENSION_DEFINITION_ID: {"extension_type": "property-extension"}
    }


def test_convert_without_extensions(client):
    vuln = client._convert_to_opencti_vulnerabilities({"id": "vulnerability--1"})

    assert vuln["extensions"] == {
        OPENCTI_EXTENSION_DEFINITION_ID: {"extension_type": "property-extension"}
    }


def test_convert_preserves_existing_opencti_extension(client):
    vuln = _vuln(cvss_version="3.1", cvss_base_score="5.0")
    vuln["extensions"][OPENCTI_EXTENSION_DEFINITION_ID] = {
        "extension_type": "property-extension",
        "x_custom": "keep-me",
    }

    client._convert_to_opencti_vulnerabilities(vuln)

    octi = vuln["extensions"][OPENCTI_EXTENSION_DEFINITION_ID]
    assert octi["x_custom"] == "keep-me"
    assert octi["cvss_base_score"] == 5.0


def test_convert_invalid_score_logs_and_raises(client, helper):
    with pytest.raises(ValueError):
        client._convert_to_opencti_vulnerabilities(
            _vuln(cvss_version="3.1", cvss_base_score="not-a-number")
        )

    helper.connector_logger.error.assert_called_once()
    assert "vulnerability--1" in helper.connector_logger.error.call_args.args[0]


# --------------------------------------------------------------------------- #
# get_entities
# --------------------------------------------------------------------------- #


def test_get_entities_concatenates_feeds(client, no_sleep):
    with patch.object(
        client, "get_indicators_feeds", return_value=[{"id": "i"}]
    ), patch.object(client, "get_vulnerabilities_feeds", return_value=[{"id": "v"}]):
        assert client.get_entities() == [{"id": "i"}, {"id": "v"}]

    no_sleep.assert_called_once_with(1.0)


def test_get_entities_logs_and_reraises(client, helper):
    with patch.object(
        client, "get_indicators_feeds", side_effect=RuntimeError("indicators down")
    ):
        with pytest.raises(RuntimeError, match="indicators down"):
            client.get_entities()

    message = helper.connector_logger.error.call_args.args[0]
    assert message.startswith("[API] Error while fetching entities")

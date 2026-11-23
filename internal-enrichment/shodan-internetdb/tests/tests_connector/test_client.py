from unittest.mock import Mock

import pytest
import requests
from pytest_mock import MockerFixture
from shodan_internetdb.client import ShodanInternetDbClient
from shodan_internetdb.exceptions import ShodanInternetDbRateLimitError


def _mock_get(mocker: MockerFixture, status_code: int) -> Mock:
    response = Mock()
    response.status_code = status_code
    response.headers = {"Retry-After": "3406"}
    response.raise_for_status.side_effect = requests.HTTPError(str(status_code))
    return mocker.patch(
        "shodan_internetdb.client.requests.Session.get", return_value=response
    )


def test_query_rate_limited_raises_rate_limit_error(mocker: MockerFixture) -> None:
    _mock_get(mocker, 429)
    with pytest.raises(ShodanInternetDbRateLimitError, match="429.*3406"):
        ShodanInternetDbClient().query("1.2.3.4")


def test_query_http_error_still_raises(mocker: MockerFixture) -> None:
    _mock_get(mocker, 500)
    with pytest.raises(requests.HTTPError):
        ShodanInternetDbClient().query("1.2.3.4")


def test_query_sets_timeout(mocker: MockerFixture) -> None:
    get = _mock_get(mocker, 429)
    with pytest.raises(ShodanInternetDbRateLimitError):
        ShodanInternetDbClient().query("1.2.3.4")
    assert get.call_args.kwargs["timeout"] == 30


def test_query_uses_configured_timeout(mocker: MockerFixture) -> None:
    get = _mock_get(mocker, 429)
    with pytest.raises(ShodanInternetDbRateLimitError):
        ShodanInternetDbClient(timeout=5).query("1.2.3.4")
    assert get.call_args.kwargs["timeout"] == 5

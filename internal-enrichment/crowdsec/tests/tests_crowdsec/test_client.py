# -*- coding: utf-8 -*-
"""CrowdSec client unittest."""

import itertools
from unittest.mock import MagicMock, patch

import pytest
from crowdsec.client import CrowdSecClient


def make_client():
    return CrowdSecClient(helper=MagicMock(), url="https://cti.test/v2/", api_key="k")


def responses(status_code):
    """Endless stream of responses, cut off so a looping client fails the test."""
    resp = MagicMock(status_code=status_code, text="error")
    return itertools.chain(itertools.repeat(resp, 10), [AssertionError("no retry cap")])


@pytest.mark.parametrize("status_code", [401, 403])
@patch("crowdsec.client.sleep")
@patch("crowdsec.client.requests.get")
def test_rejected_api_key_fails_without_retrying(get, sleep, status_code):
    get.side_effect = responses(status_code)

    with pytest.raises(Exception, match=f"{status_code}.*API key"):
        make_client().get_crowdsec_cti_for_ip("1.2.3.4")

    assert get.call_count == 1
    sleep.assert_not_called()


@patch("crowdsec.client.sleep")
@patch("crowdsec.client.requests.get")
def test_server_errors_are_retried_a_limited_number_of_times(get, sleep):
    get.side_effect = responses(500)

    with pytest.raises(Exception, match="500 after 5 attempts"):
        make_client().get_crowdsec_cti_for_ip("1.2.3.4")

    assert get.call_count == 5
    assert [c.args[0] for c in sleep.call_args_list] == [2, 4, 8, 16]


@patch("crowdsec.client.sleep")
@patch("crowdsec.client.requests.get")
def test_transient_error_is_retried_until_success(get, sleep):
    ok = MagicMock(status_code=200)
    ok.json.return_value = {"reputation": "malicious"}
    get.side_effect = [MagicMock(status_code=503, text="busy"), ok]

    result = make_client().get_crowdsec_cti_for_ip("1.2.3.4")

    assert result == {"reputation": "malicious"}
    sleep.assert_called_once_with(2)

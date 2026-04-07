from unittest.mock import Mock

import pytest
from pytest_bdd import given, scenarios, then, when

scenarios("./reauthentication_fails.constraint.feature")


@pytest.fixture(autouse=True)
def mock_obfuscate(monkeypatch):
    monkeypatch.setattr(
        "stream_connector.connector.obfuscate_api_key",
        lambda api_key, timestamp: "dummy-obfuscated",
    )


@pytest.fixture(autouse=True)
def mock_authenticate(monkeypatch):
    monkeypatch.setattr(
        "stream_connector.connector.ZscalerConnector.authenticate_with_zscaler",
        lambda self: None,
    )


@pytest.fixture
def expired_connector(connector, mock_session):
    connector.session = mock_session
    connector.session.cookies = {}
    return connector


@given("a Zscaler connector with an expired session")
def step_given_expired_session(expired_connector):
    return expired_connector


@when("a request returns 401 and re-authentication fails")
def step_request_401(expired_connector):
    connector = expired_connector

    def fake_post(*args, **kwargs):
        response = Mock()
        response.status_code = 401
        response.text = "SESSION_NOT_VALID"
        response.cookies = {}
        return response

    connector.session.post.side_effect = fake_post
    connector._last_response = connector.handle_rate_limit(connector.session.post)
    return connector


@then("the connector should stop retrying and return None")
def step_stop_retry(expired_connector):
    connector = expired_connector
    assert connector._last_response is None

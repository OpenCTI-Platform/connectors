from unittest.mock import Mock

from pytest_bdd import given, scenarios, then, when
from requests.cookies import RequestsCookieJar

scenarios("./zscaler_session.feature")


@given("a valid authenticated Zscaler session")
def valid_session(connector):
    cookie_jar = RequestsCookieJar()
    cookie_jar.set("JSESSIONID", "initial-session")

    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.cookies = cookie_jar

    connector.session.post = Mock(return_value=mock_response)
    connector.session.cookies = cookie_jar


# ----------------
# Scenario: Request succeeds with a valid session
@when("a request is made to Zscaler")
def make_request(connector):
    connector.handle_rate_limit(connector.session.post, "https://zsapi.example.com")


@then("the request should succeed without re-authentication")
def request_succeeds(connector):
    jsessionid = connector.session.cookies.get("JSESSIONID")
    assert jsessionid == "initial-session"


# ----------------


# ----------------
# Scenario: Request auto-reconnects on expired session
@when("the session expires and a request returns 401")
def session_expires(connector, monkeypatch):

    resp_401 = Mock()
    resp_401.status_code = 401
    resp_401.text = "SESSION_EXPIRED"
    resp_401.cookies = RequestsCookieJar()

    new_cookie = RequestsCookieJar()
    new_cookie.set("JSESSIONID", "new-session")

    resp_200 = Mock()
    resp_200.status_code = 200
    resp_200.cookies = new_cookie

    def fake_authenticate(self):
        self.session.cookies = new_cookie

    monkeypatch.setattr(
        "stream_connector.connector.ZscalerConnector.authenticate_with_zscaler",
        fake_authenticate,
    )

    connector.session.post = Mock(side_effect=[resp_401, resp_200])
    connector._last_response = connector.handle_rate_limit(connector.session.post)


@then("the connector should re-authenticate and succeed")
def reauth_success(connector):
    assert connector._last_response.status_code == 200
    assert connector.session.cookies.get("JSESSIONID") == "new-session"


# ----------------

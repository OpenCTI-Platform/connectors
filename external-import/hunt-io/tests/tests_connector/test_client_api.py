from unittest.mock import MagicMock

import pytest
from external_import_connector.client_api import ConnectorClient, HTTPSessionManager
from external_import_connector.settings import ConnectorSettings

V2_KEY = "api_key_value"
V3_KEY = "ak_api_key_value"


@pytest.mark.parametrize(
    "api_version, api_key, expected_header, expected_value, absent_header",
    [
        pytest.param("v2", V2_KEY, "token", V2_KEY, "Authorization", id="v2_token"),
        pytest.param(
            "v3",
            V3_KEY,
            "Authorization",
            f"Bearer {V3_KEY}",
            "token",
            id="v3_bearer",
        ),
    ],
)
def test_create_session_sets_auth_header_matching_api_version(
    api_version, api_key, expected_header, expected_value, absent_header
):
    """
    The two Hunt.io APIs use mutually exclusive auth schemes and each answers 401 when
    sent the other one's header, so the session must carry exactly one of them.
    """
    session_manager = HTTPSessionManager(MagicMock())

    session = session_manager.create_session(api_key, api_version)

    assert session.headers[expected_header] == expected_value
    assert absent_header not in session.headers


def test_api_version_is_accepted_through_deprecated_namespace(deprecated_v3_config):
    """
    `api_version` is a new field, so its deprecated spellings exist only because the SDK
    namespace shim forwards every key. Guard that, since the naming decision relies on it.
    """
    client = ConnectorClient(helper=MagicMock(), config=ConnectorSettings())

    assert client.session.headers["Authorization"] == f"Bearer {V3_KEY}"


def test_refresh_session_on_timeout_keeps_v3_bearer_header(v3_config):
    """
    `_refresh_session_on_timeout` rebuilds the session independently of `__init__`, so a
    missed argument there would silently drop authentication after a connection timeout.
    """
    client = ConnectorClient(helper=MagicMock(), config=ConnectorSettings())
    assert client.session.headers["Authorization"] == f"Bearer {V3_KEY}"

    client._refresh_session_on_timeout()

    assert client.session.headers["Authorization"] == f"Bearer {V3_KEY}"
    assert "token" not in client.session.headers

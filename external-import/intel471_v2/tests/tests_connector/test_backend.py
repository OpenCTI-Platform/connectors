import base64
from unittest.mock import patch

import pytest
from intel471.backend import BackendName, get_client
from pydantic import HttpUrl

BACKENDS = [
    pytest.param(BackendName.TITAN, "intel471.backend.titan_client", id="titan"),
    pytest.param(BackendName.VERITY471, "intel471.backend.verity471", id="verity471"),
]


@pytest.mark.parametrize("backend_name, patch_target", BACKENDS)
@pytest.mark.parametrize(
    "proxy_url",
    [
        pytest.param("http://proxy.example.com:3128", id="string"),
        pytest.param(HttpUrl("http://proxy.example.com:3128"), id="httpurl"),
    ],
)
def test_get_client_proxy_without_auth_is_set(proxy_url, backend_name, patch_target):
    """
    Test that get_client correctly handles both string and Pydantic HttpUrl proxy values.
    A TypeError was raised when an HttpUrl was passed directly to urllib3's parse_url(), which
    expects a plain string. The fix converts proxy_url to str() before use.
    """
    with patch(patch_target) as mock_client:
        get_client(
            backend_name=backend_name,
            api_username="test-user",
            api_key="test-key",
            proxy_url=proxy_url,
        )

        call_kwargs = mock_client.Configuration.call_args.kwargs
        assert isinstance(call_kwargs["proxy"], str)
        assert call_kwargs["proxy"].startswith("http://proxy.example.com:3128")
        assert "proxy_headers" not in call_kwargs


@pytest.mark.parametrize("backend_name, patch_target", BACKENDS)
@pytest.mark.parametrize(
    "proxy_url",
    [
        pytest.param("http://user:pass@proxy.example.com:3128", id="string"),
        pytest.param(HttpUrl("http://user:pass@proxy.example.com:3128"), id="httpurl"),
    ],
)
def test_get_client_proxy_auth_headers_are_set(proxy_url, backend_name, patch_target):
    """
    Test that get_client extracts proxy auth credentials and sets proxy_headers for both
    string and HttpUrl proxy values that contain user:password credentials.
    """
    with patch(patch_target) as mock_client:
        get_client(
            backend_name=backend_name,
            api_username="test-user",
            api_key="test-key",
            proxy_url=proxy_url,
        )

        call_kwargs = mock_client.Configuration.call_args.kwargs
        assert isinstance(call_kwargs["proxy"], str)
        assert call_kwargs["proxy"].startswith(
            "http://user:pass@proxy.example.com:3128"
        )
        expected_auth = base64.b64encode(b"user:pass").decode()
        assert call_kwargs["proxy_headers"] == {
            "proxy-authorization": f"Basic {expected_auth}"
        }


@pytest.mark.parametrize("backend_name, patch_target", BACKENDS)
def test_get_client_without_proxy(backend_name, patch_target):
    """
    Test that get_client omits proxy-related config when no proxy_url is provided.
    """
    with patch(patch_target) as mock_client:
        get_client(
            backend_name=backend_name,
            api_username="test-user",
            api_key="test-key",
        )

        call_kwargs = mock_client.Configuration.call_args.kwargs
        assert "proxy" not in call_kwargs
        assert "proxy_headers" not in call_kwargs

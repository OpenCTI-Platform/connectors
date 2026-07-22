import base64
from unittest.mock import patch

import pytest
import titan_client
import verity471
from intel471.backend import BackendName, ClientWrapper, get_client
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

        if backend_name == BackendName.VERITY471:
            call_kwargs = mock_client.Configuration.call_args.kwargs
            assert isinstance(call_kwargs["proxy"], str)
            assert call_kwargs["proxy"].startswith("http://proxy.example.com:3128")
            assert "proxy_headers" not in call_kwargs
        else:
            # Titan: proxy is set as attribute after construction
            call_kwargs = mock_client.Configuration.call_args.kwargs
            assert "proxy" not in call_kwargs
            config_instance = mock_client.Configuration.return_value
            assert config_instance.proxy.startswith("http://proxy.example.com:3128")


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

        expected_auth = base64.b64encode(b"user:pass").decode()
        expected_headers = {"proxy-authorization": f"Basic {expected_auth}"}

        if backend_name == BackendName.VERITY471:
            call_kwargs = mock_client.Configuration.call_args.kwargs
            assert isinstance(call_kwargs["proxy"], str)
            assert call_kwargs["proxy"].startswith(
                "http://user:pass@proxy.example.com:3128"
            )
            assert call_kwargs["proxy_headers"] == expected_headers
        else:
            # Titan: proxy is set as attribute after construction
            call_kwargs = mock_client.Configuration.call_args.kwargs
            assert "proxy" not in call_kwargs
            config_instance = mock_client.Configuration.return_value
            assert config_instance.proxy.startswith(
                "http://user:pass@proxy.example.com:3128"
            )
            assert config_instance.proxy_headers == expected_headers


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


class TestRealClientInstantiation:
    """
    Tests using real client libraries (no mocks) to verify that Configuration
    instantiation does not raise TypeError. Regression tests for #6912.
    """

    @pytest.mark.parametrize(
        "proxy_url",
        [
            pytest.param(None, id="no-proxy"),
            pytest.param("http://proxy.example.com:3128", id="simple-proxy"),
            pytest.param("http://user:pass@proxy.example.com:3128", id="auth-proxy"),
        ],
    )
    def test_titan_client_instantiation(self, proxy_url):
        """Titan backend must not raise TypeError with proxy config (#6912)."""
        client = get_client(
            backend_name="titan",
            api_username="test-user",
            api_key="test-key",
            proxy_url=proxy_url,
        )
        assert isinstance(client, ClientWrapper)
        assert client.backend_name == "titan"
        assert isinstance(client.config, titan_client.Configuration)
        if proxy_url:
            assert client.config.proxy == str(proxy_url)
        else:
            assert client.config.proxy is None

    @pytest.mark.parametrize(
        "proxy_url",
        [
            pytest.param(None, id="no-proxy"),
            pytest.param("http://proxy.example.com:3128", id="simple-proxy"),
            pytest.param("http://user:pass@proxy.example.com:3128", id="auth-proxy"),
        ],
    )
    def test_verity471_client_instantiation(self, proxy_url):
        """Verity471 backend must not raise TypeError with proxy config."""
        client = get_client(
            backend_name="verity471",
            api_username="test-user",
            api_key="test-key",
            proxy_url=proxy_url,
        )
        assert isinstance(client, ClientWrapper)
        assert client.backend_name == "verity471"
        assert isinstance(client.config, verity471.Configuration)
        if proxy_url:
            assert client.config.proxy == str(proxy_url)
        else:
            assert client.config.proxy is None

import os
import sys
from unittest.mock import MagicMock, Mock, patch

import pytest

sys.path.append(os.path.join(os.path.dirname(__file__), "..", "src"))

from lastinfosec import LastInfoSecEnrichment  # noqa: E402

DATA = {"enrichment_entity": {"id": "observable-id", "observable_value": "example.com"}}


def make_connector(proxy_http=None, proxy_https=None):
    connector = LastInfoSecEnrichment.__new__(LastInfoSecEnrichment)
    connector.helper = MagicMock()
    connector.helper.send_stix2_bundle.return_value = ["bundle"]
    connector.api_url = "https://api.client.lastinfosec.com/v2"
    connector.lastinfosec_apikey = "api-key"
    connector.proxy_http = proxy_http
    connector.proxy_https = proxy_https
    return connector


def make_response():
    response = Mock()
    response.status_code = 200
    response.json.return_value = {"message": [{"type": "bundle", "objects": []}]}
    return response


@pytest.mark.parametrize(
    "proxy_http, proxy_https, expected_proxies",
    [
        (
            "http://proxy.local:3128",
            "http://proxy.local:3129",
            {"http": "http://proxy.local:3128", "https": "http://proxy.local:3129"},
        ),
        (None, "http://proxy.local:3129", {"https": "http://proxy.local:3129"}),
        (None, None, {}),
    ],
)
def test_process_message_sends_request_through_configured_proxies(
    proxy_http, proxy_https, expected_proxies
):
    connector = make_connector(proxy_http=proxy_http, proxy_https=proxy_https)

    with patch("lastinfosec.requests.post", return_value=make_response()) as post:
        result = connector._process_message(DATA)

    post.assert_called_once()
    assert post.call_args.kwargs["json"] == {"value": "example.com"}
    assert post.call_args.kwargs["proxies"] == expected_proxies
    assert result == "Sent 1 stix bundle(s) for worker import"

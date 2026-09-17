from unittest.mock import MagicMock

import httpx
from censys_enrichmentapis.client import Client
from censys_platform import ErrorModel, ErrorModelData


def test_fetch_web_properties_uses_hostname_and_ports(mocker) -> None:
    properties = [MagicMock(), MagicMock()]
    responses = []
    for web_property in properties:
        response = MagicMock()
        response.result.result.resource = web_property
        responses.append(response)

    sdk = MagicMock()
    sdk.global_data.get_web_property.side_effect = responses
    sdk_context = mocker.patch("censys_enrichmentapis.client.SDK")
    sdk_context.return_value.__enter__.return_value = sdk

    result = list(
        Client("test-org", "test-token").fetch_web_properties(
            "example.com", ports=(80, 443)
        )
    )

    assert result == properties
    assert sdk.global_data.get_web_property.call_args_list == [
        mocker.call(webproperty_id="example.com:80"),
        mocker.call(webproperty_id="example.com:443"),
    ]


def test_fetch_web_properties_skips_ports_not_found(mocker) -> None:
    not_found = ErrorModel(
        data=ErrorModelData(status=404, title="Not Found"),
        raw_response=httpx.Response(
            404,
            request=httpx.Request("GET", "https://api.platform.censys.io"),
        ),
    )
    web_property = MagicMock()
    response = MagicMock()
    response.result.result.resource = web_property

    sdk = MagicMock()
    sdk.global_data.get_web_property.side_effect = [not_found, response]
    sdk_context = mocker.patch("censys_enrichmentapis.client.SDK")
    sdk_context.return_value.__enter__.return_value = sdk

    result = list(
        Client("test-org", "test-token").fetch_web_properties("example.com")
    )

    assert result == [web_property]
    assert sdk.global_data.get_web_property.call_args_list == [
        mocker.call(webproperty_id="example.com:80"),
        mocker.call(webproperty_id="example.com:443"),
    ]

from unittest.mock import MagicMock

import httpx
import pytest
from censys_enrichmentapis.client import MAX_SEARCH_RESULTS, Client
from censys_enrichmentapis.errors import EntityHasNoUsableHashError
from censys_platform import (
    ErrorModel,
    ErrorModelData,
    HostEnrichment,
    HostEnrichmentService,
)


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

    result = list(Client("test-org", "test-token").fetch_web_properties("example.com"))

    assert result == [web_property]
    assert sdk.global_data.get_web_property.call_args_list == [
        mocker.call(webproperty_id="example.com:80"),
        mocker.call(webproperty_id="example.com:443"),
    ]


def test_fetch_web_properties_reraises_non_404_error(mocker) -> None:
    server_error = ErrorModel(
        data=ErrorModelData(status=500, title="Internal Server Error"),
        raw_response=httpx.Response(
            500,
            request=httpx.Request("GET", "https://api.platform.censys.io"),
        ),
    )
    sdk = MagicMock()
    sdk.global_data.get_web_property.side_effect = server_error
    sdk_context = mocker.patch("censys_enrichmentapis.client.SDK")
    sdk_context.return_value.__enter__.return_value = sdk

    with pytest.raises(ErrorModel):
        list(
            Client("test-org", "test-token").fetch_web_properties(
                "example.com", ports=(443,)
            )
        )


def test_fetch_ip_raises_when_no_result(mocker) -> None:
    response = MagicMock()
    response.result.result = None
    sdk = MagicMock()
    sdk.global_data.get_host_enrichment.return_value = response
    sdk_context = mocker.patch("censys_enrichmentapis.client.SDK")
    sdk_context.return_value.__enter__.return_value = sdk

    with pytest.raises(ValueError, match="No data found for IP 203.0.113.5"):
        Client("test-org", "test-token").fetch_ip("203.0.113.5")


def test_restore_service_fields_skips_non_dict_raw_service() -> None:
    # A real Censys response could return a malformed/partial entry for a
    # given service; the merge must skip it rather than crash the whole
    # enrichment, while still restoring fields for well-formed siblings.
    #
    # The raw response mirrors the actual get_host_enrichment shape
    # (single-level "result.resource.services"), not the SDK's
    # "res.result.result.resource" *object* attribute chain.
    good_service = HostEnrichmentService(port=443)
    bad_service = HostEnrichmentService(port=80)
    host = HostEnrichment(services=[good_service, bad_service])
    raw_response = {
        "result": {
            "resource": {
                "services": [
                    {"port": 443, "software": [{"product": "nginx"}]},
                    "not-a-dict",
                ]
            }
        }
    }

    Client._restore_service_fields(host, raw_response)

    assert good_service.__dict__["software"] == [{"product": "nginx"}]
    assert "software" not in bad_service.__dict__


def test_search_certificates_yields_nothing_when_no_match(mocker) -> None:
    response = MagicMock()
    response.result.result = None
    sdk = MagicMock()
    sdk.global_data.search.return_value = response
    sdk_context = mocker.patch("censys_enrichmentapis.client.SDK")
    sdk_context.return_value.__enter__.return_value = sdk

    result = list(
        Client("test-org", "test-token")._search_certificates(
            "cert.names = 'example.com'"
        )
    )

    assert result == []


def test_search_certificates_skips_hits_without_certificate(mocker) -> None:
    matching_cert = MagicMock()
    response = MagicMock()
    response.result.result.hits = [
        MagicMock(certificate_v1=None),
        MagicMock(certificate_v1=MagicMock(resource=matching_cert)),
    ]
    sdk = MagicMock()
    sdk.global_data.search.return_value = response
    sdk_context = mocker.patch("censys_enrichmentapis.client.SDK")
    sdk_context.return_value.__enter__.return_value = sdk

    result = list(Client("test-org", "test-token")._search_certificates("some query"))

    assert result == [matching_cert]
    query_arg = sdk.global_data.search.call_args.kwargs["search_query_input_body"]
    assert query_arg.query == "some query"


def _search_page(hits: list, next_page_token: str = "") -> MagicMock:
    page = MagicMock()
    page.result.result.hits = [
        MagicMock(certificate_v1=MagicMock(resource=hit)) for hit in hits
    ]
    page.result.result.next_page_token = next_page_token
    return page


def test_search_certificates_follows_next_page_token(mocker) -> None:
    first_cert, second_cert, third_cert = MagicMock(), MagicMock(), MagicMock()
    sdk = MagicMock()
    sdk.global_data.search.side_effect = [
        _search_page([first_cert, second_cert], next_page_token="page-2"),
        _search_page([third_cert]),
    ]
    sdk_context = mocker.patch("censys_enrichmentapis.client.SDK")
    sdk_context.return_value.__enter__.return_value = sdk

    result = list(Client("test-org", "test-token")._search_certificates("q"))

    assert result == [first_cert, second_cert, third_cert]
    bodies = [
        call.kwargs["search_query_input_body"]
        for call in sdk.global_data.search.call_args_list
    ]
    assert [body.page_token for body in bodies] == [None, "page-2"]
    assert [body.page_size for body in bodies] == [
        MAX_SEARCH_RESULTS,
        MAX_SEARCH_RESULTS - 2,
    ]


def test_search_certificates_stops_at_max_results(mocker) -> None:
    # The cap bounds both the number of certificates and the number of
    # (credit-consuming) search pages requested.
    sdk = MagicMock()
    sdk.global_data.search.side_effect = [
        _search_page([MagicMock(), MagicMock()], next_page_token="page-2"),
        _search_page([MagicMock(), MagicMock()], next_page_token="page-3"),
    ]
    sdk_context = mocker.patch("censys_enrichmentapis.client.SDK")
    sdk_context.return_value.__enter__.return_value = sdk

    result = list(
        Client("test-org", "test-token")._search_certificates("q", max_results=3)
    )

    assert len(result) == 3
    assert sdk.global_data.search.call_count == 2
    bodies = [
        call.kwargs["search_query_input_body"]
        for call in sdk.global_data.search.call_args_list
    ]
    # The second page only asks for what is still missing.
    assert [body.page_size for body in bodies] == [3, 1]


def test_fetch_certs_drops_invalid_hash_but_keeps_valid_one(mocker) -> None:
    # A hash that isn't hexadecimal (e.g. containing a stray quote) must not
    # reach the Censys search-query string literal unescaped.
    sdk = MagicMock()
    sdk.global_data.search.return_value.result.result = None
    sdk_context = mocker.patch("censys_enrichmentapis.client.SDK")
    sdk_context.return_value.__enter__.return_value = sdk

    list(
        Client("test-org", "test-token").fetch_certs(
            {"MD5": "deadbeef", "SHA-256": '" or cert.names="anything'}
        )
    )

    query = sdk.global_data.search.call_args.kwargs["search_query_input_body"].query
    assert query == 'cert.fingerprint_md5 = "deadbeef"'


def test_fetch_certs_raises_when_no_hash_is_usable() -> None:
    with pytest.raises(EntityHasNoUsableHashError):
        list(
            Client("test-org", "test-token").fetch_certs({"SHA-1": '"; or 1=1 or x="'})
        )


def test_fetch_certs_by_domain_rejects_quote_without_calling_api(mocker) -> None:
    sdk_context = mocker.patch("censys_enrichmentapis.client.SDK")

    result = list(
        Client("test-org", "test-token").fetch_certs_by_domain(
            "example.com' or cert.names='anything"
        )
    )

    assert result == []
    sdk_context.assert_not_called()


def test_fetch_certs_by_domain_builds_query(mocker) -> None:
    sdk = MagicMock()
    sdk.global_data.search.return_value.result.result = None
    sdk_context = mocker.patch("censys_enrichmentapis.client.SDK")
    sdk_context.return_value.__enter__.return_value = sdk

    list(Client("test-org", "test-token").fetch_certs_by_domain("example.com"))

    query = sdk.global_data.search.call_args.kwargs["search_query_input_body"].query
    assert query == "cert.names = 'example.com'"

import base64
from typing import Any
from unittest.mock import MagicMock

import pytest
import requests
from abuseipdb_taxii_client import AbuseIPDBTaxiiClient, TaxiiBadRequestError
from abuseipdb_taxii_client.api_client import TAXII_ACCEPT
from conftest import make_response
from connectors_sdk import (
    ConfigurationInvalidError,
    ProviderApiAuthenticationError,
    ProviderApiAuthorizationError,
    ProviderApiConnectionError,
    ProviderApiInvalidResponseError,
    ProviderApiNotFoundError,
    ProviderApiRateLimitError,
    ProviderApiServerError,
    ProviderApiTimeoutError,
)
from urllib3.exceptions import MaxRetryError, ReadTimeoutError

HOST = "taxii.example.test"
API_ROOT = f"https://{HOST}/taxii2/root/"
EMAIL = "someone@example.com"
API_KEY = "api-key-sentinel"
COLLECTION_SENTINEL = "collection-sentinel"
CURSOR_SENTINEL = "cursor-sentinel"
BODY_SENTINEL = "body-sentinel"
SERVER_TIMESTAMP = "2026-08-21T15:00:00.123456Z"


def make_client(*responses: requests.Response | Exception) -> AbuseIPDBTaxiiClient:
    client = AbuseIPDBTaxiiClient(
        api_root=API_ROOT,
        username=EMAIL,
        password=API_KEY,
        timeout=5,
        ssl_verify=True,
    )
    client._raw_request = MagicMock(side_effect=list(responses))
    return client


def objects_response(body: Any, **headers: str) -> requests.Response:
    return make_response(
        body=body,
        headers={"Content-Type": "application/taxii+json;version=2.1", **headers},
    )


def get_page(client: AbuseIPDBTaxiiClient, **kwargs: Any):
    params = {"added_after": None, "next_cursor": None, "limit": 100, **kwargs}
    return client.get_objects_page(COLLECTION_SENTINEL, **params)


@pytest.mark.parametrize(
    "header_name", ["X-TAXII-Date-Added-Last", "x-taxii-date-added-last"]
)
def test_date_added_last_is_read_whatever_the_header_casing(header_name: str):
    client = make_client(
        make_response(
            body={"more": False},
            headers={
                "Content-Type": "application/taxii+json;version=2.1",
                header_name: SERVER_TIMESTAMP,
            },
        )
    )

    assert get_page(client).added_last == SERVER_TIMESTAMP


@pytest.mark.parametrize(
    "headers",
    [
        pytest.param({"X-TAXII-Date-Added-Last": "not-a-timestamp"}, id="garbage"),
        pytest.param({"X-TAXII-Date-Added-Last": "2026-08-21T15:00:00"}, id="naive"),
        pytest.param({}, id="absent"),
    ],
)
def test_unusable_date_added_last_gives_no_mark(headers: dict[str, str]):
    client = make_client(objects_response({"more": False}, **headers))

    assert get_page(client).added_last is None


def test_date_added_last_is_normalized_to_the_server_format():
    client = make_client(
        objects_response(
            {"more": False}, **{"X-TAXII-Date-Added-Last": "2026-08-21T17:00:00+02:00"}
        )
    )

    assert get_page(client).added_last == "2026-08-21T15:00:00.000000Z"


def test_more_false_without_objects_is_an_empty_final_page():
    client = make_client(objects_response({"more": False}))

    page = get_page(client)

    assert page.objects == []
    assert page.more is False
    assert page.next_cursor is None


@pytest.mark.parametrize(
    "response",
    [
        pytest.param(objects_response({"more": True}), id="more_without_next"),
        pytest.param(
            objects_response({"objects": [{"id": "indicator--1"}], "more": False}),
            id="object_without_type",
        ),
        pytest.param(
            objects_response({"objects": [{"type": "indicator"}], "more": False}),
            id="object_without_id",
        ),
        pytest.param(
            objects_response({"more": "yes"}),
            id="more_not_a_bool",
        ),
        pytest.param(
            make_response(
                body={"more": False}, headers={"Content-Type": "application/json"}
            ),
            id="non_taxii_content_type",
        ),
        pytest.param(
            make_response(
                headers={"Content-Type": "application/taxii+json;version=2.1"},
                raw_body=b"not json",
            ),
            id="invalid_json",
        ),
        pytest.param(objects_response([]), id="non_object_json"),
    ],
)
def test_invalid_responses_are_rejected(response: requests.Response):
    client = make_client(response)

    with pytest.raises(ProviderApiInvalidResponseError):
        get_page(client)


@pytest.mark.parametrize(
    "content_type",
    ["application/taxii+json;version=2.1", "application/taxii+json; version=2.1"],
)
def test_both_taxii_content_type_spellings_are_accepted(content_type: str):
    client = make_client(
        make_response(body={"more": False}, headers={"Content-Type": content_type})
    )

    assert get_page(client).more is False


@pytest.mark.parametrize(
    "kwargs, expected_params",
    [
        pytest.param(
            {"added_after": "2026-08-19T04:00:00Z", "next_cursor": "c1"},
            {"limit": 100, "next": "c1"},
            id="cursor_wins",
        ),
        pytest.param(
            {"added_after": "2026-08-19T04:00:00Z", "next_cursor": None},
            {"limit": 100, "added_after": "2026-08-19T04:00:00Z"},
            id="added_after_without_cursor",
        ),
        pytest.param(
            {"added_after": None, "next_cursor": None},
            {"limit": 100},
            id="limit_only",
        ),
    ],
)
def test_request_parameters(kwargs: dict[str, Any], expected_params: dict[str, Any]):
    client = make_client(objects_response({"more": False}))

    get_page(client, **kwargs)

    assert client._raw_request.call_args.kwargs["params"] == expected_params


@pytest.mark.parametrize(
    "status, expected_error",
    [
        (400, TaxiiBadRequestError),
        (401, ProviderApiAuthenticationError),
        (403, ProviderApiAuthorizationError),
        (404, ProviderApiNotFoundError),
        (429, ProviderApiRateLimitError),
        (503, ProviderApiServerError),
    ],
)
def test_http_status_maps_to_a_standard_error(status: int, expected_error: type):
    client = make_client(make_response(status=status, body={}))

    with pytest.raises(expected_error):
        get_page(client)


def _assert_sanitized(err: BaseException) -> None:
    text = str(err)
    for sentinel in (COLLECTION_SENTINEL, CURSOR_SENTINEL, BODY_SENTINEL, HOST):
        assert sentinel not in text
    assert err.__cause__ is None


def test_http_error_does_not_expose_request_or_body():
    error_body = {
        "title": BODY_SENTINEL,
        "description": BODY_SENTINEL,
        "http_status": "400",
    }
    client = make_client(
        make_response(
            status=400,
            body=error_body,
            headers={"Content-Type": "application/taxii+json; version=2.1"},
        )
    )

    with pytest.raises(TaxiiBadRequestError) as err:
        get_page(client, next_cursor=CURSOR_SENTINEL)

    _assert_sanitized(err.value)


@pytest.mark.parametrize(
    "transport_error, expected_error",
    [
        pytest.param(
            requests.exceptions.ConnectTimeout,
            ProviderApiTimeoutError,
            id="timeout",
        ),
        pytest.param(
            requests.exceptions.ConnectionError,
            ProviderApiConnectionError,
            id="connection",
        ),
    ],
)
def test_transport_error_does_not_expose_the_url(
    transport_error: type[requests.exceptions.RequestException],
    expected_error: type,
):
    url = f"{API_ROOT}collections/{COLLECTION_SENTINEL}/objects/?next={CURSOR_SENTINEL}"
    client = make_client(transport_error(f"failed: {url}"))

    with pytest.raises(expected_error) as err:
        get_page(client, next_cursor=CURSOR_SENTINEL)

    _assert_sanitized(err.value)
    assert err.value.__suppress_context__ is True


def test_read_timeout_after_retries_is_a_timeout():
    url = f"{API_ROOT}collections/{COLLECTION_SENTINEL}/objects/?next={CURSOR_SENTINEL}"
    exhausted = MaxRetryError(
        pool=None, url=url, reason=ReadTimeoutError(None, url, "Read timed out.")
    )
    client = make_client(requests.exceptions.ConnectionError(exhausted))

    with pytest.raises(ProviderApiTimeoutError) as err:
        get_page(client, next_cursor=CURSOR_SENTINEL)

    _assert_sanitized(err.value)


def test_read_timeout_while_reading_the_body_is_a_timeout():
    url = f"{API_ROOT}collections/{COLLECTION_SENTINEL}/objects/?next={CURSOR_SENTINEL}"
    stalled = ReadTimeoutError(None, url, "Read timed out.")
    client = make_client(requests.exceptions.ConnectionError(stalled))

    with pytest.raises(ProviderApiTimeoutError) as err:
        get_page(client, next_cursor=CURSOR_SENTINEL)

    _assert_sanitized(err.value)


def test_discovery_picks_the_single_readable_feed():
    client = make_client(
        objects_response(
            {
                "collections": [
                    {"id": "reports", "can_read": False, "can_write": True},
                    {"id": "feed", "can_read": True, "can_write": False},
                ]
            }
        )
    )

    assert client.discover_collection_id(None) == "feed"


REPORTS_COLLECTION = {"id": "reports-sentinel", "can_read": False, "can_write": True}
FEED_A = {"id": "feed-a-sentinel", "can_read": True, "can_write": False}
FEED_B = {"id": "feed-b-sentinel", "can_read": True, "can_write": False}


@pytest.mark.parametrize(
    "configured_id",
    [
        pytest.param(FEED_B["id"], id="same_case"),
        pytest.param(FEED_B["id"].upper(), id="upper_case"),
    ],
)
def test_discovery_picks_the_configured_feed_among_several(configured_id: str):
    client = make_client(
        objects_response({"collections": [REPORTS_COLLECTION, FEED_A, FEED_B]})
    )

    assert client.discover_collection_id(configured_id) == FEED_B["id"]


@pytest.mark.parametrize(
    "configured_id, collections",
    [
        pytest.param(
            "unknown-sentinel",
            [REPORTS_COLLECTION, FEED_A, FEED_B],
            id="configured_absent",
        ),
        pytest.param(
            REPORTS_COLLECTION["id"],
            [REPORTS_COLLECTION, FEED_A, FEED_B],
            id="configured_not_readable",
        ),
        pytest.param(None, [REPORTS_COLLECTION], id="unset_none_readable"),
        pytest.param(
            None, [REPORTS_COLLECTION, FEED_A, FEED_B], id="unset_several_readable"
        ),
    ],
)
def test_discovery_rejects_an_unusable_feed_choice(
    configured_id: str | None, collections: list[dict]
):
    client = make_client(objects_response({"collections": collections}))

    with pytest.raises(ConfigurationInvalidError) as err:
        client.discover_collection_id(configured_id)

    for collection_id in [configured_id, *(c["id"] for c in collections)]:
        assert collection_id is None or collection_id not in str(err.value)


@pytest.mark.parametrize(
    "body",
    [
        pytest.param({"collections": "feed"}, id="collections_not_a_list"),
        pytest.param({}, id="collections_missing"),
        pytest.param({"collections": [{"can_read": True}]}, id="id_missing"),
        pytest.param({"collections": [{"id": ""}]}, id="id_empty"),
    ],
)
def test_discovery_rejects_malformed_metadata(body: dict):
    client = make_client(objects_response(body))

    with pytest.raises(ProviderApiInvalidResponseError):
        client.discover_collection_id(None)


def test_session_uses_taxii_accept_basic_auth_and_bounded_retries():
    client = AbuseIPDBTaxiiClient(
        api_root=API_ROOT,
        username=EMAIL,
        password=API_KEY,
        timeout=5,
        ssl_verify=True,
    )

    session = client._session
    scheme, encoded = session.headers["Authorization"].split(" ", 1)
    retry = session.get_adapter(API_ROOT).max_retries

    assert session.headers["Accept"] == TAXII_ACCEPT
    assert scheme == "Basic"
    assert base64.b64decode(encoded).decode("utf-8") == f"{EMAIL}:{API_KEY}"
    assert retry.total == 5
    assert retry.respect_retry_after_header is True

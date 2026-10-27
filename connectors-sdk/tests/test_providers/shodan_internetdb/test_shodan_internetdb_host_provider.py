# pragma: no cover # Do not compute coverage on test files
"""Offer tests for ShodanInternetDbHostByIdProvider."""

import json
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest
import requests
from connectors_sdk.client.exceptions import (
    ApiNotFoundError,
    ApiRateLimitError,
    ApiServerError,
)
from connectors_sdk.converters.shodan_internetdb import ShodanInternetDbHostConverter
from connectors_sdk.exceptions.error import DataRetrievalError
from connectors_sdk.models import OrganizationAuthor, TLPMarking
from connectors_sdk.providers import AbstractByIdProvider
from connectors_sdk.providers.shodan_internetdb import (
    ShodanInternetDbClient,
    ShodanInternetDbHostByIdProvider,
)

FIXTURE = (
    Path(__file__).parents[2]
    / "test_converters"
    / "shodan_internetdb"
    / "fixtures"
    / "internetdb_result.json"
)
IP = "198.51.100.7"
UNKNOWN_IP = "10.0.0.1"


class FakeShodanInternetDbClient(ShodanInternetDbClient):
    """Fake client answering per IP and recording calls."""

    def __init__(self, responses: dict[str, Any]) -> None:
        """Store the response, or the exception, of each IP."""
        super().__init__(max_retries=0)
        self.responses = responses
        self.calls: list[str] = []

    def get_host(self, ip: str) -> Any:
        """Return or raise the configured response."""
        self.calls.append(ip)
        response = self.responses[ip]
        if isinstance(response, Exception):
            raise response
        return response


@pytest.fixture
def body() -> dict[str, Any]:
    """Return an InternetDB body."""
    return dict(json.loads(FIXTURE.read_text()))


def test_provider_type_and_name() -> None:
    """Test that the provider is a by id provider."""
    assert issubclass(ShodanInternetDbHostByIdProvider, AbstractByIdProvider)


def test_default_client() -> None:
    """Test that the default client targets the public InternetDB API."""
    provider = ShodanInternetDbHostByIdProvider()

    assert isinstance(provider.client, ShodanInternetDbClient)
    assert provider.client._base_url == "https://internetdb.shodan.io"


def test_client_queries_the_ip_path() -> None:
    """Test that the client GETs `/<ip>`."""
    client = ShodanInternetDbClient()
    with patch.object(client, "_get", return_value={"ip": IP}) as get:
        assert client.get_host(IP) == {"ip": IP}

    get.assert_called_once_with(IP)


def test_known_ip(body: dict[str, Any]) -> None:
    """Test that a known IP gives an item with the IP and its result."""
    client = FakeShodanInternetDbClient({IP: body})

    item = ShodanInternetDbHostByIdProvider(client=client).get_data([IP])[IP]

    assert item.observable_value == IP
    assert item.result.ports == body["ports"]
    assert item.result.vulns == body["vulns"]


def test_duplicate_ip_queried_once(body: dict[str, Any]) -> None:
    """Test that each distinct IP is queried once."""
    client = FakeShodanInternetDbClient({IP: body})

    ShodanInternetDbHostByIdProvider(client=client).get_data([IP, IP])

    assert client.calls == [IP]


def test_unknown_ip_left_out(body: dict[str, Any]) -> None:
    """Test that a 404 leaves the IP out without raising."""
    not_found = ApiNotFoundError("No information available")
    client = FakeShodanInternetDbClient({IP: body, UNKNOWN_IP: not_found})

    result = ShodanInternetDbHostByIdProvider(client=client).get_data([UNKNOWN_IP, IP])

    assert list(result) == [IP]


@pytest.mark.parametrize(
    "error",
    [ApiRateLimitError("Too many requests"), ApiServerError("Bad gateway")],
)
def test_api_error_raises(error: Exception) -> None:
    """Test that other API errors raise a DataRetrievalError with the cause."""
    client = FakeShodanInternetDbClient({IP: error})

    with pytest.raises(DataRetrievalError, match=IP) as raised:
        ShodanInternetDbHostByIdProvider(client=client).get_data([IP])

    assert raised.value.__cause__ is error


def test_connection_error_raises_with_cause() -> None:
    """Test that a failed request raises a DataRetrievalError with the cause."""
    error = requests.ConnectionError("connection refused")
    client = FakeShodanInternetDbClient({IP: error})

    with pytest.raises(DataRetrievalError) as raised:
        ShodanInternetDbHostByIdProvider(client=client).get_data([IP])

    assert raised.value.__cause__ is error


def test_unexpected_body_raises() -> None:
    """Test that a body of an unexpected format raises a DataRetrievalError."""
    client = FakeShodanInternetDbClient({IP: {"detail": "unexpected"}})

    with pytest.raises(DataRetrievalError, match="Unexpected"):
        ShodanInternetDbHostByIdProvider(client=client).get_data([IP])


def test_failure_for_one_ip_gives_no_partial_result(body: dict[str, Any]) -> None:
    """Test that a failure for one IP of a list fails the whole call."""
    client = FakeShodanInternetDbClient({IP: body, UNKNOWN_IP: ApiServerError("x")})

    with pytest.raises(DataRetrievalError):
        ShodanInternetDbHostByIdProvider(client=client).get_data([IP, UNKNOWN_IP])


def test_items_chain_with_converter(body: dict[str, Any]) -> None:
    """Test that the provider items are accepted as is by the converter."""
    provider = ShodanInternetDbHostByIdProvider(
        client=FakeShodanInternetDbClient({IP: body})
    )
    converter = ShodanInternetDbHostConverter(
        author=OrganizationAuthor(name="Shodan"),
        markings=[TLPMarking(level="clear")],
    )

    objects = [
        obj
        for item in provider.get_data([IP]).values()
        for obj in converter.transform(item)
    ]

    assert objects

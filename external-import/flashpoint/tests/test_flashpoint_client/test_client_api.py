import json
from pathlib import Path
from unittest.mock import Mock, patch

import pytest
from flashpoint_client import FlashpointClient, FlashpointClientError
from flashpoint_client.models import CompromisedCredentialSighting
from pydantic import ValidationError
from requests import Response
from requests.exceptions import HTTPError

TEST_API_BASE_URL = "http://flashpointtest.com"
TEST_API_KEY = "<API_KEY>"


@pytest.fixture
def mock_flashpoint_client():
    return FlashpointClient(
        api_base_url=TEST_API_BASE_URL,
        api_key=TEST_API_KEY,
    )


def mock_response(status_code: int, body: dict | None = None):
    response = Mock(spec=Response)

    response.status_code = status_code
    response.json = lambda: body

    if status_code >= 400:
        response.url = TEST_API_BASE_URL
        response.reason = "An error occured"
        response.raise_for_status = lambda: Response.raise_for_status(response)

    return response


def get_data_sample(file_name):
    file_path = Path(__file__).parent.parent.joinpath("data_samples", file_name)
    with open(file_path, encoding="utf-8") as f:
        data = json.load(f)
    return data


def test_flashpoint_client_session(mock_flashpoint_client):
    assert mock_flashpoint_client.session is not None
    assert mock_flashpoint_client.session.headers is not None
    assert (
        mock_flashpoint_client.session.headers["Authorization"]
        == f"Bearer {TEST_API_KEY}"
    )


def test_get_compromised_credential_sightings_should_return_compromised_credential_sightings(
    mock_flashpoint_client,
):
    with patch(
        "requests.Session.request",
        return_value=mock_response(
            status_code=200,
            body=get_data_sample(
                "search_compromised_credential_sightings_response.json"
            ),
        ),
    ):
        data = mock_flashpoint_client.get_compromised_credential_sightings()
        compromised_credential_sightings = [
            obj for obj in data
        ]  # convert generator to list

    assert isinstance(compromised_credential_sightings, list)
    assert isinstance(
        compromised_credential_sightings[0], CompromisedCredentialSighting
    )


@pytest.mark.parametrize(
    "status_code",
    [
        pytest.param(403, id="forbidden"),
        pytest.param(404, id="not_found"),
        pytest.param(429, id="too_many_requests"),
    ],
)
def test_get_compromised_credential_sightings_should_handle_requests_exceptions(
    mock_flashpoint_client, status_code
):
    with patch(
        "requests.Session.request",
        return_value=mock_response(status_code=status_code),
    ):
        with pytest.raises(FlashpointClientError) as exc_info:
            data = mock_flashpoint_client.get_compromised_credential_sightings()
            _ = [obj for obj in data]  # convert to list to execute generator

    assert "Failed to fetch Compromised Credential Sightings" in str(exc_info)
    assert isinstance(exc_info.value.__cause__, HTTPError)
    assert str(status_code) in str(exc_info.value.__cause__)


def test_get_compromised_credential_sightings_should_handle_validation_exceptions(
    mock_flashpoint_client,
):
    with patch(
        "requests.Session.request",
        return_value=mock_response(
            status_code=200,
            body={
                "hits": {
                    "total": 1,
                    "hits": [
                        {
                            "_source": {
                                "header_": {"indexed_at": 1234567890},
                                "basetype": "credential-sighting",
                                # Missing required fields for CompromisedCredentialSighting
                            }
                        }
                    ],
                },
            },
        ),
    ):
        with pytest.raises(FlashpointClientError) as exc_info:
            data = mock_flashpoint_client.get_compromised_credential_sightings()
            _ = [obj for obj in data]  # convert to list to execute generator

    assert "Invalid Compromised Credential Sighting data" in str(exc_info)
    assert isinstance(exc_info.value.__cause__, ValidationError)

from unittest.mock import MagicMock, patch

import pytest
import requests
from rf_asi_client.api_client import RfAsiClient


def _mock_response(payload: dict) -> MagicMock:
    response = MagicMock()
    response.json.return_value = payload
    response.raise_for_status.return_value = None
    return response


def test_client_sets_apikey_header(opencti_helper):
    client = RfAsiClient(
        opencti_helper,
        base_url="https://api.securitytrails.com/v2",
        api_key="secret-api-key",
    )

    assert client.session.headers["apikey"] == "secret-api-key"
    assert client.session.headers["accept"] == "application/json"


def test_list_exposures_follows_cursor_pagination(
    opencti_helper, exposures_list_page, exposures_list_page_last, all_exposure_items
):
    client = RfAsiClient(
        opencti_helper,
        base_url="https://api.securitytrails.com/v2",
        api_key="test-api-key",
    )

    with patch.object(
        client.session,
        "get",
        side_effect=[
            _mock_response(exposures_list_page),
            _mock_response(exposures_list_page_last),
        ],
    ) as mock_get:
        exposures = client.list_exposures("test-project-id", limit=100)

    assert exposures == all_exposure_items
    assert mock_get.call_count == 2

    first_call_kwargs = mock_get.call_args_list[0].kwargs
    second_call_kwargs = mock_get.call_args_list[1].kwargs

    assert first_call_kwargs["params"] == {"limit": 100}
    assert second_call_kwargs["params"] == {
        "limit": 100,
        "cursor": "cursor-page-2",
    }
    assert mock_get.call_args_list[0].args[0] == (
        "https://api.securitytrails.com/v2/projects/test-project-id/exposures"
    )


def test_list_exposures_passes_filters(opencti_helper, exposures_list_page_last):
    client = RfAsiClient(
        opencti_helper,
        base_url="https://api.securitytrails.com/v2",
        api_key="test-api-key",
    )

    with patch.object(
        client.session,
        "get",
        return_value=_mock_response(exposures_list_page_last),
    ) as mock_get:
        client.list_exposures(
            "test-project-id",
            limit=50,
            filter_severity_min="moderate",
        )

    assert mock_get.call_args.kwargs["params"] == {
        "limit": 50,
        "filter_severity_min": "moderate",
    }


def test_list_exposures_returns_partial_results_on_mid_pagination_failure(
    opencti_helper, exposures_list_page
):
    client = RfAsiClient(
        opencti_helper,
        base_url="https://api.securitytrails.com/v2",
        api_key="test-api-key",
    )

    failing_response = MagicMock()
    failing_response.raise_for_status.side_effect = requests.HTTPError("502 Bad Gateway")

    with patch.object(
        client.session,
        "get",
        side_effect=[
            _mock_response(exposures_list_page),
            failing_response,
        ],
    ):
        exposures = client.list_exposures("test-project-id", limit=100)

    assert exposures == exposures_list_page["data"]


def test_list_exposures_raises_on_first_page_failure(opencti_helper):
    client = RfAsiClient(
        opencti_helper,
        base_url="https://api.securitytrails.com/v2",
        api_key="test-api-key",
    )

    failing_response = MagicMock()
    failing_response.raise_for_status.side_effect = requests.HTTPError("401 Unauthorized")

    with patch.object(client.session, "get", return_value=failing_response):
        with pytest.raises(requests.HTTPError):
            client.list_exposures("test-project-id", limit=100)


def test_parse_list_response_handles_missing_fields():
    data, next_cursor = RfAsiClient._parse_list_response({})

    assert data == []
    assert next_cursor is None

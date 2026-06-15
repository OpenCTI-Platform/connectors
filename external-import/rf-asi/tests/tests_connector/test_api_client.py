from unittest.mock import MagicMock, patch

import pytest
import requests
from rf_asi_client.api_client import HttpRetrySettings, RfAsiClient


def _mock_response(payload: dict) -> MagicMock:
    response = MagicMock()
    response.json.return_value = payload
    response.raise_for_status.return_value = None
    return response


def _error_response(status_code: int, headers: dict | None = None) -> MagicMock:
    response = MagicMock()
    response.status_code = status_code
    response.headers = headers or {}

    def raise_for_status() -> None:
        raise requests.HTTPError(response=response)

    response.raise_for_status = raise_for_status
    return response


def _client(opencti_helper, **kwargs) -> RfAsiClient:
    defaults = {
        "base_url": "https://api.securitytrails.com/v2",
        "api_key": "test-api-key",
        "retry": HttpRetrySettings(max_attempts=3),
    }
    defaults.update(kwargs)
    return RfAsiClient(opencti_helper, **defaults)


def test_client_sets_apikey_header(opencti_helper):
    client = RfAsiClient(
        opencti_helper,
        base_url="https://api.securitytrails.com/v2",
        api_key="secret-api-key",
    )

    assert client.session.headers["apikey"] == "secret-api-key"
    assert client.session.headers["accept"] == "application/json"


def test_list_exposures_page_returns_items_and_cursor(
    opencti_helper, exposures_list_page
):
    client = RfAsiClient(
        opencti_helper,
        base_url="https://api.securitytrails.com/v2",
        api_key="test-api-key",
    )

    with patch.object(
        client.session,
        "get",
        return_value=_mock_response(exposures_list_page),
    ) as mock_get:
        items, next_cursor = client.list_exposures_page("test-project-id", limit=100)

    assert items == exposures_list_page["data"]
    assert next_cursor == "cursor-page-2"
    assert mock_get.call_count == 1
    assert mock_get.call_args.kwargs["params"] == {"limit": 100}
    assert mock_get.call_args.args[0] == (
        "https://api.securitytrails.com/v2/projects/test-project-id/exposures"
    )


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
    failing_response.raise_for_status.side_effect = requests.HTTPError(
        "502 Bad Gateway"
    )

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
    failing_response.raise_for_status.side_effect = requests.HTTPError(
        "401 Unauthorized"
    )

    with patch.object(client.session, "get", return_value=failing_response):
        with pytest.raises(requests.HTTPError):
            client.list_exposures("test-project-id", limit=100)


def test_parse_list_response_handles_missing_fields():
    data, next_cursor = RfAsiClient._parse_list_response({})

    assert data == []
    assert next_cursor is None


def test_get_exposure_assets_page_returns_signature_assets_and_cursor(
    opencti_helper, exposure_assets_page
):
    client = RfAsiClient(
        opencti_helper,
        base_url="https://api.securitytrails.com/v2",
        api_key="test-api-key",
    )

    with patch.object(
        client.session,
        "get",
        return_value=_mock_response(exposure_assets_page),
    ) as mock_get:
        signature, asset_exposures, next_cursor = client.get_exposure_assets_page(
            "test-project-id",
            "sig-001",
            limit=100,
        )

    assert signature == exposure_assets_page["data"]["signature"]
    assert asset_exposures == exposure_assets_page["data"]["asset_exposures"]
    assert next_cursor == "assets-cursor-page-2"
    assert mock_get.call_count == 1
    assert mock_get.call_args.kwargs["params"] == {"limit": 100}
    assert mock_get.call_args.args[0] == (
        "https://api.securitytrails.com/v2/projects/test-project-id/exposures/sig-001"
    )


def test_get_exposure_assets_follows_cursor_pagination(
    opencti_helper,
    exposure_assets_page,
    exposure_assets_page_last,
    all_exposure_assets,
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
            _mock_response(exposure_assets_page),
            _mock_response(exposure_assets_page_last),
        ],
    ) as mock_get:
        assets_data = client.get_exposure_assets(
            "test-project-id",
            "sig-001",
            limit=100,
        )

    assert assets_data == all_exposure_assets
    assert mock_get.call_count == 2

    first_call_kwargs = mock_get.call_args_list[0].kwargs
    second_call_kwargs = mock_get.call_args_list[1].kwargs

    assert first_call_kwargs["params"] == {"limit": 100}
    assert second_call_kwargs["params"] == {
        "limit": 100,
        "cursor": "assets-cursor-page-2",
    }


def test_get_exposure_assets_returns_partial_results_on_mid_pagination_failure(
    opencti_helper, exposure_assets_page
):
    client = RfAsiClient(
        opencti_helper,
        base_url="https://api.securitytrails.com/v2",
        api_key="test-api-key",
    )

    failing_response = MagicMock()
    failing_response.raise_for_status.side_effect = requests.HTTPError(
        "502 Bad Gateway"
    )

    with patch.object(
        client.session,
        "get",
        side_effect=[
            _mock_response(exposure_assets_page),
            failing_response,
        ],
    ):
        assets_data = client.get_exposure_assets(
            "test-project-id",
            "sig-001",
            limit=100,
        )

    assert assets_data == {
        "signature": exposure_assets_page["data"]["signature"],
        "asset_exposures": exposure_assets_page["data"]["asset_exposures"],
    }


def test_parse_assets_response_handles_missing_fields():
    signature, asset_exposures, next_cursor = RfAsiClient._parse_assets_response({})

    assert signature == {}
    assert asset_exposures == []
    assert next_cursor is None


def test_list_exposures_batch_run_limit_one_preserves_cursor(
    opencti_helper, exposures_list_page
):
    client = RfAsiClient(
        opencti_helper,
        base_url="https://api.securitytrails.com/v2",
        api_key="test-api-key",
    )

    with patch.object(
        client.session,
        "get",
        return_value=_mock_response(exposures_list_page),
    ) as mock_get:
        exposures, next_cursor = client.list_exposures_batch(
            "test-project-id",
            page_limit=100,
            run_limit=1,
        )

    assert len(exposures) == 1
    assert exposures[0] == exposures_list_page["data"][0]
    assert next_cursor == "cursor-page-2"
    assert mock_get.call_count == 1
    assert mock_get.call_args.kwargs["params"] == {"limit": 1}


def test_list_exposures_batch_run_limit_two_from_cursor_completes_cycle(
    opencti_helper, exposures_list_page_last
):
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
        exposures, next_cursor = client.list_exposures_batch(
            "test-project-id",
            page_limit=100,
            run_limit=2,
            cursor="cursor-page-2",
        )

    assert exposures == exposures_list_page_last["data"]
    assert next_cursor is None
    assert mock_get.call_count == 1
    assert mock_get.call_args.kwargs["params"] == {
        "limit": 2,
        "cursor": "cursor-page-2",
    }


def test_list_exposures_batch_run_limit_three_spans_both_pages(
    opencti_helper,
    exposures_list_page,
    exposures_list_page_last,
    all_exposure_items,
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
        exposures, next_cursor = client.list_exposures_batch(
            "test-project-id",
            page_limit=100,
            run_limit=3,
        )

    assert exposures == all_exposure_items
    assert next_cursor is None
    assert mock_get.call_count == 2

    first_call_kwargs = mock_get.call_args_list[0].kwargs
    second_call_kwargs = mock_get.call_args_list[1].kwargs

    assert first_call_kwargs["params"] == {"limit": 3}
    assert second_call_kwargs["params"] == {
        "limit": 1,
        "cursor": "cursor-page-2",
    }


def test_request_data_retries_on_429_then_succeeds(opencti_helper, exposures_list_page):
    client = _client(opencti_helper)

    with patch("time.sleep"), patch.object(
        client.session,
        "get",
        side_effect=[
            _error_response(429),
            _mock_response(exposures_list_page),
        ],
    ) as mock_get:
        items, next_cursor = client.list_exposures_page("test-project-id", limit=100)

    assert items == exposures_list_page["data"]
    assert next_cursor == "cursor-page-2"
    assert mock_get.call_count == 2


def test_request_data_honors_retry_after_header(opencti_helper, exposures_list_page):
    client = _client(opencti_helper)

    with patch("time.sleep") as mock_sleep, patch.object(
        client.session,
        "get",
        side_effect=[
            _error_response(429, headers={"Retry-After": "15"}),
            _mock_response(exposures_list_page),
        ],
    ):
        client.list_exposures_page("test-project-id", limit=100)

    mock_sleep.assert_called_with(15)


def test_request_data_raises_after_retry_exhausted(opencti_helper):
    client = _client(opencti_helper)

    with patch("time.sleep"), patch.object(
        client.session,
        "get",
        return_value=_error_response(429),
    ) as mock_get:
        with pytest.raises(requests.HTTPError):
            client.list_exposures_page("test-project-id", limit=100)

    assert mock_get.call_count == 3


def test_request_data_does_not_retry_401(opencti_helper):
    client = _client(opencti_helper)

    with patch.object(
        client.session,
        "get",
        return_value=_error_response(401),
    ) as mock_get:
        with pytest.raises(requests.HTTPError):
            client.list_exposures_page("test-project-id", limit=100)

    assert mock_get.call_count == 1


def test_list_exposures_batch_stops_at_first_page_when_run_limit_reached(
    opencti_helper, exposures_list_page
):
    client = RfAsiClient(
        opencti_helper,
        base_url="https://api.securitytrails.com/v2",
        api_key="test-api-key",
    )

    with patch.object(
        client.session,
        "get",
        return_value=_mock_response(exposures_list_page),
    ) as mock_get:
        exposures, next_cursor = client.list_exposures_batch(
            "test-project-id",
            page_limit=100,
            run_limit=2,
        )

    assert len(exposures) == 2
    assert exposures == exposures_list_page["data"]
    assert next_cursor == "cursor-page-2"
    assert mock_get.call_count == 1
    assert mock_get.call_args.kwargs["params"] == {"limit": 2}

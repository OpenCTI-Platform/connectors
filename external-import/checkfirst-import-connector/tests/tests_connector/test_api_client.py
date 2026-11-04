from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import pytest
from checkfirst_client import CheckfirstClient


@pytest.fixture
def mock_session_get(monkeypatch):
    """Replace `requests.Session.get` with a mock answering one empty last page."""
    response = MagicMock()
    response.json.return_value = {"data": [], "pagination": {"has_next": False}}
    session_get = MagicMock(return_value=response)
    monkeypatch.setattr("requests.Session.get", session_get)
    return session_get


@pytest.fixture
def api_client():
    return CheckfirstClient(
        helper=MagicMock(),
        base_url="https://api.checkfirst.example",
        api_key="test-api-key",
    )


def test_client_should_send_since_and_until_as_utc_iso_strings(
    api_client, mock_session_get
):
    """Both bounds reach the API as `...Z` strings, the format it documents."""
    list(
        api_client.fetch_paginated_data(
            api_endpoint="/v1/articles",
            since=datetime(2025, 1, 1, tzinfo=timezone.utc),
            until=datetime(2025, 1, 31, 23, 59, 59, tzinfo=timezone.utc),
        )
    )

    params = mock_session_get.call_args.kwargs["params"]
    assert params == {
        "since": "2025-01-01T00:00:00Z",
        "until": "2025-01-31T23:59:59Z",
    }


def test_client_should_convert_offset_bounds_to_utc(api_client, mock_session_get):
    """A bound with another offset is sent as the same instant in UTC."""
    list(
        api_client.fetch_paginated_data(
            api_endpoint="/v1/articles",
            until=datetime(2025, 2, 1, 1, 0, tzinfo=timezone(timedelta(hours=2))),
        )
    )

    params = mock_session_get.call_args.kwargs["params"]
    assert params["until"] == "2025-01-31T23:00:00Z"


def test_client_should_omit_until_when_not_set(api_client, mock_session_get):
    """Without `until`, the request carries no upper bound at all."""
    list(
        api_client.fetch_paginated_data(
            api_endpoint="/v1/articles",
            since=datetime(2025, 1, 1, tzinfo=timezone.utc),
        )
    )

    params = mock_session_get.call_args.kwargs["params"]
    assert "until" not in params
    assert params["since"] == "2025-01-01T00:00:00Z"


def test_client_should_forward_until_from_iter_api_rows(api_client, monkeypatch):
    """`iter_api_rows` passes `until` through to the paginated fetch."""
    fetch = MagicMock(return_value=iter([]))
    monkeypatch.setattr(api_client, "fetch_paginated_data", fetch)
    until = datetime(2025, 1, 31, tzinfo=timezone.utc)

    list(api_client.iter_api_rows(api_endpoint="/v1/articles", until=until))

    assert fetch.call_args.kwargs["until"] == until


def test_client_should_send_until_alongside_the_cursor(api_client, mock_session_get):
    """Resuming from a saved cursor keeps the upper bound on every request."""
    list(
        api_client.fetch_paginated_data(
            api_endpoint="/v1/articles",
            after="66f0c0ffee",
            until=datetime(2025, 1, 31, 23, 59, 59, tzinfo=timezone.utc),
        )
    )

    params = mock_session_get.call_args.kwargs["params"]
    assert params == {"after": "66f0c0ffee", "until": "2025-01-31T23:59:59Z"}

"""Tests for keyset (`after` / `next_cursor`) pagination in `CheckfirstClient`."""

from json import JSONDecodeError
from unittest.mock import MagicMock

import pytest
import requests
from checkfirst_client import CheckfirstClient
from checkfirst_client.api_client import CheckfirstAPIError
from utils.run_reporter import SkipReason, run_reporter


def _article(article_id: str, **overrides) -> dict:
    item = {
        "_id": article_id,
        "url": f"https://france.news-pravda.com/{article_id}",
        "source_title": "Telegram Source",
        "source_url": "https://t.me/source",
        "published_date": "2025-03-15T00:00:00Z",
    }
    item.update(overrides)
    return item


def _response(payload: dict) -> MagicMock:
    response = MagicMock()
    response.json.return_value = payload
    return response


def _page(items: list[dict], has_next: bool, next_cursor: str | None = None) -> dict:
    pagination: dict = {"has_next": has_next}
    if next_cursor is not None:
        pagination["next_cursor"] = next_cursor
    return {"data": items, "pagination": pagination}


@pytest.fixture(autouse=True)
def reset_reporter():
    run_reporter.reset()
    yield
    run_reporter.reset()


@pytest.fixture
def api_client():
    return CheckfirstClient(
        helper=MagicMock(),
        base_url="https://api.checkfirst.example",
        api_key="test-api-key",
    )


@pytest.fixture
def session_get(monkeypatch):
    get = MagicMock()
    monkeypatch.setattr("requests.Session.get", get)
    return get


def test_fetch_should_follow_next_cursor_until_last_page(api_client, session_get):
    session_get.side_effect = [
        _response(_page([_article("a"), _article("b")], True, "b")),
        _response(_page([_article("c")], False)),
    ]

    items = list(api_client.fetch_paginated_data(api_endpoint="v1/articles"))

    assert [item["_id"] for item in items] == ["a", "b", "c"]
    first_call, second_call = session_get.call_args_list
    assert first_call.args[0] == "https://api.checkfirst.example/v1/articles"
    assert "after" not in first_call.kwargs["params"]
    assert second_call.kwargs["params"]["after"] == "b"
    assert run_reporter.pages_fetched == 2


def test_fetch_should_resume_after_the_given_cursor(api_client, session_get):
    session_get.return_value = _response(_page([_article("z")], False))

    list(api_client.fetch_paginated_data(api_endpoint="/v1/articles", after="y"))

    assert session_get.call_args.kwargs["params"]["after"] == "y"


def test_fetch_should_fall_back_to_last_item_id_without_next_cursor(
    api_client, session_get
):
    session_get.side_effect = [
        _response(_page([_article("a"), _article("b")], True)),
        _response(_page([], True)),
    ]

    items = list(api_client.fetch_paginated_data(api_endpoint="/v1/articles"))

    assert [item["_id"] for item in items] == ["a", "b"]
    assert session_get.call_args.kwargs["params"]["after"] == "b"


def test_fetch_should_raise_on_unrecognized_response(api_client, session_get):
    session_get.return_value = _response({"items": []})

    with pytest.raises(CheckfirstAPIError, match="Unrecognized API response"):
        list(api_client.fetch_paginated_data(api_endpoint="/v1/articles"))


def test_fetch_should_raise_on_http_error(api_client, session_get):
    error_response = MagicMock(status_code=503, reason="Service Unavailable")
    response = MagicMock()
    response.raise_for_status.side_effect = requests.HTTPError(response=error_response)
    session_get.return_value = response

    with pytest.raises(CheckfirstAPIError, match="HTTP error 503"):
        list(api_client.fetch_paginated_data(api_endpoint="/v1/articles"))


def test_fetch_should_raise_on_invalid_json(api_client, session_get):
    response = MagicMock()
    response.json.side_effect = JSONDecodeError("Expecting value", "", 0)
    session_get.return_value = response

    with pytest.raises(CheckfirstAPIError, match="Invalid JSON"):
        list(api_client.fetch_paginated_data(api_endpoint="/v1/articles"))


def test_fetch_should_raise_on_request_failure(api_client, session_get):
    session_get.side_effect = requests.ConnectionError("connection refused")

    with pytest.raises(CheckfirstAPIError, match="connection refused"):
        list(api_client.fetch_paginated_data(api_endpoint="/v1/articles"))


def test_iter_rows_should_track_last_seen_id_including_skipped_rows(
    api_client, session_get
):
    session_get.return_value = _response(
        _page(
            [
                _article("a"),
                _article("b", url=""),  # empty -> dropped -> missing required field
                _article("c", published_date="not-a-date"),
                _article("d", description="x" * 500),  # too large
            ],
            False,
        )
    )

    rows = list(
        api_client.iter_api_rows(api_endpoint="/v1/articles", max_row_bytes=300)
    )

    assert [row.id for row in rows] == ["a"]
    assert [row.row_number for row in rows] == [1]
    assert api_client.last_seen_id == "d"
    assert run_reporter.skipped == {
        SkipReason.ROW_MISSING_REQUIRED_FIELDS.value: 1,
        SkipReason.ROW_INVALID_PUBLICATION_DATE.value: 1,
        SkipReason.ROW_TOO_LARGE.value: 1,
    }


def test_iter_rows_should_raise_on_unexpected_validation_error(api_client, session_get):
    session_get.return_value = _response(
        _page([_article("a", keywords="not-a-list")], False)
    )

    with pytest.raises(CheckfirstAPIError, match="Data validation error for row 1"):
        list(api_client.iter_api_rows(api_endpoint="/v1/articles"))

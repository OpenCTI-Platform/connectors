"""Tests for the Wiz GraphQL pagination guards."""

from unittest.mock import MagicMock

from wiz_cloud.client_api import WizApiClient


def _client() -> WizApiClient:
    """Build a client without performing any network call.

    Returns:
        A client whose execute() and logger are MagicMocks.
    """
    client = WizApiClient.__new__(WizApiClient)
    client.execute = MagicMock()
    client._logger = MagicMock()
    return client


def _page(nodes: list[dict], has_next: bool, cursor: str | None) -> dict:
    return {
        "things": {
            "nodes": nodes,
            "pageInfo": {"hasNextPage": has_next, "endCursor": cursor},
        }
    }


def test_paginate_walks_pages_until_has_next_page_is_false():
    client = _client()
    client.execute.side_effect = [
        _page([{"id": "1"}], True, "cursor-1"),
        _page([{"id": "2"}], False, None),
    ]

    pages = list(client.paginate("query", {"after": None}, connection_key="things"))

    assert pages == [[{"id": "1"}], [{"id": "2"}]]
    assert client.execute.call_args_list[1][0][1]["after"] == "cursor-1"


def test_paginate_stops_when_the_cursor_is_missing():
    client = _client()
    client.execute.side_effect = [_page([{"id": "1"}], True, None)]

    pages = list(client.paginate("query", {"after": None}, connection_key="things"))

    assert pages == [[{"id": "1"}]]
    assert client.execute.call_count == 1
    assert client._logger.warning.called


def test_paginate_reports_a_missing_cursor_as_such():
    """The warning must say why pagination stopped, not just that it did."""
    client = _client()
    client.execute.side_effect = [_page([{"id": "1"}], True, None)]

    list(client.paginate("query", {"after": None}, connection_key="things"))

    meta = client._logger.warning.call_args[0][1]
    assert meta["reason"] == "missing"
    assert meta["connection"] == "things"


def test_paginate_stops_when_the_cursor_does_not_advance():
    client = _client()
    client.execute.side_effect = [
        _page([{"id": "1"}], True, "same"),
        _page([{"id": "2"}], True, "same"),
    ]

    pages = list(client.paginate("query", {"after": None}, connection_key="things"))

    assert pages == [[{"id": "1"}], [{"id": "2"}]]
    assert client.execute.call_count == 2
    assert client._logger.warning.call_args[0][1]["reason"] == "repeated"


def test_paginate_stays_quiet_on_a_normal_end_of_pagination():
    """A clean end of data must not look like a truncated run."""
    client = _client()
    client.execute.side_effect = [_page([{"id": "1"}], False, None)]

    list(client.paginate("query", {"after": None}, connection_key="things"))

    assert not client._logger.warning.called

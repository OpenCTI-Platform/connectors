"""Tests for the Wiz GraphQL client: date format, pagination and queries."""

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import pytest
from pydantic import ValidationError
from wiz_client.client_api import WizApiClient, _utc
from wiz_client.models import WizIssue, WizVulnerabilityFinding


def _client() -> WizApiClient:
    """Build a client that does not make network calls.

    Returns:
        A client where _execute() and the logger are MagicMocks.
    """
    client = WizApiClient.__new__(WizApiClient)
    client._execute = MagicMock()
    client._logger = MagicMock()
    return client


def _page(
    nodes: list[dict], has_next: bool, cursor: str | None, key: str = "things"
) -> dict:
    return {
        key: {
            "nodes": nodes,
            "pageInfo": {"hasNextPage": has_next, "endCursor": cursor},
        }
    }


def _variables(client: WizApiClient, call: int = 0) -> dict:
    """Return the GraphQL variables sent by an _execute() call (the first by default)."""
    return client._execute.call_args_list[call][0][1]


# -- cursor formatting ------------------------------------------------------


class TestCursorFormatting:
    def test_keeps_microseconds(self):
        # Wiz createdAt carries microseconds and the filter is exclusive, so
        # truncating to the second re-selects the issue the cursor points at.
        dt = datetime(2025, 2, 20, 13, 27, 49, 464786, tzinfo=timezone.utc)
        assert _utc(dt) == "2025-02-20T13:27:49.464786Z"

    def test_converts_to_utc(self):
        dt = datetime(2025, 2, 20, 15, 27, 49, 1, tzinfo=timezone(timedelta(hours=2)))
        assert _utc(dt) == "2025-02-20T13:27:49.000001Z"

    def test_whole_second_has_no_fraction(self):
        dt = datetime(2025, 2, 20, 13, 27, 49, tzinfo=timezone.utc)
        assert _utc(dt) == "2025-02-20T13:27:49Z"


# -- pagination ---------------------------------------------------------------


def test_paginate_walks_pages_until_has_next_page_is_false():
    client = _client()
    client._execute.side_effect = [
        _page([{"id": "1"}], True, "cursor-1"),
        _page([{"id": "2"}], False, None),
    ]

    pages = list(client._paginate("query", {"after": None}, connection_key="things"))

    assert pages == [[{"id": "1"}], [{"id": "2"}]]
    assert _variables(client, 1)["after"] == "cursor-1"


def test_paginate_stops_when_the_cursor_is_missing():
    client = _client()
    client._execute.side_effect = [_page([{"id": "1"}], True, None)]

    pages = list(client._paginate("query", {"after": None}, connection_key="things"))

    assert pages == [[{"id": "1"}]]
    assert client._execute.call_count == 1
    assert client._logger.warning.called


def test_paginate_reports_a_missing_cursor_as_such():
    """The warning must say why pagination stopped, not just that it did."""
    client = _client()
    client._execute.side_effect = [_page([{"id": "1"}], True, None)]

    list(client._paginate("query", {"after": None}, connection_key="things"))

    meta = client._logger.warning.call_args[0][1]
    assert meta["reason"] == "missing"
    assert meta["connection"] == "things"


def test_paginate_stops_when_the_cursor_does_not_advance():
    client = _client()
    client._execute.side_effect = [
        _page([{"id": "1"}], True, "same"),
        _page([{"id": "2"}], True, "same"),
    ]

    pages = list(client._paginate("query", {"after": None}, connection_key="things"))

    assert pages == [[{"id": "1"}], [{"id": "2"}]]
    assert client._execute.call_count == 2
    assert client._logger.warning.call_args[0][1]["reason"] == "repeated"


def test_paginate_stays_quiet_on_a_normal_end_of_pagination():
    """A clean end of data must not look like a truncated run."""
    client = _client()
    client._execute.side_effect = [_page([{"id": "1"}], False, None)]

    list(client._paginate("query", {"after": None}, connection_key="things"))

    assert not client._logger.warning.called


# -- issues query -----------------------------------------------------------


class TestPaginateIssues:
    SINCE = datetime(2026, 8, 1, 12, 0, 0, 123456, tzinfo=timezone.utc)

    def _run(self, client: WizApiClient) -> list:
        return list(
            client.paginate_issues(
                first=50,
                type=["THREAT_DETECTION"],
                severity=["CRITICAL", "HIGH"],
                status=["OPEN"],
                created_after=self.SINCE,
            )
        )

    def test_yields_parsed_issues(self, signin_issue_data):
        client = _client()
        client._execute.side_effect = [
            _page([signin_issue_data], False, None, key="issues")
        ]

        pages = self._run(client)

        assert len(pages) == 1
        assert isinstance(pages[0][0], WizIssue)
        assert pages[0][0].id == signin_issue_data["id"]

    def test_sends_the_issues_query(self):
        client = _client()
        client._execute.side_effect = [_page([], False, None, key="issues")]

        self._run(client)

        query = client._execute.call_args_list[0][0][0]
        assert "issues: issuesV2(" in query

    def test_filters_threat_detections_created_after_the_cursor(self):
        client = _client()
        client._execute.side_effect = [_page([], False, None, key="issues")]

        self._run(client)

        variables = _variables(client)
        assert variables["first"] == 50
        assert variables["orderBy"] == {"field": "CREATED_AT", "direction": "ASC"}
        assert variables["filterBy"] == {
            "type": ["THREAT_DETECTION"],
            "severity": ["CRITICAL", "HIGH"],
            "status": ["OPEN"],
            "createdAt": {"after": "2026-08-01T12:00:00.123456Z"},
        }

    def test_leaves_empty_filters_out(self):
        client = _client()
        client._execute.side_effect = [_page([], False, None, key="issues")]

        list(client.paginate_issues(first=50, severity=[], status=None))

        assert _variables(client)["filterBy"] == {}

    def test_raises_on_an_issue_that_does_not_parse(self):
        # On purpose: the run stops and the cursor is not updated.
        client = _client()
        client._execute.side_effect = [
            _page([{"id": "broken"}], False, None, key="issues")
        ]

        with pytest.raises(ValidationError):
            self._run(client)


# -- vulnerability findings query -------------------------------------------


class TestPaginateVulnerabilities:
    def _run(self, client: WizApiClient, **kwargs) -> list:
        params = {
            "first": 50,
            "severity": ["CRITICAL", "HIGH"],
            "status": ["OPEN", "IN_PROGRESS"],
            "asset_id": "asset-1",
        }
        params.update(kwargs)
        return list(client.paginate_vulnerabilities_findings(**params))

    def test_yields_parsed_findings(self, vulnerability_finding_data):
        client = _client()
        client._execute.side_effect = [
            _page(
                [vulnerability_finding_data], False, None, key="vulnerabilityFindings"
            )
        ]

        pages = self._run(client)

        assert isinstance(pages[0][0], WizVulnerabilityFinding)
        assert pages[0][0].name == "CVE-2026-46333"

    def test_sends_the_vulnerability_findings_query(self):
        client = _client()
        client._execute.side_effect = [
            _page([], False, None, key="vulnerabilityFindings")
        ]

        self._run(client)

        query = client._execute.call_args_list[0][0][0]
        assert "vulnerabilityFindings(" in query

    def test_queries_the_single_asset_of_the_issue(self):
        client = _client()
        client._execute.side_effect = [
            _page([], False, None, key="vulnerabilityFindings")
        ]

        self._run(client)

        filter_by = _variables(client)["filterBy"]
        assert filter_by["assetIdV2"] == {"equals": ["asset-1"]}
        assert filter_by["severity"] == ["CRITICAL", "HIGH"]
        assert filter_by["status"] == ["OPEN", "IN_PROGRESS"]

    def test_leaves_empty_filters_out(self):
        client = _client()
        client._execute.side_effect = [
            _page([], False, None, key="vulnerabilityFindings")
        ]

        list(client.paginate_vulnerabilities_findings(first=50))

        assert _variables(client)["filterBy"] == {}

    def test_leaves_the_exploit_filter_out_when_none(self):
        client = _client()
        client._execute.side_effect = [
            _page([], False, None, key="vulnerabilityFindings")
        ]

        self._run(client, has_exploit=None)

        assert "hasExploit" not in _variables(client)["filterBy"]

    @pytest.mark.parametrize("has_exploit", [True, False])
    def test_sends_the_exploit_filter_as_given(self, has_exploit):
        client = _client()
        client._execute.side_effect = [
            _page([], False, None, key="vulnerabilityFindings")
        ]

        self._run(client, has_exploit=has_exploit)

        assert _variables(client)["filterBy"]["hasExploit"] is has_exploit

    def test_raises_on_a_finding_that_does_not_parse(self):
        client = _client()
        client._execute.side_effect = [
            _page([{"id": "broken"}], False, None, key="vulnerabilityFindings")
        ]

        with pytest.raises(ValidationError):
            self._run(client)

"""Tests for the ORKL API client."""

from unittest.mock import MagicMock

import pytest
from connectors_sdk import ApiClientError
from orkl.client_api import (
    BACKOFF_FACTOR,
    MAX_PAGES,
    MAX_RETRIES,
    PAGE_SIZE,
    RATE_LIMIT,
    TIMEOUT,
    OrklClient,
)


@pytest.fixture
def client():
    """Create a client with default configuration and a mocked session."""
    return OrklClient("https://orkl.eu/api/v1")


@pytest.fixture
def client_with_mocked_get(client):
    """Same client, but with `_get` replaced by a MagicMock."""
    client._get = MagicMock()
    return client


class TestConfiguration:
    """Tests that ORKL-specific defaults land correctly on the instance."""

    def test_defaults_applied(self, client):
        assert client._raise_on_limit_exceeded is False
        assert client._max_retries == MAX_RETRIES
        assert client._backoff_factor == BACKOFF_FACTOR
        assert client._timeout == TIMEOUT
        assert client._rate_limit == RATE_LIMIT

    def test_defaults_can_be_overridden(self):
        client = OrklClient(
            "https://orkl.eu/api/v1",
            raise_on_limit_exceeded=True,
            max_retries=1,
            backoff_factor=0.5,
            timeout=10,
            rate_limit="5/minute",
        )
        assert client._raise_on_limit_exceeded is True
        assert client._max_retries == 1
        assert client._backoff_factor == 0.5
        assert client._timeout == 10
        assert client._rate_limit == "5/minute"


class TestSessionHeaders:
    """Tests for the client's static session headers."""

    def test_user_agent_present_and_descriptive(self, client):
        headers = client.session_headers
        assert "User-Agent" in headers
        assert headers["User-Agent"]
        assert "ORKL" in headers["User-Agent"]

    def test_no_authorization_header(self, client):
        headers = client.session_headers
        assert "Authorization" not in headers


class TestParseResponse:
    """Tests for envelope unwrapping via `_parse_response`."""

    def _fake_response(self, payload):
        response = MagicMock()
        response.headers = {"Content-Type": "application/json"}
        response.json.return_value = payload
        return response

    def test_unwraps_success_envelope(self, client, entries_page_data):
        response = self._fake_response(
            {
                "data": entries_page_data,
                "message": "library entries",
                "status": "success",
            }
        )
        result = client._parse_response(response)
        assert result == entries_page_data

    def test_null_data_returns_none(self, client, library_entries_empty_response):
        response = self._fake_response(library_entries_empty_response)
        result = client._parse_response(response)
        assert result is None

    def test_non_success_status_raises(self, client):
        envelope = {"data": None, "message": "entry not found", "status": "error"}
        response = self._fake_response(envelope)
        response.status_code = 200
        with pytest.raises(ApiClientError) as exc_info:
            client._parse_response(response)
        assert "entry not found" in str(exc_info.value)
        assert exc_info.value.response_body == envelope
        assert exc_info.value.status_code == 200

    def test_non_enveloped_dict_returned_unchanged(self, client):
        response = self._fake_response({"foo": "bar"})
        result = client._parse_response(response)
        assert result == {"foo": "bar"}


class TestIterLibraryEntries:
    """Tests for the `iter_library_entries` pagination generator."""

    def test_envelope_unwrapping_via_real_fixture(
        self, client_with_mocked_get, entries_page_data
    ):
        """Drive the generator end-to-end using the real page fixture data.

        `_get` already returns unwrapped data (envelope handling is done in
        `_parse_response`, tested separately above), so this exercises the
        pagination logic against realistic entry shapes.
        """
        client_with_mocked_get._get.side_effect = [entries_page_data]
        pages = list(client_with_mocked_get.iter_library_entries(page_size=100))
        assert len(pages) == 1
        assert pages[0] == entries_page_data

    def test_null_data_yields_no_pages(self, client_with_mocked_get):
        client_with_mocked_get._get.return_value = None
        pages = list(client_with_mocked_get.iter_library_entries())
        assert pages == []

    def test_empty_list_yields_no_pages(self, client_with_mocked_get):
        client_with_mocked_get._get.return_value = []
        pages = list(client_with_mocked_get.iter_library_entries())
        assert pages == []

    def test_pagination_two_pages(self, client_with_mocked_get):
        full_page = [{"id": str(i), "updated_at": "2026-01-01"} for i in range(100)]
        short_page = [{"id": "100", "updated_at": "2026-01-01"}]
        client_with_mocked_get._get.side_effect = [full_page, short_page]

        pages = list(client_with_mocked_get.iter_library_entries())

        assert len(pages) == 2
        assert pages[0] == full_page
        assert pages[1] == short_page
        assert client_with_mocked_get._get.call_count == 2

        first_call = client_with_mocked_get._get.call_args_list[0]
        second_call = client_with_mocked_get._get.call_args_list[1]
        assert first_call.args[0] == "/library/entries"
        assert first_call.kwargs["params"] == {
            "limit": 100,
            "offset": 0,
            "order_by": "created_at",
            "order": "asc",
        }
        assert second_call.kwargs["params"] == {
            "limit": 100,
            "offset": 100,
            "order_by": "created_at",
            "order": "asc",
        }

    def test_short_first_page_terminates_without_second_request(
        self, client_with_mocked_get
    ):
        short_page = [{"id": "1"}]
        client_with_mocked_get._get.return_value = short_page

        pages = list(client_with_mocked_get.iter_library_entries())

        assert pages == [short_page]
        client_with_mocked_get._get.assert_called_once()

    def test_lazy_generator_only_fetches_consumed_pages(self, client_with_mocked_get):
        full_page = [{"id": str(i)} for i in range(100)]
        second_page = [{"id": "100"}]
        client_with_mocked_get._get.side_effect = [full_page, second_page]

        gen = client_with_mocked_get.iter_library_entries()
        first = next(gen)

        assert first == full_page
        client_with_mocked_get._get.assert_called_once()

    def test_offset_advances_by_actual_entries_returned(self, client_with_mocked_get):
        short_full_page = [{"id": str(i)} for i in range(37)]
        # 37 < page_size(50) so this should already be the last page,
        # confirming offset would have advanced by 37 had it continued.
        client_with_mocked_get._get.return_value = short_full_page

        list(client_with_mocked_get.iter_library_entries(page_size=50))

        call = client_with_mocked_get._get.call_args_list[0]
        assert call.kwargs["params"]["offset"] == 0

    def test_offset_advances_across_pages_by_actual_count(self, client_with_mocked_get):
        page_one = [{"id": str(i)} for i in range(10)]
        page_two = [{"id": str(i)} for i in range(5)]
        client_with_mocked_get._get.side_effect = [page_one, page_two]

        list(client_with_mocked_get.iter_library_entries(page_size=10))

        second_call = client_with_mocked_get._get.call_args_list[1]
        assert second_call.kwargs["params"]["offset"] == 10

    @pytest.mark.parametrize(
        "requested,expected",
        [(0, 1), (-5, 1), (150, 100), (100, 100), (1, 1)],
    )
    def test_page_size_is_clamped(self, client_with_mocked_get, requested, expected):
        client_with_mocked_get._get.return_value = []
        list(client_with_mocked_get.iter_library_entries(page_size=requested))
        call = client_with_mocked_get._get.call_args_list[0]
        assert call.kwargs["params"]["limit"] == expected


class TestIterLibraryEntriesGuards:
    """Tests for the pagination self-defence guards (MAX_PAGES + stall)."""

    def test_full_pages_forever_terminate_at_max_pages_cap(
        self, client_with_mocked_get
    ):
        """A server that always serves a full, ever-changing page (e.g.
        ignoring `offset` but not stalling on identical ids -- simulated
        here by giving every page unique ids derived from a call counter)
        must still be bounded by MAX_PAGES rather than looping forever.
        """
        call_counter = {"n": 0}

        def fake_get(path, params=None, **kwargs):
            n = call_counter["n"]
            call_counter["n"] += 1
            return [{"id": f"{n}-{i}"} for i in range(100)]

        client_with_mocked_get._get.side_effect = fake_get

        pages = list(client_with_mocked_get.iter_library_entries(page_size=100))

        assert len(pages) == MAX_PAGES
        assert client_with_mocked_get._get.call_count == MAX_PAGES

    def test_stalled_identical_page_stops_pagination(self, client_with_mocked_get):
        """If the server returns the exact same entry ids on consecutive
        pages, `offset` is clearly not being honoured, and pagination must
        stop rather than loop on the same page forever.
        """
        stalled_page = [{"id": str(i)} for i in range(100)]
        client_with_mocked_get._get.return_value = stalled_page

        pages = list(client_with_mocked_get.iter_library_entries(page_size=100))

        # First occurrence is legitimately yielded; the repeat is detected
        # and stops the generator before a third request is even made.
        assert len(pages) == 1
        assert pages[0] == stalled_page
        assert client_with_mocked_get._get.call_count == 2

    def test_legitimate_full_backfill_under_cap_yields_every_page(
        self, client_with_mocked_get
    ):
        """Regression guard: a normal multi-page backfill, well under
        MAX_PAGES and with unique ids per page, must still yield every
        page -- the new guards must not truncate a real run.
        """
        num_full_pages = 5
        pages_data = [
            [{"id": f"p{page}-{i}"} for i in range(100)]
            for page in range(num_full_pages)
        ]
        last_short_page = [{"id": "final"}]
        client_with_mocked_get._get.side_effect = pages_data + [last_short_page]

        pages = list(client_with_mocked_get.iter_library_entries(page_size=100))

        assert len(pages) == num_full_pages + 1
        assert pages[:-1] == pages_data
        assert pages[-1] == last_short_page
        assert client_with_mocked_get._get.call_count == num_full_pages + 1


class TestGetLibraryEntry:
    """Tests for the single-entry lookup helper."""

    def test_calls_correct_endpoint(self, client_with_mocked_get):
        client_with_mocked_get._get.return_value = {"id": "abc"}
        result = client_with_mocked_get.get_library_entry("abc")
        client_with_mocked_get._get.assert_called_once_with("/library/entry/abc")
        assert result == {"id": "abc"}


class TestGetLibraryVersion:
    def test_returns_integer_id(self, client_with_mocked_get):
        client_with_mocked_get._get.return_value = {
            "ID": 589,
            "date": "2026-10-23T02:29:15Z",
        }
        assert client_with_mocked_get.get_library_version() == 589
        client_with_mocked_get._get.assert_called_once_with("/library/version")

    @pytest.mark.parametrize("payload", [None, {}, {"ID": "589"}, {"ID": None}])
    def test_missing_or_non_integer_id_raises(self, client_with_mocked_get, payload):
        client_with_mocked_get._get.return_value = payload
        with pytest.raises(ApiClientError):
            client_with_mocked_get.get_library_version()


class TestIterLibraryVersionsSince:
    """The version log is read newest first and stops at the known version."""

    @staticmethod
    def _versions(ids):
        return {"entries": [{"ID": i, "created_library_entries": []} for i in ids]}

    def test_yields_only_versions_newer_than_given(self, client_with_mocked_get):
        client_with_mocked_get._get.return_value = self._versions([12, 11, 9, 7])
        got = list(client_with_mocked_get.iter_library_versions_since(9))
        assert [v["ID"] for v in got] == [12, 11]
        call = client_with_mocked_get._get.call_args
        assert call.args[0] == "/library/version/entries"
        assert call.kwargs["params"] == {
            "limit": PAGE_SIZE,
            "offset": 0,
            "order": "desc",
        }

    def test_stops_at_version_ids_that_are_not_contiguous(self, client_with_mocked_get):
        # Version 10 does not exist upstream; 9 is the first id <= 10.
        client_with_mocked_get._get.return_value = self._versions([12, 11, 9, 7])
        got = list(client_with_mocked_get.iter_library_versions_since(10))
        assert [v["ID"] for v in got] == [12, 11]

    def test_nothing_new_yields_nothing(self, client_with_mocked_get):
        client_with_mocked_get._get.return_value = self._versions([12, 11])
        assert list(client_with_mocked_get.iter_library_versions_since(12)) == []

    @pytest.mark.parametrize("payload", [None, {}, {"entries": None}, {"entries": []}])
    def test_empty_log_yields_nothing(self, client_with_mocked_get, payload):
        client_with_mocked_get._get.return_value = payload
        assert list(client_with_mocked_get.iter_library_versions_since(0)) == []

    def test_paginates_until_known_version(self, client_with_mocked_get):
        first = self._versions(range(300, 300 - PAGE_SIZE, -1))
        second = self._versions([199, 198, 150])
        client_with_mocked_get._get.side_effect = [first, second]
        got = list(client_with_mocked_get.iter_library_versions_since(198))
        assert len(got) == PAGE_SIZE + 1
        assert got[-1]["ID"] == 199
        second_call = client_with_mocked_get._get.call_args_list[1]
        assert second_call.kwargs["params"]["offset"] == PAGE_SIZE

    def test_short_page_ends_the_walk_without_another_request(
        self, client_with_mocked_get
    ):
        client_with_mocked_get._get.return_value = self._versions([12, 11])
        list(client_with_mocked_get.iter_library_versions_since(0))
        assert client_with_mocked_get._get.call_count == 1

    def test_real_fixture_shape(
        self, client_with_mocked_get, library_versions_page_response
    ):
        client_with_mocked_get._get.return_value = library_versions_page_response[
            "data"
        ]
        got = list(client_with_mocked_get.iter_library_versions_since(7))
        assert [v["ID"] for v in got] == [12, 11, 9]
        assert got[2]["created_library_entries"] is None

    def test_hitting_the_page_cap_raises_instead_of_truncating(
        self, client_with_mocked_get, monkeypatch
    ):
        import orkl.client_api as client_api

        monkeypatch.setattr(client_api, "MAX_PAGES", 2)
        client_with_mocked_get._get.return_value = self._versions(
            range(1000, 1000 - PAGE_SIZE, -1)
        )
        with pytest.raises(ApiClientError):
            list(client_with_mocked_get.iter_library_versions_since(0))
        assert client_with_mocked_get._get.call_count == 2

    def test_version_without_integer_id_stops_with_warning(
        self, client_with_mocked_get
    ):
        client_with_mocked_get._get.return_value = {
            "entries": [
                {"ID": 12, "created_library_entries": []},
                {"ID": "oops", "created_library_entries": []},
                {"ID": 11, "created_library_entries": []},
            ]
        }
        client_with_mocked_get.logger = MagicMock()
        got = list(client_with_mocked_get.iter_library_versions_since(0))
        assert [v["ID"] for v in got] == [12]
        client_with_mocked_get.logger.warning.assert_called_once()

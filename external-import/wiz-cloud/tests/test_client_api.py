"""Tests for the Wiz GraphQL client: OAuth2 token, error handling, pagination.

No network: requests.post (token endpoint) and the SDK transport are patched.
"""

from unittest.mock import MagicMock, patch

import pytest
from connectors_sdk import BaseClientApi
from wiz_cloud.client_api import WizApiClient, WizGraphQLError

AUTH_URL = "https://auth.example.com/oauth/token"


@pytest.fixture
def client() -> WizApiClient:
    return WizApiClient(
        base_url="https://api.example.com/graphql",
        auth_url=AUTH_URL,
        client_id="id",
        client_secret="secret",
    )


def _token_response(token="tok", expires_in=86400) -> MagicMock:
    response = MagicMock()
    response.json.return_value = {"access_token": token, "expires_in": expires_in}
    return response


class TestAccessToken:
    def test_requests_a_token_with_client_credentials(self, client):
        with patch(
            "wiz_cloud.client_api.requests.post", return_value=_token_response()
        ) as post:
            assert client._access_token() == "tok"

        assert post.call_args.args == (AUTH_URL,)
        assert post.call_args.kwargs["data"] == {
            "grant_type": "client_credentials",
            "client_id": "id",
            "client_secret": "secret",
            "audience": "wiz-api",
        }
        post.return_value.raise_for_status.assert_called_once()

    def test_reuses_a_valid_token(self, client):
        with patch(
            "wiz_cloud.client_api.requests.post", return_value=_token_response()
        ) as post:
            client._access_token()
            client._access_token()

        assert post.call_count == 1

    def test_refreshes_an_expired_token(self, client):
        with patch(
            "wiz_cloud.client_api.requests.post",
            side_effect=[_token_response("old", 0), _token_response("new")],
        ) as post:
            assert client._access_token() == "old"
            # expires_in=0 minus the one minute margin is already in the past.
            assert client._access_token() == "new"

        assert post.call_count == 2


class TestRawRequest:
    def test_injects_bearer_token_and_keeps_caller_headers(self, client):
        with (
            patch.object(client, "_access_token", return_value="tok"),
            patch.object(BaseClientApi, "_raw_request") as parent,
        ):
            client._raw_request("POST", "", headers={"X-Test": "1"}, json={})

        parent.assert_called_once_with(
            "POST", "", headers={"X-Test": "1", "Authorization": "Bearer tok"}, json={}
        )

    def test_works_without_caller_headers(self, client):
        with (
            patch.object(client, "_access_token", return_value="tok"),
            patch.object(BaseClientApi, "_raw_request") as parent,
        ):
            client._raw_request("POST", "")

        assert parent.call_args.kwargs["headers"] == {"Authorization": "Bearer tok"}


class TestExecute:
    def test_returns_the_data_object(self, client):
        with patch.object(client, "_post", return_value={"data": {"issues": {}}}):
            assert client.execute("query", {"first": 1}) == {"issues": {}}

    def test_posts_query_and_variables(self, client):
        with patch.object(client, "_post", return_value={"data": {}}) as post:
            client.execute("query", {"first": 1})

        post.assert_called_once_with(
            "", json={"query": "query", "variables": {"first": 1}}
        )

    def test_raises_on_graphql_errors(self, client):
        payload = {"errors": [{"message": "boom"}], "data": None}
        with patch.object(client, "_post", return_value=payload):
            with pytest.raises(WizGraphQLError, match="boom"):
                client.execute("query", {})

    def test_raises_when_data_is_missing(self, client):
        with patch.object(client, "_post", return_value={"data": None}):
            with pytest.raises(WizGraphQLError, match="no data"):
                client.execute("query", {})


class TestPaginate:
    @staticmethod
    def _page(nodes, end_cursor=None):
        return {
            "issues": {
                "nodes": nodes,
                "pageInfo": {
                    "hasNextPage": end_cursor is not None,
                    "endCursor": end_cursor,
                },
            }
        }

    def test_follows_the_cursor_until_the_last_page(self, client):
        pages = iter([self._page([{"id": 1}], "c1"), self._page([{"id": 2}])])
        cursors = []

        def execute(query, variables):
            # The variables dict is reused across calls, so snapshot the cursor.
            cursors.append(variables["after"])
            return next(pages)

        with patch.object(client, "execute", side_effect=execute):
            result = list(client.paginate("query", {"after": None}, "issues"))

        assert result == [[{"id": 1}], [{"id": 2}]]
        assert cursors == [None, "c1"]

    def test_does_not_mutate_the_caller_variables(self, client):
        variables = {"after": None}
        pages = [self._page([{"id": 1}], "c1"), self._page([{"id": 2}])]
        with patch.object(client, "execute", side_effect=pages):
            list(client.paginate("query", variables, "issues"))

        assert variables == {"after": None}

    def test_skips_empty_pages(self, client):
        pages = [self._page([], "c1"), self._page(None)]
        with patch.object(client, "execute", side_effect=pages):
            assert list(client.paginate("query", {}, "issues")) == []

    def test_tolerates_a_missing_page_info(self, client):
        with patch.object(
            client, "execute", return_value={"issues": {"nodes": [{"id": 1}]}}
        ):
            assert list(client.paginate("query", {}, "issues")) == [[{"id": 1}]]

from __future__ import annotations

import hashlib
from unittest.mock import MagicMock, patch

import pytest
import requests
from connectors_sdk import ApiClientError
from cortex_xdr_client import CortexXdrApiError
from cortex_xdr_client.client import CortexXdrClient
from pydantic import HttpUrl


def _mock_response(
    status_code: int = 200,
    json_data=None,
    text: str = "",
    content_type: str | None = "application/json",
):
    resp = MagicMock(spec=requests.Response)
    resp.status_code = status_code
    resp.ok = 200 <= status_code < 400
    resp.json.return_value = json_data
    resp.text = text
    headers = {}
    if content_type:
        headers["Content-Type"] = content_type
    resp.headers = headers
    resp.content = (text or "").encode()
    return resp


@pytest.fixture
def client():
    return CortexXdrClient(
        HttpUrl("https://api-test.com"),
        "test-api-key-id",
        "test-api-key",
    )


class TestInit:
    def test_init_stores_credentials_and_base_url(self, client):
        # Given: a CortexXdrClient built from an HttpUrl and credentials
        # When: accessing its attributes
        # Then: the base URL is converted to str and credentials are stored as-is
        assert client._base_url == "https://api-test.com"
        assert client._api_key_id == "test-api-key-id"
        assert client._api_key == "test-api-key"

    def test_session_has_json_content_type_and_accept_headers(self, client):
        # Given: a CortexXdrClient
        # When: accessing the underlying session's headers
        # Then: 'Content-Type' and 'Accept' are both set to 'application/json'
        assert client._session.headers["Content-Type"] == "application/json"
        assert client._session.headers["Accept"] == "application/json"
        # And: authentication headers are not included (per request; not per session)
        assert "x-xdr-timestamp" not in client._session.headers
        assert "x-xdr-nonce" not in client._session.headers
        assert "x-xdr-auth-id" not in client._session.headers
        assert "Authorization" not in client._session.headers


class TestBuildAuthHeaders:
    def test_headers_contain_expected_keys(self, client):
        # Given: a client with credentials
        # When: building the Advanced auth headers
        headers = client._build_auth_headers()
        # Then: all 4 expected headers are present and auth-id matches the key id
        assert set(headers.keys()) == {
            "x-xdr-timestamp",
            "x-xdr-nonce",
            "x-xdr-auth-id",
            "Authorization",
        }
        assert headers["x-xdr-auth-id"] == "test-api-key-id"

    def test_nonce_is_64_char_alphanumeric(self, client):
        # Given: a client
        # When: building the Advanced auth headers
        headers = client._build_auth_headers()
        # Then: the nonce is a 64-char alphanumeric string
        nonce = headers["x-xdr-nonce"]
        assert len(nonce) == 64
        assert nonce.isalnum()

    def test_authorization_is_sha256_of_key_nonce_timestamp(self, client):
        # Given: a client
        # When: building the Advanced auth headers
        headers = client._build_auth_headers()
        # Then: Authorization is the sha256 hash of api_key + nonce + timestamp
        nonce = headers["x-xdr-nonce"]
        timestamp = headers["x-xdr-timestamp"]
        expected = hashlib.sha256(
            f"{client._api_key}{nonce}{timestamp}".encode("utf-8")
        ).hexdigest()
        assert headers["Authorization"] == expected

    def test_nonce_and_hash_differ_between_calls(self, client):
        # Given: a client
        # When: building the Advanced auth headers twice in a row
        first = client._build_auth_headers()
        second = client._build_auth_headers()
        # Then: the nonce and resulting hash differ, preventing replay
        assert first["x-xdr-nonce"] != second["x-xdr-nonce"]
        assert first["Authorization"] != second["Authorization"]


class TestInsertIocs:
    def test_insert_iocs_defaults_optional_fields_to_none(self, client):
        # Given: an IOC with only the required fields (indicator, type)
        ioc = {"indicator": "virus1.exe", "type": "FILENAME"}
        # When: calling insert_iocs
        with patch.object(client._session, "request") as mock_request:
            mock_request.return_value = _mock_response(
                json_data={"added_objects": [{"id": 123, "status": "Created"}]}
            )
            result = client.insert_iocs([ioc])
        # Then: a POST is issued to the insert endpoint with all optional fields
        # explicitly defaulted to null, and expiration disabled by default
        args, kwargs = mock_request.call_args
        assert args[0] == "POST"
        assert args[1].endswith("/public_api/v1/indicators/insert")
        assert kwargs["json"] == {
            "request_data": [
                {
                    "indicator": "virus1.exe",
                    "type": "FILENAME",
                    "severity": None,
                    "expiration_date": None,
                    "default_expiration_enabled": True,
                    "comment": None,
                    "reputation": None,
                    "reliability": None,
                }
            ]
        }
        assert result == {"added_objects": [{"id": 123, "status": "Created"}]}

    def test_insert_iocs_disables_default_expiration_when_expiration_date_set(
        self, client
    ):
        # Given: an IOC with an explicit expiration date and full optional fields
        ioc = {
            "indicator": "1.2.3.4",
            "type": "IP",
            "severity": "SEV_040_HIGH",
            "expiration_date": 1893456000000,
            "comment": "malicious",
            "reputation": "BAD",
            "reliability": "A",
        }
        # When: calling insert_iocs
        with patch.object(client._session, "request") as mock_request:
            mock_request.return_value = _mock_response(
                json_data={"added_objects": [{"id": 123, "status": "Created"}]}
            )
            client.insert_iocs([ioc])
        # Then: default_expiration_enabled is False and all other fields are
        # carried over unmodified
        _, kwargs = mock_request.call_args
        sent_ioc = kwargs["json"]["request_data"][0]
        assert sent_ioc["expiration_date"] == 1893456000000
        assert sent_ioc["default_expiration_enabled"] is False
        assert sent_ioc["severity"] == "SEV_040_HIGH"
        assert sent_ioc["comment"] == "malicious"
        assert sent_ioc["reputation"] == "BAD"
        assert sent_ioc["reliability"] == "A"

    def test_insert_iocs_posts_request_data_for_multiple_iocs(self, client):
        # Given: several IOC payloads
        iocs = [
            {"indicator": "virus1.exe", "type": "FILENAME"},
            {"indicator": "1.2.3.4", "type": "IP", "severity": "SEV_040_HIGH"},
        ]
        # When: calling insert_iocs with the whole batch
        with patch.object(client._session, "request") as mock_request:
            mock_request.return_value = _mock_response(
                json_data={
                    "added_objects": [
                        {"id": 123, "status": "Created"},
                        {"id": 124, "status": "Created"},
                    ]
                }
            )
            result = client.insert_iocs(iocs)
        # Then: a single POST is issued carrying both fully-defaulted payloads
        _, kwargs = mock_request.call_args
        assert kwargs["json"]["request_data"] == [
            {
                "indicator": "virus1.exe",
                "type": "FILENAME",
                "severity": None,
                "expiration_date": None,
                "default_expiration_enabled": True,
                "comment": None,
                "reputation": None,
                "reliability": None,
            },
            {
                "indicator": "1.2.3.4",
                "type": "IP",
                "severity": "SEV_040_HIGH",
                "expiration_date": None,
                "default_expiration_enabled": True,
                "comment": None,
                "reputation": None,
                "reliability": None,
            },
        ]
        assert len(result["added_objects"]) == 2

    def test_insert_iocs_sends_fresh_auth_headers(self, client):
        # Given: a client
        # When: calling insert_iocs
        with patch.object(client._session, "request") as mock_request:
            mock_request.return_value = _mock_response(
                json_data={"added_objects": [{"id": 123, "status": "Created"}]}
            )
            client.insert_iocs([{"indicator": "virus1.exe", "type": "FILENAME"}])
        # Then: the request carries the Advanced auth headers
        _, kwargs = mock_request.call_args
        assert "x-xdr-auth-id" in kwargs["headers"]
        assert "x-xdr-nonce" in kwargs["headers"]
        assert "x-xdr-timestamp" in kwargs["headers"]
        assert "Authorization" in kwargs["headers"]

    def test_insert_iocs_includes_rule_id_when_provided(self, client):
        # Given: an IOC carrying an existing `rule_id` (i.e. it already
        # exists on Cortex XDR and is being updated, not created)
        ioc = {"indicator": "1.2.3.4", "type": "IP", "rule_id": 42}
        # When: calling insert_iocs
        with patch.object(client._session, "request") as mock_request:
            mock_request.return_value = _mock_response(
                json_data={"updated_objects": [{"id": 42, "status": "Updated"}]}
            )
            client.insert_iocs([ioc])
        # Then: "rule_id" is included in the sent payload so Cortex XDR
        # overwrites the existing IOC instead of failing
        _, kwargs = mock_request.call_args
        assert kwargs["json"]["request_data"][0]["rule_id"] == 42

    def test_insert_iocs_omits_rule_id_when_not_provided(self, client):
        # Given: an IOC without a `rule_id` (i.e. a new IOC being created)
        ioc = {"indicator": "virus1.exe", "type": "FILENAME"}
        # When: calling insert_iocs
        with patch.object(client._session, "request") as mock_request:
            mock_request.return_value = _mock_response(
                json_data={"added_objects": [{"id": 123, "status": "Created"}]}
            )
            client.insert_iocs([ioc])
        # Then: no "rule_id" key is sent at all
        _, kwargs = mock_request.call_args
        assert "rule_id" not in kwargs["json"]["request_data"][0]


class TestGetIocs:
    def test_posts_request_data_with_given_filters(self, client):
        # Given: a fully specified filter
        # When: calling get_iocs
        with patch.object(client._session, "request") as mock_request:
            mock_request.return_value = _mock_response(
                json_data={"objects_count": 0, "objects": []}
            )
            result = client.get_iocs(
                [{"field": "indicator", "operator": "IN", "value": ["evil.com"]}]
            )
        # Then: a POST is issued to the get endpoint carrying the given filter as-is
        args, kwargs = mock_request.call_args
        assert args[0] == "POST"
        assert args[1].endswith("/public_api/v1/indicators/get")
        assert kwargs["json"] == {
            "request_data": {
                "filters": [
                    {
                        "field": "indicator",
                        "operator": "IN",
                        "value": ["evil.com"],
                    }
                ]
            }
        }
        assert result == {"objects_count": 0, "objects": []}

    def test_defaults_field_to_indicator(self, client):
        # Given: a filter without a "field" key
        # When: calling get_iocs
        with patch.object(client._session, "request") as mock_request:
            mock_request.return_value = _mock_response(
                json_data={"objects_count": 0, "objects": []}
            )
            client.get_iocs([{"operator": "EQ", "value": "evil.com"}])
        # Then: "field" defaults to "indicator"
        _, kwargs = mock_request.call_args
        assert kwargs["json"]["request_data"]["filters"][0]["field"] == "indicator"

    def test_sends_none_when_operator_missing(self, client):
        # Given: a filter without an "operator" key
        # When: calling get_iocs
        with patch.object(client._session, "request") as mock_request:
            mock_request.return_value = _mock_response(
                json_data={"objects_count": 0, "objects": []}
            )
            client.get_iocs([{"value": "evil.com"}])
        # Then: "operator" is sent as null rather than raising
        _, kwargs = mock_request.call_args
        assert kwargs["json"]["request_data"]["filters"][0]["operator"] is None

    def test_sends_none_when_value_missing(self, client):
        # Given: a filter without a "value" key
        # When: calling get_iocs
        with patch.object(client._session, "request") as mock_request:
            mock_request.return_value = _mock_response(
                json_data={"objects_count": 0, "objects": []}
            )
            client.get_iocs([{"operator": "EQ"}])
        # Then: "value" is sent as null rather than raising
        _, kwargs = mock_request.call_args
        assert kwargs["json"]["request_data"]["filters"][0]["value"] is None

    def test_returns_parsed_response_with_matching_objects(self, client):
        # Given: existing IOCs matching the queried indicator values
        with patch.object(client._session, "request") as mock_request:
            mock_request.return_value = _mock_response(
                json_data={
                    "objects_count": 1,
                    "objects": [
                        {
                            "rule_id": 42,
                            "indicator": "evil.com",
                            "type": "DOMAIN_NAME",
                            "severity": "SEV_040_HIGH",
                            "expiration_date": -1,
                            "comment": None,
                        }
                    ],
                }
            )
            # When: calling get_iocs
            result = client.get_iocs(
                [{"field": "indicator", "operator": "IN", "value": ["evil.com"]}]
            )
        # Then: the parsed response, including `rule_id`, is returned as-is
        assert result["objects"][0]["rule_id"] == 42

    def test_sends_fresh_auth_headers(self, client):
        # Given: a client
        # When: calling get_iocs
        with patch.object(client._session, "request") as mock_request:
            mock_request.return_value = _mock_response(
                json_data={"objects_count": 0, "objects": []}
            )
            client.get_iocs(
                [{"field": "indicator", "operator": "IN", "value": ["evil.com"]}]
            )
        # Then: the request carries the Advanced auth headers
        _, kwargs = mock_request.call_args
        assert "x-xdr-auth-id" in kwargs["headers"]
        assert "x-xdr-nonce" in kwargs["headers"]
        assert "x-xdr-timestamp" in kwargs["headers"]
        assert "Authorization" in kwargs["headers"]


class TestDeleteIocs:
    def test_delete_iocs_defaults_field_to_indicator(self, client):
        # Given: a filter with only the required "value" and "operator" fields
        # When: calling delete_iocs
        with patch.object(client._session, "request") as mock_request:
            mock_request.return_value = _mock_response(json_data={"objects_count": 1})
            result = client.delete_iocs([{"operator": "EQ", "value": "virus1.exe"}])
        # Then: a POST is issued to the delete endpoint with "field" defaulted
        # to "indicator"
        args, kwargs = mock_request.call_args
        assert args[0] == "POST"
        assert args[1].endswith("/public_api/v1/indicators/delete")
        assert kwargs["json"] == {
            "request_data": {
                "filters": [
                    {
                        "field": "indicator",
                        "operator": "EQ",
                        "value": "virus1.exe",
                    }
                ]
            }
        }
        assert result == {"objects_count": 1}

    def test_delete_iocs_sends_none_when_operator_missing(self, client):
        # Given: a filter without an "operator" key
        # When: calling delete_iocs
        with patch.object(client._session, "request") as mock_request:
            mock_request.return_value = _mock_response(json_data={"objects_count": 1})
            client.delete_iocs([{"value": "virus1.exe"}])
        # Then: "operator" is sent as null rather than raising
        _, kwargs = mock_request.call_args
        assert kwargs["json"]["request_data"]["filters"][0]["operator"] is None

    def test_delete_iocs_posts_request_data_for_multiple_filters(self, client):
        # Given: several filters, only specifying "value" and "operator"
        filters = [
            {"operator": "EQ", "value": "virus1.exe"},
            {"operator": "EQ", "value": "1.2.3.4"},
        ]
        # When: calling delete_iocs with the whole batch
        with patch.object(client._session, "request") as mock_request:
            mock_request.return_value = _mock_response(json_data={"objects_count": 2})
            result = client.delete_iocs(filters)
        # Then: a single POST is issued carrying both fully-defaulted filters
        _, kwargs = mock_request.call_args
        assert kwargs["json"] == {
            "request_data": {
                "filters": [
                    {"field": "indicator", "operator": "EQ", "value": "virus1.exe"},
                    {"field": "indicator", "operator": "EQ", "value": "1.2.3.4"},
                ]
            }
        }
        assert result == {"objects_count": 2}

    def test_delete_iocs_raises_when_value_missing(self, client):
        # Given: a filter without a "value" key
        # When: calling delete_iocs
        # Then: it fails fast rather than silently sending a null value
        with pytest.raises(KeyError):
            client.delete_iocs([{"operator": "EQ"}])

    def test_delete_iocs_sends_fresh_auth_headers(self, client):
        # Given: a client
        # When: calling delete_iocs
        with patch.object(client._session, "request") as mock_request:
            mock_request.return_value = _mock_response(json_data={"objects_count": 1})
            client.delete_iocs([{"value": "virus1.exe"}])
        # Then: the request carries the Advanced auth headers
        _, kwargs = mock_request.call_args
        assert "x-xdr-auth-id" in kwargs["headers"]
        assert "x-xdr-nonce" in kwargs["headers"]
        assert "x-xdr-timestamp" in kwargs["headers"]
        assert "Authorization" in kwargs["headers"]


class TestErrorPropagation:
    def test_unauthorized_response_raises_cortex_xdr_api_error(self, client):
        # Given: a 401 response from the API
        with patch.object(client._session, "request") as mock_request:
            mock_request.return_value = _mock_response(
                status_code=401, json_data={"message": "unauthorized"}
            )
            # When: calling insert_iocs
            # Then: a CortexXdrApiError is raised, wrapping the original ApiClientError
            with pytest.raises(CortexXdrApiError) as exc_info:
                client.insert_iocs([{"indicator": "virus1.exe", "type": "FILENAME"}])
            assert isinstance(exc_info.value.__cause__, ApiClientError)

    def test_get_iocs_raises_cortex_xdr_api_error(self, client):
        # Given: a 401 response from the API
        with patch.object(client._session, "request") as mock_request:
            mock_request.return_value = _mock_response(
                status_code=401, json_data={"message": "unauthorized"}
            )
            # When: calling get_iocs
            # Then: a CortexXdrApiError is raised, wrapping the original ApiClientError
            with pytest.raises(CortexXdrApiError) as exc_info:
                client.get_iocs(
                    [{"field": "indicator", "operator": "IN", "value": ["evil.com"]}]
                )
            assert isinstance(exc_info.value.__cause__, ApiClientError)

    def test_delete_iocs_raises_cortex_xdr_api_error(self, client):
        # Given: a 401 response from the API
        with patch.object(client._session, "request") as mock_request:
            mock_request.return_value = _mock_response(
                status_code=401, json_data={"message": "unauthorized"}
            )
            # When: calling delete_iocs
            # Then: a CortexXdrApiError is raised, wrapping the original ApiClientError
            with pytest.raises(CortexXdrApiError) as exc_info:
                client.delete_iocs([{"value": "virus1.exe"}])
            assert isinstance(exc_info.value.__cause__, ApiClientError)

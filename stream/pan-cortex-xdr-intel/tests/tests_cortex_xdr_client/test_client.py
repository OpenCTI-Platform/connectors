from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest
import requests
from connectors_sdk import ApiClientError
from cortex_xdr_client.client import CortexXdrClient
from cortex_xdr_client.exceptions import CortexXdrApiError, CortexXdrRequestBodyError
from pydantic import HttpUrl, ValidationError


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


class TestUpsertIndicator:
    def test_upsert_indicator_posts_request_data_with_all_fields_present(self, client):
        # Given: only the required fields (value, type)
        # When: calling upsert_indicator
        with patch.object(client._session, "request") as mock_request:
            mock_request.return_value = _mock_response(
                json_data={"added_objects": [{"id": 123, "status": "Created"}]}
            )
            result = client.upsert_indicator(value="virus1.exe", type="FILENAME")
        # Then: a POST is issued to the insert endpoint with a single-item array,
        # all optional fields explicitly present as null, and expiration disabled
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
                    "comment": None,
                    "reputation": None,
                    "reliability": None,
                    "default_expiration_enabled": True,
                }
            ]
        }
        assert result == {"added_objects": [{"id": 123, "status": "Created"}]}

    def test_upsert_indicator_with_expiration_serializes_timestamp_ms(self, client):
        # Given: an indicator with an explicit expiration date and full optional fields
        expiration = datetime(2030, 1, 1, tzinfo=timezone.utc)
        # When: calling upsert_indicator
        with patch.object(client._session, "request") as mock_request:
            mock_request.return_value = _mock_response(
                json_data={"added_objects": [{"id": 123, "status": "Created"}]}
            )
            client.upsert_indicator(
                value="1.2.3.4",
                type="IP",
                severity="SEV_040_HIGH",
                expiration=expiration,
                comment="malicious",
                reputation="BAD",
                reliability="A",
            )
        # Then: the expiration date is serialized as a Unix timestamp in milliseconds
        # and default_expiration_enabled is False
        _, kwargs = mock_request.call_args
        indicator = kwargs["json"]["request_data"][0]
        assert indicator["expiration_date"] == 1893456000000
        assert indicator["default_expiration_enabled"] is False
        assert indicator["severity"] == "SEV_040_HIGH"
        assert indicator["comment"] == "malicious"
        assert indicator["reputation"] == "BAD"
        assert indicator["reliability"] == "A"

    def test_upsert_indicator_sends_fresh_auth_headers(self, client):
        # Given: a client
        # When: calling upsert_indicator
        with patch.object(client._session, "request") as mock_request:
            mock_request.return_value = _mock_response(
                json_data={"added_objects": [{"id": 123, "status": "Created"}]}
            )
            client.upsert_indicator(value="virus1.exe", type="FILENAME")
        # Then: the request carries the Advanced auth headers
        _, kwargs = mock_request.call_args
        assert "x-xdr-auth-id" in kwargs["headers"]
        assert "x-xdr-nonce" in kwargs["headers"]
        assert "x-xdr-timestamp" in kwargs["headers"]
        assert "Authorization" in kwargs["headers"]


class TestDeleteIndicator:
    def test_delete_indicator_posts_request_data_filters(self, client):
        # Given: an indicator value to delete
        # When: calling delete_indicator
        with patch.object(client._session, "request") as mock_request:
            mock_request.return_value = _mock_response(json_data={"objects_count": 1})
            result = client.delete_indicator(value="virus1.exe")
        # Then: a POST is issued to the delete endpoint with the value wrapped in
        # an EQ filter on the "indicator" field
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

    def test_delete_indicator_sends_fresh_auth_headers(self, client):
        # Given: a client
        # When: calling delete_indicator
        with patch.object(client._session, "request") as mock_request:
            mock_request.return_value = _mock_response(json_data={"objects_count": 1})
            client.delete_indicator(value="virus1.exe")
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
            # When: calling upsert_indicator
            # Then: a CortexXdrApiError is raised, wrapping the original ApiClientError
            with pytest.raises(CortexXdrApiError) as exc_info:
                client.upsert_indicator(value="virus1.exe", type="FILENAME")
            assert isinstance(exc_info.value.__cause__, ApiClientError)

    def test_invalid_indicator_type_raises_cortex_xdr_request_body_error(self, client):
        # Given: an indicator type not part of the allowed literal values
        # When: calling upsert_indicator
        # Then: a CortexXdrRequestBodyError is raised, wrapping the ValidationError
        with pytest.raises(CortexXdrRequestBodyError) as exc_info:
            client.upsert_indicator(value="virus1.exe", type="NOT_A_VALID_TYPE")
        assert isinstance(exc_info.value.__cause__, ValidationError)

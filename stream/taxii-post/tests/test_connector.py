import json
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from pydantic import SecretStr
from taxii_post_connector.connector import (
    TaxiiPostConnector,
    accept_header_by_taxii_version,
    content_type_by_stix_version,
)

# --------------------------
# --- Scenario Functions ---
# --------------------------


# Scenario: If accept header is correct depending on taxii version
@pytest.mark.parametrize(
    "taxii_version, expected_result",
    [
        ("2.0.0", "application/vnd.oasis.taxii+json; version=2.0.0"),
        ("2.1.0", "application/taxii+json; version=2.1.0"),
        ("2.2.0", "application/taxii+json; version=2.2.0"),
    ],
)
def test_accept_header_by_taxii_version(taxii_version, expected_result):
    # When we call accept_header_by_taxii_version function
    result = accept_header_by_taxii_version(taxii_version)
    # Then the custom properties are correctly formatted
    assert result == expected_result


# Scenario: If content type is correct depending on stix version
@pytest.mark.parametrize(
    "stix_version, expected_result",
    [
        ("2.0.0", "application/vnd.oasis.stix+json; version=2.0.0"),
        ("2.1.0", "application/stix+json; version=2.1.0"),
        ("2.2.0", "application/stix+json; version=2.2.0"),
    ],
)
def test_content_type_by_stix_version(stix_version, expected_result):
    # When we call content_type_by_stix_version function
    result = content_type_by_stix_version(stix_version)
    # Then the custom properties are correctly formatted
    assert result == expected_result


# -----------------------------------------
# --- Auth Selection in _process_message ---
# -----------------------------------------

STIX_OBJECT = {
    "id": "indicator--fa42a846-8d90-4e51-bc29-71d5b4802168",
    "type": "indicator",
    "extensions": {},
}


def _make_stream_msg():
    return SimpleNamespace(
        data=json.dumps({"data": STIX_OBJECT.copy()}),
    )


def _make_taxii_config(**overrides):
    """Build a minimal TaxiiConfig-like namespace for the connector."""
    defaults = dict(
        url="https://taxii.example.com",
        ssl_verify=False,
        api_root="root",
        collection_id="col-1",
        token=None,
        login=SecretStr("user"),
        password=SecretStr("pass"),
        version="2.1",
        stix_version="2.1",
        delete_created_by_ref=True,
        delete_marking_definition=True,
    )
    defaults.update(overrides)
    return SimpleNamespace(**defaults)


def _make_connector(taxii_config):
    """Build a TaxiiPostConnector with a mocked helper and the given taxii config."""
    settings = MagicMock()
    settings.taxii = taxii_config
    helper = MagicMock()
    return TaxiiPostConnector(settings, helper)


@patch("taxii_post_connector.connector.requests.post")
def test_empty_token_falls_back_to_basic_auth(mock_post):
    """When token is an empty SecretStr, basic auth should be used."""
    mock_post.return_value = MagicMock(status_code=200, content=b"ok")
    connector = _make_connector(_make_taxii_config(token=SecretStr("")))

    connector._process_message(_make_stream_msg())

    mock_post.assert_called_once()
    call_kwargs = mock_post.call_args
    assert "auth" in call_kwargs.kwargs, "Expected basic auth, got token auth"
    assert "Authorization" not in call_kwargs.kwargs.get("headers", {})


@patch("taxii_post_connector.connector.requests.post")
def test_none_token_uses_basic_auth(mock_post):
    """When token is None, basic auth should be used."""
    mock_post.return_value = MagicMock(status_code=200, content=b"ok")
    connector = _make_connector(_make_taxii_config(token=None))

    connector._process_message(_make_stream_msg())

    mock_post.assert_called_once()
    call_kwargs = mock_post.call_args
    assert "auth" in call_kwargs.kwargs, "Expected basic auth, got token auth"
    assert "Authorization" not in call_kwargs.kwargs.get("headers", {})


@patch("taxii_post_connector.connector.requests.post")
def test_valid_token_uses_bearer_auth(mock_post):
    """When token has a real value, Bearer auth should be used."""
    mock_post.return_value = MagicMock(status_code=200, content=b"ok")
    connector = _make_connector(_make_taxii_config(token=SecretStr("my-secret-token")))

    connector._process_message(_make_stream_msg())

    mock_post.assert_called_once()
    call_kwargs = mock_post.call_args
    headers = call_kwargs.kwargs.get("headers", {})
    assert headers.get("Authorization") == "Bearer my-secret-token"
    assert "auth" not in call_kwargs.kwargs

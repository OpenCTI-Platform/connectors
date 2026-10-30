import json
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from pydantic import SecretStr
from taxii_post_connector.connector import (
    TaxiiPostConnector,
    accept_header_by_taxii_version,
    content_type_by_stix_version,
    remap_identity_ids,
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
        login="user",
        password=SecretStr("pass"),
        version="2.1",
        stix_version="2.1",
        delete_created_by_ref=True,
        delete_marking_definition=True,
        identity_id_mapping={},
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


# ----------------------------
# --- Identity ID remapping --
# ----------------------------


ORIGINAL_ID_1 = "identity--00000000-0000-4000-8000-000000000011"
REPLACEMENT_ID_1 = "identity--00000000-0000-4000-8000-000000000021"
ORIGINAL_ID_2 = "identity--00000000-0000-4000-8000-000000000012"
REPLACEMENT_ID_2 = "identity--00000000-0000-4000-8000-000000000022"
IDENTITY_ID_MAPPING = {ORIGINAL_ID_1: REPLACEMENT_ID_1, ORIGINAL_ID_2: REPLACEMENT_ID_2}

OTHER_ID = "identity--00000000-0000-4000-8000-000000000099"


def test_remap_identity_ids_rewrites_own_id():
    """A parsed identity object with an id as an original in the mapping should have its own id replaced"""

    stix_object = {"id": ORIGINAL_ID_1, "type": "identity", "name": "testidentity"}
    remap_identity_ids(stix_object, IDENTITY_ID_MAPPING)

    assert stix_object == {
        "id": REPLACEMENT_ID_1,
        "type": "identity",
        "name": "testidentity",
    }


def test_remap_identity_ids_rewrites_refs():
    """
    An object who has one of the original identity ids in either their single or list reference properties
    has them correctly mapped to the replacement ids
    """

    stix_object = {
        "id": "sighting--1c68244b-3ec9-4eea-aded-808bbdec7836",
        "type": "sighting",
        # set each of these fields to the original id, and one to a generic id not to be mapped
        "created_by_ref": ORIGINAL_ID_1,
        "sighting_of_ref": ORIGINAL_ID_2,
        "where_sighted_refs": [ORIGINAL_ID_1, OTHER_ID, ORIGINAL_ID_2],
        "object_marking_refs": ["marking-definition--abc"],
    }

    remap_identity_ids(stix_object, IDENTITY_ID_MAPPING)

    assert stix_object == {
        "id": "sighting--1c68244b-3ec9-4eea-aded-808bbdec7836",
        "type": "sighting",
        # each original id should be mapped, and the other id should remain
        "created_by_ref": REPLACEMENT_ID_1,
        "sighting_of_ref": REPLACEMENT_ID_2,
        "where_sighted_refs": [REPLACEMENT_ID_1, OTHER_ID, REPLACEMENT_ID_2],
        "object_marking_refs": ["marking-definition--abc"],
    }


def test_remap_identity_ids_rewrites_relationship_refs():
    """A relationship between two identities with original ids has both both sides replaced"""

    stix_object = {
        "id": "relationship--1c68244b-3ec9-4eea-aded-808bbdec7836",
        "type": "relationship",
        "relationship_type": "related-to",
        "source_ref": ORIGINAL_ID_1,
        "target_ref": ORIGINAL_ID_2,
    }

    remap_identity_ids(stix_object, IDENTITY_ID_MAPPING)

    assert stix_object["source_ref"] == REPLACEMENT_ID_1
    assert stix_object["target_ref"] == REPLACEMENT_ID_2


def test_remap_identity_ids_rewrites_object_refs():
    """A report referencing an original id has that id replaced"""

    indicator_id = "indicator--00000000-0000-4000-8000-000000000001"
    stix_object = {
        "id": "report--1c68244b-3ec9-4eea-aded-808bbdec7836",
        "type": "report",
        "object_refs": [ORIGINAL_ID_1, indicator_id, OTHER_ID],
    }

    remap_identity_ids(stix_object, IDENTITY_ID_MAPPING)

    assert stix_object["object_refs"] == [REPLACEMENT_ID_1, indicator_id, OTHER_ID]


def _post_through_connector(stix_object, identity_id_mapping):
    """
    Process a stream message with the given object and mapping and returns what gets
    posted to the TAXII Server
    """

    connector = _make_connector(
        _make_taxii_config(identity_id_mapping=identity_id_mapping)
    )
    with patch("taxii_post_connector.connector.requests.post") as mock_post:
        mock_post.return_value = MagicMock(status_code=200, content=b"ok")
        connector._process_message(
            SimpleNamespace(data=json.dumps({"data": stix_object}))
        )

    mock_post.assert_called_once()
    (posted_object,) = mock_post.call_args.kwargs["json"]["objects"]
    return posted_object


def test_process_message_posts_remapped_identity_ids():
    """The object posted to the TAXII server correctly contains the remapped identity"""
    sighting = {
        "id": "sighting--1c68244b-3ec9-4eea-aded-808bbdec7836",
        "type": "sighting",
        "sighting_of_ref": "indicator--00000000-0000-4000-8000-000000000001",
        "where_sighted_refs": [ORIGINAL_ID_1],
        "extensions": {},
    }
    posted_object = _post_through_connector(sighting, IDENTITY_ID_MAPPING)

    assert posted_object["where_sighted_refs"] == [REPLACEMENT_ID_1]


def test_process_message_posts_remapped_identity_own_id():
    """An identity with the original id has its own id replaced"""
    identity = {"id": ORIGINAL_ID_1, "type": "identity", "name": "testidentity"}
    posted_object = _post_through_connector(identity, IDENTITY_ID_MAPPING)
    assert posted_object["id"] == REPLACEMENT_ID_1


def test_process_message_without_mapping_posts_ids_unchanged():
    """When no mapping is configured the identity persists"""
    identity = {"id": ORIGINAL_ID_1, "type": "identity", "name": "testidentity"}
    posted_object = _post_through_connector(identity, {})
    assert posted_object["id"] == ORIGINAL_ID_1

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from taxii_post_connector.connector import (
    TaxiiPostConnector,
    accept_header_by_taxii_version,
    content_type_by_stix_version,
)
from taxii_post_connector.settings import TaxiiConfig


def make_connector(**taxii_overrides):
    """
    Build a `TaxiiPostConnector` with a real `TaxiiConfig` (so configuration
    behaves exactly like in production) and a mocked helper, for unit testing
    the object transformation logic without any network or OpenCTI access.
    """
    taxii_config = {
        "url": "http://test.com",
        "collection_id": "collection-id",
        **taxii_overrides,
    }
    config = SimpleNamespace(taxii=TaxiiConfig(**taxii_config))
    return TaxiiPostConnector(config=config, helper=MagicMock())


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


# Scenario: identity objects must not be posted when created_by_ref is stripped
def test_prepare_object_skips_identity_when_delete_created_by_ref_enabled():
    # Given a connector configured to strip created_by_ref
    connector = make_connector(delete_created_by_ref=True)
    identity = {"id": "identity--1", "type": "identity", "name": "ACME"}
    # When we prepare an identity object
    result = connector._prepare_object(identity)
    # Then it is skipped (not posted) since its created_by_ref attribution is removed
    assert result is None


# Scenario: identity objects are kept when created_by_ref is not stripped
def test_prepare_object_keeps_identity_when_delete_created_by_ref_disabled():
    # Given a connector configured to keep created_by_ref
    connector = make_connector(delete_created_by_ref=False)
    identity = {"id": "identity--1", "type": "identity", "name": "ACME"}
    # When we prepare an identity object
    result = connector._prepare_object(identity)
    # Then it is still posted
    assert result is not None
    assert result["id"] == "identity--1"


# Scenario: non-identity objects are always posted, with created_by_ref stripped
def test_prepare_object_keeps_non_identity_and_strips_created_by_ref():
    # Given a connector configured to strip created_by_ref
    connector = make_connector(delete_created_by_ref=True)
    indicator = {
        "id": "indicator--1",
        "type": "indicator",
        "created_by_ref": "identity--1",
    }
    # When we prepare a non-identity object
    result = connector._prepare_object(indicator)
    # Then it is posted with the created_by_ref attribution removed
    assert result is not None
    assert result["id"] == "indicator--1"
    assert "created_by_ref" not in result

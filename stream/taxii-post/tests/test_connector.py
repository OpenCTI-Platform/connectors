import pytest
from taxii_post_connector.connector import (
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

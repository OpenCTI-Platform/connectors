"""Tests for `enisa_euvd.models` -- validating raw EUVD API payloads."""

from datetime import datetime, timezone

import pytest
from enisa_euvd.models import EUVDVulnerability
from pydantic import ValidationError


def test_vulnerability_parses_a_full_item(single_vulnerability):
    vuln = EUVDVulnerability.model_validate(single_vulnerability)

    assert vuln.id == "EUVD-2024-00001"
    assert vuln.description.startswith("Example Reflected Cross-Site Scripting")
    assert vuln.date_published == datetime(2024, 1, 10, 9, 0, 0, tzinfo=timezone.utc)
    assert vuln.date_updated == datetime(2024, 1, 15, 15, 30, 0, tzinfo=timezone.utc)
    assert vuln.base_score == 5.9
    assert vuln.base_score_version == "4.0"
    assert vuln.base_score_vector.startswith("CVSS:4.0/")
    assert vuln.epss == 0.02
    assert vuln.references == [
        "https://example-vendor.example/advisories/example-1",
        "https://cve-database.example/vuln/detail/CVE-2024-00001",
    ]
    assert vuln.aliases == ["CVE-2024-00001", "GHSA-aaaa-bbbb-cccc"]
    assert len(vuln.products) == 1
    assert vuln.products[0].product.name == "Example Admin Panel"
    assert vuln.products[0].product.vendor.name == "Example Vendor"
    assert vuln.products[0].product_version == "1.2.3"


def test_vulnerability_handles_missing_products_and_null_lists(search_page):
    item = search_page["items"][2]  # CVSS v2 item with empty product/vendor lists
    vuln = EUVDVulnerability.model_validate(item)

    assert vuln.products == []
    assert vuln.base_score_version == "2.0"


def test_vulnerability_coalesces_null_references_and_aliases_to_empty_lists():
    raw = {
        "id": "EUVD-2024-99999",
        "description": "Minimal item with null references/aliases.",
        "datePublished": "Jan 1, 2024, 12:00:00 AM",
        "dateUpdated": "Jan 1, 2024, 12:00:00 AM",
        "references": None,
        "aliases": None,
    }
    vuln = EUVDVulnerability.model_validate(raw)

    assert vuln.references == []
    assert vuln.aliases == []
    assert vuln.products == []
    assert vuln.base_score is None
    assert vuln.epss is None


def test_vulnerability_requires_id_and_description():
    with pytest.raises(ValidationError):
        EUVDVulnerability.model_validate(
            {
                "datePublished": "Jan 1, 2024, 12:00:00 AM",
                "dateUpdated": "Jan 1, 2024, 12:00:00 AM",
            }
        )


@pytest.mark.parametrize(
    "search_index,expected_version",
    [(0, "4.0"), (1, "3.1"), (2, "2.0")],
)
def test_vulnerability_parses_every_cvss_version(
    search_page, search_index, expected_version
):
    vuln = EUVDVulnerability.model_validate(search_page["items"][search_index])
    assert vuln.base_score_version == expected_version

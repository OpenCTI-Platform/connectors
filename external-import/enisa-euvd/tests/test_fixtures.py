"""Tests validating the shape of the anonymised fixtures in `tests/resources/`.

These fixtures mirror the real `/search` endpoint response shape (verified
against the live ENISA EUVD API), with every value replaced by fake data.
"""

from typing import Any


def test_search_page_has_items_and_total(search_page: dict[str, Any]):
    assert "items" in search_page
    assert "total" in search_page
    assert isinstance(search_page["items"], list)
    assert len(search_page["items"]) == search_page["total"]


def test_search_page_covers_every_cvss_version(search_page: dict[str, Any]):
    """The fixture must cover CVSS v2, v3 and v4 so model routing can be tested."""
    versions = {item["baseScoreVersion"] for item in search_page["items"]}
    assert versions == {"2.0", "3.1", "4.0"}


def test_search_page_covers_item_without_products(search_page: dict[str, Any]):
    """At least one item has no `enisaIdProduct`/`enisaIdVendor` (optional software mapping)."""
    assert any(
        not item["enisaIdProduct"] and not item["enisaIdVendor"]
        for item in search_page["items"]
    )


def test_search_page_empty_has_no_items(search_page_empty: dict[str, Any]):
    assert search_page_empty == {"items": [], "total": 0}


def test_single_vulnerability_matches_a_search_page_item(
    single_vulnerability: dict[str, Any], search_page: dict[str, Any]
):
    assert single_vulnerability["id"] == search_page["items"][0]["id"]


def test_fixtures_contain_no_real_looking_identifiers(search_page: dict[str, Any]):
    """Every id/uuid in the fixture is an obviously-fake placeholder, never a real one."""
    for item in search_page["items"]:
        assert item["id"].startswith("EUVD-2024-0000")
        assert item["enisaUuid"].startswith("00000000-0000-0000-0000-0000000000")
        for product_ref in item["enisaIdProduct"]:
            assert product_ref["id"].startswith("10000000-0000-0000-0000-0000000000")
        for vendor_ref in item["enisaIdVendor"]:
            assert vendor_ref["id"].startswith("20000000-0000-0000-0000-0000000000")

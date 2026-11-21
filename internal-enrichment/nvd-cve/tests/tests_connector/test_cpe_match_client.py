from unittest.mock import AsyncMock, MagicMock

from src.services.client.cpe_match import CPEMatchClient


def test_extract_cpe_names_ignores_criteria_patterns():
    data = {
        "matchStrings": [
            {
                "matchString": {
                    "criteria": "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
                    "matches": [],
                }
            }
        ]
    }
    cpe_names: set[str] = set()

    CPEMatchClient._extract_cpe_names(data, cpe_names)

    assert cpe_names == set()


def test_extract_cpe_names_filters_invalid_values():
    valid_cpe = "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*"
    data = {
        "matchStrings": [
            {
                "matchString": {
                    "matches": [
                        {"cpeName": None},
                        {"cpeName": ""},
                        {"cpeName": "   "},
                        {"cpeName": 123},
                        {},
                        {"cpeName": valid_cpe},
                    ]
                }
            }
        ]
    }
    cpe_names: set[str] = set()

    CPEMatchClient._extract_cpe_names(data, cpe_names)

    assert cpe_names == {valid_cpe}


async def test_get_cpes_for_cve_stops_when_initial_results_per_page_is_zero():
    valid_cpe = "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*"
    first_page = {
        "totalResults": 10,
        "resultsPerPage": 0,
        "matchStrings": [{"matchString": {"matches": [{"cpeName": valid_cpe}]}}],
    }

    client = CPEMatchClient.__new__(CPEMatchClient)
    client.helper = MagicMock()
    client.helper.connector_logger = MagicMock()
    client.get_complete_collection = AsyncMock(return_value=first_page)

    result = await client.get_cpes_for_cve("CVE-2024-0001")

    assert result == [valid_cpe]
    assert client.get_complete_collection.await_count == 1


async def test_get_cpes_for_cve_stops_when_paginated_results_per_page_is_zero():
    cpe1 = "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*"
    cpe2 = "cpe:2.3:a:vendor:product:2.0:*:*:*:*:*:*:*"
    first_page = {
        "totalResults": 4,
        "resultsPerPage": 2,
        "matchStrings": [{"matchString": {"matches": [{"cpeName": cpe1}]}}],
    }
    second_page = {
        "totalResults": 4,
        "resultsPerPage": 0,
        "matchStrings": [{"matchString": {"matches": [{"cpeName": cpe2}]}}],
    }

    client = CPEMatchClient.__new__(CPEMatchClient)
    client.helper = MagicMock()
    client.helper.connector_logger = MagicMock()
    client.get_complete_collection = AsyncMock(side_effect=[first_page, second_page])

    result = await client.get_cpes_for_cve("CVE-2024-0002")

    assert set(result) == {cpe1, cpe2}
    assert client.get_complete_collection.await_count == 2

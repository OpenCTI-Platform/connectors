"""IP resolutions (IP -> resolved domains) unit tests."""

import json
import os
import re
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest
import stix2
from pycti import StixCoreRelationship
from pydantic import ValidationError
from tests_virustotal.test_virustotal import _make_connector
from virustotal.client import VirusTotalClient
from virustotal.models.configs.virustotal_configs import (
    ConfigLoaderVirusTotal,
    resolve_since_floor,
)
from virustotal.processors import IPProcessor

IP = "138.128.150.133"
IP_ID = stix2.IPv4Address(value=IP).id
# 2025-10-01T00:00:00Z
FLOOR_TS = int(datetime(2025, 10, 1, tzinfo=timezone.utc).timestamp())
DAY = 86400


def _load_ip_report() -> dict:
    path = os.path.join(os.path.dirname(__file__), "resources", "vt_test_ipv4.json")
    with open(path, encoding="utf-8") as file:
        return json.load(file)


def _resolution(host_name: str, date: int) -> dict:
    return {
        "type": "resolution",
        "id": f"{IP}{host_name}",
        "attributes": {
            "host_name": host_name,
            "ip_address": IP,
            "date": date,
            "resolver": "VirusTotal",
        },
    }


def _page(resolutions: list[dict], cursor: str | None = None) -> dict:
    return {"data": resolutions, "meta": {"cursor": cursor} if cursor else {}}


# Three pages, newest first, all after the floor.
THREE_PAGES = [
    _page(
        [
            _resolution("news-one.example", FLOOR_TS + 30 * DAY),
            _resolution("shop.example", FLOOR_TS + 29 * DAY),
        ],
        "c1",
    ),
    _page(
        [
            _resolution("daily-two.example", FLOOR_TS + 20 * DAY),
            _resolution("blog.example", FLOOR_TS + 19 * DAY),
        ],
        "c2",
    ),
    _page([_resolution("press-three.example", FLOOR_TS + 10 * DAY)]),
]


def _make_processor(
    pages: list, is_indicator: bool = False, **settings
) -> tuple[IPProcessor, MagicMock]:
    connector = _make_connector()
    connector.ip_add_resolutions = True
    connector.ip_resolutions_since = "none"
    connector.api_requests_per_minute = 0
    for key, value in settings.items():
        setattr(connector, key, value)
    connector.client.get_ip_info.return_value = _load_ip_report()
    connector.client.get_ip_resolutions_page.side_effect = pages
    helper = connector.helper
    helper.playbook = None
    helper.stix2_create_bundle.side_effect = list
    helper.send_stix2_bundle.return_value = ["bundle"]
    entity = {"entity_type": "IPv4-Addr", "observable_value": IP, "objectMarking": []}
    processor = IPProcessor(connector, [], {"id": IP_ID}, entity, is_indicator)
    return processor, helper


def _sent_bundles(helper: MagicMock) -> list[list]:
    return [c.args[0] for c in helper.send_stix2_bundle.call_args_list]


def _domains(objects: list) -> list[str]:
    return [o["value"] for o in objects if o["type"] == "domain-name"]


class TestResolveSinceFloor(unittest.TestCase):
    NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)

    def test_relative_days(self):
        self.assertEqual(
            resolve_since_floor("90d", self.NOW), self.NOW - timedelta(days=90)
        )

    def test_absolute_date(self):
        self.assertEqual(
            resolve_since_floor("2025-10-01", self.NOW),
            datetime(2025, 10, 1, tzinfo=timezone.utc),
        )

    def test_none_disables_floor(self):
        self.assertIsNone(resolve_since_floor("None", self.NOW))

    def test_invalid_value(self):
        for value in ["3w", "90", "2025/10/01", "yesterday"]:
            with self.assertRaises(ValueError):
                resolve_since_floor(value, self.NOW)


class TestResolutionsConfig(unittest.TestCase):
    def test_defaults_keep_feature_off(self):
        config = ConfigLoaderVirusTotal(token="fake-token")
        self.assertFalse(config.ip_add_resolutions)
        self.assertEqual(config.ip_resolutions_since, "90d")
        self.assertIsNone(config.ip_resolutions_max_entries)
        self.assertEqual(config.ip_resolutions_max_pages, 25)
        self.assertIsNone(config.ip_resolutions_keywords)
        self.assertEqual(config.api_requests_per_minute, 4)

    def test_invalid_since_rejected_at_start_up(self):
        with self.assertRaises(ValidationError):
            ConfigLoaderVirusTotal(token="fake-token", ip_resolutions_since="3 months")

    def test_invalid_keywords_rejected_at_start_up(self):
        with self.assertRaises(ValidationError):
            ConfigLoaderVirusTotal(token="fake-token", ip_resolutions_keywords="news(")

    def test_caps_must_be_positive(self):
        with self.assertRaises(ValidationError):
            ConfigLoaderVirusTotal(token="fake-token", ip_resolutions_max_pages=0)
        with self.assertRaises(ValidationError):
            ConfigLoaderVirusTotal(token="fake-token", ip_resolutions_max_entries=0)


class TestResolutionsClient(unittest.TestCase):
    def setUp(self):
        self.client = VirusTotalClient(
            MagicMock(), "https://www.virustotal.com/api/v3", "fake-api-key"
        )
        self.client._query = MagicMock(return_value={"data": []})

    def test_first_page_url(self):
        self.client.get_ip_resolutions_page(IP)
        self.client._query.assert_called_once_with(
            f"https://www.virustotal.com/api/v3/ip_addresses/{IP}/resolutions?limit=40"
        )

    def test_next_page_url_with_cursor_and_limit(self):
        self.client.get_ip_resolutions_page(IP, "abc=", 3)
        self.client._query.assert_called_once_with(
            f"https://www.virustotal.com/api/v3/ip_addresses/{IP}/resolutions"
            "?limit=3&cursor=abc%3D"
        )


class TestBuildResolvedDomains(unittest.TestCase):
    def setUp(self):
        processor, _ = _make_processor([])
        self.builder = processor._make_builder(_load_ip_report())
        self.author = processor.connector.author

    def test_domain_resolves_to_ip_with_last_seen_start_time(self):
        objects = self.builder.build_resolved_domains(
            [_resolution("news.example", FLOOR_TS)], None
        )
        domain, relationship = objects
        self.assertEqual(domain["type"], "domain-name")
        self.assertEqual(domain["value"], "news.example")
        self.assertEqual(domain["created_by_ref"], self.author.id)
        self.assertNotIn("x_opencti_score", domain)
        self.assertEqual(relationship["relationship_type"], "resolves-to")
        self.assertEqual(relationship["source_ref"], domain.id)
        self.assertEqual(relationship["target_ref"], IP_ID)
        self.assertEqual(
            relationship["start_time"], datetime(2025, 10, 1, tzinfo=timezone.utc)
        )
        self.assertEqual(
            relationship["description"],
            "VirusTotal resolution, last seen 2025-10-01T00:00:00Z",
        )

    def test_relationship_id_ignores_date(self):
        first = self.builder.build_resolved_domains(
            [_resolution("news.example", FLOOR_TS)], None
        )[1]
        later = self.builder.build_resolved_domains(
            [_resolution("news.example", FLOOR_TS + DAY)], None
        )[1]
        self.assertEqual(first.id, later.id)
        self.assertEqual(
            first.id,
            StixCoreRelationship.generate_id("resolves-to", first.source_ref, IP_ID),
        )

    def test_keywords_filter_case_insensitive(self):
        objects = self.builder.build_resolved_domains(
            [
                _resolution("NEWS.example", FLOOR_TS),
                _resolution("shop.example", FLOOR_TS),
            ],
            re.compile("news|press", re.IGNORECASE),
        )
        self.assertEqual(_domains(objects), ["NEWS.example"])


class TestIPResolutionsLoop(unittest.TestCase):
    def test_flag_off_makes_no_resolutions_call(self):
        processor, helper = _make_processor(THREE_PAGES, ip_add_resolutions=False)
        result = processor.process()
        processor.client.get_ip_info.assert_called_once_with(IP)
        processor.client.get_ip_resolutions_page.assert_not_called()
        self.assertEqual(helper.send_stix2_bundle.call_count, 1)
        self.assertEqual(result, "Sent 1 stix bundle(s) for worker import")

    def test_indicator_enrichment_makes_no_resolutions_call(self):
        processor, helper = _make_processor(THREE_PAGES, is_indicator=True)
        processor.process()
        processor.client.get_ip_resolutions_page.assert_not_called()
        self.assertEqual(helper.send_stix2_bundle.call_count, 1)

    def test_one_bundle_per_page_until_end_of_list(self):
        processor, helper = _make_processor(THREE_PAGES)
        result = processor.process()
        bundles = _sent_bundles(helper)
        # Main enrichment bundle first, then one bundle per page.
        self.assertEqual(len(bundles), 4)
        self.assertEqual(_domains(bundles[0]), [])
        self.assertEqual(_domains(bundles[1]), ["news-one.example", "shop.example"])
        self.assertEqual(_domains(bundles[2]), ["daily-two.example", "blog.example"])
        self.assertEqual(_domains(bundles[3]), ["press-three.example"])
        for bundle in bundles[1:]:
            self.assertEqual(bundle[0]["type"], "identity")
        self.assertEqual(
            [c.args[1] for c in processor.client.get_ip_resolutions_page.mock_calls],
            [None, "c1", "c2"],
        )
        self.assertTrue(
            result.endswith(
                "resolutions: kept 5 of 5 fetched (3 pages, stopped: end of list)"
            )
        )

    def test_keywords_filter_created_domains(self):
        processor, helper = _make_processor(
            THREE_PAGES,
            ip_resolutions_keywords=re.compile("news|daily|press", re.IGNORECASE),
        )
        result = processor.process()
        created = [d for b in _sent_bundles(helper)[1:] for d in _domains(b)]
        self.assertEqual(
            created, ["news-one.example", "daily-two.example", "press-three.example"]
        )
        self.assertIn("kept 3 of 5 fetched (3 pages", result)

    def test_stops_on_date_floor_mid_page(self):
        pages = [
            THREE_PAGES[0],
            _page(
                [
                    _resolution("daily-two.example", FLOOR_TS + DAY),
                    _resolution("old-one.example", FLOOR_TS - DAY),
                    _resolution("old-two.example", FLOOR_TS - 2 * DAY),
                ],
                "c2",
            ),
            THREE_PAGES[2],
        ]
        processor, helper = _make_processor(pages, ip_resolutions_since="2025-10-01")
        result = processor.process()
        created = [d for b in _sent_bundles(helper)[1:] for d in _domains(b)]
        self.assertNotIn("old-one.example", created)
        self.assertNotIn("old-two.example", created)
        self.assertEqual(processor.client.get_ip_resolutions_page.call_count, 2)
        self.assertTrue(
            result.endswith(
                "resolutions: kept 3 of 5 fetched (2 pages, stopped: date floor)"
            )
        )

    def test_resolution_on_floor_date_is_kept(self):
        pages = [_page([_resolution("edge.example", FLOOR_TS)])]
        processor, helper = _make_processor(pages, ip_resolutions_since="2025-10-01")
        processor.process()
        self.assertEqual(_domains(_sent_bundles(helper)[1]), ["edge.example"])

    def test_entry_cap_below_page_size_is_one_call(self):
        pages = [
            _page(
                [
                    _resolution("a.example", FLOOR_TS + 3 * DAY),
                    _resolution("b.example", FLOOR_TS + 2 * DAY),
                    _resolution("c.example", FLOOR_TS + DAY),
                ],
                "c1",
            )
        ]
        processor, helper = _make_processor(pages, ip_resolutions_max_entries=3)
        result = processor.process()
        processor.client.get_ip_resolutions_page.assert_called_once_with(IP, None, 3)
        self.assertEqual(
            _domains(_sent_bundles(helper)[1]), ["a.example", "b.example", "c.example"]
        )
        self.assertTrue(
            result.endswith(
                "resolutions: kept 3 of 3 fetched (1 pages, stopped: entry cap)"
            )
        )

    def test_entry_cap_counts_fetched_not_kept(self):
        processor, _ = _make_processor(
            THREE_PAGES,
            ip_resolutions_max_entries=3,
            ip_resolutions_keywords=re.compile("press"),
        )
        # The cap falls on the second page: 2 entries, then 1.
        processor.client.get_ip_resolutions_page.side_effect = [
            THREE_PAGES[0],
            _page([_resolution("daily-two.example", FLOOR_TS)], "c2"),
        ]
        result = processor.process()
        self.assertEqual(
            [c.args[2] for c in processor.client.get_ip_resolutions_page.mock_calls],
            [3, 1],
        )
        self.assertTrue(
            result.endswith(
                "resolutions: kept 0 of 3 fetched (2 pages, stopped: entry cap)"
            )
        )

    def test_stops_on_page_cap(self):
        processor, helper = _make_processor(THREE_PAGES, ip_resolutions_max_pages=2)
        result = processor.process()
        self.assertEqual(processor.client.get_ip_resolutions_page.call_count, 2)
        self.assertEqual(len(_sent_bundles(helper)), 3)
        self.assertTrue(
            result.endswith(
                "resolutions: kept 4 of 4 fetched (2 pages, stopped: page cap)"
            )
        )

    def test_failed_page_keeps_previous_pages(self):
        processor, helper = _make_processor([THREE_PAGES[0], None, THREE_PAGES[2]])
        result = processor.process()
        bundles = _sent_bundles(helper)
        self.assertEqual(len(bundles), 2)
        self.assertEqual(_domains(bundles[1]), ["news-one.example", "shop.example"])
        self.assertTrue(
            result.endswith(
                "resolutions: kept 2 of 2 fetched (1 pages, stopped: error)"
            )
        )
        helper.connector_logger.warning.assert_called_once()

    def test_error_payload_ends_loop(self):
        error_page = {"error": {"code": "QuotaExceededError", "message": "Quota"}}
        processor, _ = _make_processor([error_page])
        result = processor.process()
        self.assertTrue(result.endswith("(0 pages, stopped: error)"))

    @patch("virustotal.processors.ip_address.time.sleep")
    def test_requests_per_minute_spaces_pages(self, sleep: MagicMock):
        processor, _ = _make_processor(THREE_PAGES, api_requests_per_minute=4)
        processor.process()
        # No wait before the first page, 15 s before each next one.
        self.assertEqual([c.args[0] for c in sleep.call_args_list], [15.0, 15.0])

    @patch("virustotal.processors.ip_address.time.sleep")
    def test_zero_requests_per_minute_disables_wait(self, sleep: MagicMock):
        processor, _ = _make_processor(THREE_PAGES, api_requests_per_minute=0)
        processor.process()
        sleep.assert_not_called()

    def test_playbook_sends_a_single_bundle(self):
        processor, helper = _make_processor(THREE_PAGES)
        helper.playbook = {"playbook_id": "fake"}
        result = processor.process()
        bundles = _sent_bundles(helper)
        self.assertEqual(len(bundles), 1)
        self.assertEqual(
            _domains(bundles[0]),
            [
                "news-one.example",
                "shop.example",
                "daily-two.example",
                "blog.example",
                "press-three.example",
            ],
        )
        self.assertTrue(result.endswith("(3 pages, stopped: end of list)"))


if __name__ == "__main__":
    pytest.main([__file__])

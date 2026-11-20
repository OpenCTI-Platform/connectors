import random
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest
from src.connector import ConnectorAbuseIPDB

REPORTS = [
    {"reportedAt": "2024-03-10T12:00:00+00:00", "reporterCountryCode": "FR"},
    {"reportedAt": "2024-01-05T08:30:00+00:00", "reporterCountryCode": "FR"},
    {"reportedAt": "2024-06-20T23:59:59+00:00", "reporterCountryCode": "FR"},
    {"reportedAt": "2024-02-01T00:00:00+00:00", "reporterCountryCode": "US"},
    {"reportedAt": "2024-02-02T00:00:00+00:00", "reporterCountryCode": None},
]


def _run(reports):
    helper = MagicMock()
    helper.api.label.read_or_create_unchecked.return_value = {"value": "whitelist"}
    config = MagicMock()
    config.abuseipdb.max_tlp = "TLP:AMBER"
    connector = ConnectorAbuseIPDB(config, helper)

    response = MagicMock()
    response.json.return_value = {
        "data": {
            "isWhitelisted": False,
            "abuseConfidenceScore": 80,
            "reports": [dict(r, categories=[18]) for r in reports],
        }
    }
    data = {
        "enrichment_entity": {"objectMarking": [], "observable_value": "1.2.3.4"},
        "stix_objects": [],
        "stix_entity": {
            "id": "ipv4-addr--6c6b8b2a-2f4e-5f0a-9a3b-1b2c3d4e5f60",
            "value": "1.2.3.4",
        },
    }
    with patch("src.connector.abuseipdb.requests.get", return_value=response):
        connector._process_message(data)
    return {
        o.where_sighted_refs[0]: o
        for o in data["stix_objects"]
        if o.type == "sighting"
    }


@pytest.mark.parametrize("seed", range(5))
def test_sighting_dates_are_earliest_and_latest_whatever_the_order(seed):
    reports = list(REPORTS)
    random.Random(seed).shuffle(reports)
    sightings = _run(reports)
    reference = _run(REPORTS)

    assert len(sightings) == 2
    by_count = {s.count: s for s in sightings.values()}
    fr, us = by_count[3], by_count[1]
    assert fr.first_seen == datetime(2024, 1, 5, 8, 30, tzinfo=timezone.utc)
    assert fr.last_seen == datetime(2024, 6, 20, 23, 59, 59, tzinfo=timezone.utc)
    assert us.first_seen == us.last_seen == datetime(2024, 2, 1, tzinfo=timezone.utc)
    for ref, sighting in sightings.items():
        assert sighting.first_seen <= sighting.last_seen
        assert sighting.id == reference[ref].id

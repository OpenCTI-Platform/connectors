"""Unit tests for the handling of missing or invalid ransomware.live dates."""

from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest
from ransomwarelive.converter_to_stix import ConverterToStix
from ransomwarelive.ransom_conn import RansomwareAPIConnector
from ransomwarelive.utils import safe_datetime

# ---------------------------------------------------------------------------
# utils.safe_datetime
# ---------------------------------------------------------------------------


def test_safe_datetime_parses_valid_value():
    assert safe_datetime("2026-10-01T12:30:00+00:00") == datetime(
        2026, 10, 1, 12, 30, tzinfo=timezone.utc
    )


@pytest.mark.parametrize("value", [None, "", "invalid-date"])
def test_safe_datetime_returns_none_for_missing_or_invalid_value(value):
    assert safe_datetime(value) is None


# ---------------------------------------------------------------------------
# RansomwareAPIConnector.create_bundle_list
# ---------------------------------------------------------------------------


def _make_connector() -> RansomwareAPIConnector:
    """Build a connector that only creates the victim and the Report."""
    connector = RansomwareAPIConnector.__new__(RansomwareAPIConnector)
    connector.helper = MagicMock()
    connector.config = MagicMock()
    connector.config.ransomwarelive.create_threat_actor = False
    connector.config.ransomwarelive.create_intrusion_set = False
    connector.config.ransomwarelive.create_campaign = False
    connector.config.ransomwarelive.create_report = True
    connector.config.ransomwarelive.create_leak_post_refs = False
    connector.converter_to_stix = ConverterToStix("TLP:CLEAR")
    connector.author = connector.converter_to_stix.author
    connector.processed_groups = set()
    connector.country_cache = {}
    return connector


def _report(bundle_objects: list) -> dict:
    reports = [obj for obj in bundle_objects if obj and obj.get("type") == "report"]
    assert len(reports) == 1
    return reports[0]


def test_create_bundle_list_uses_discovered_date_when_attack_date_is_empty():
    connector = _make_connector()
    item = {
        "victim": "Acme Corp",
        "group": "acme-ransomware",
        "country": "",
        "activity": "",
        "domain": "",
        "attackdate": "",
        "discovered": "2026-10-02T08:00:00+00:00",
    }

    bundle_objects = connector.create_bundle_list(item, group_data=[])

    assert _report(bundle_objects)["published"] == datetime(
        2026, 10, 2, 8, 0, tzinfo=timezone.utc
    )


def test_create_bundle_list_keeps_attack_date_when_present():
    connector = _make_connector()
    item = {
        "victim": "Acme Corp",
        "group": "acme-ransomware",
        "country": "",
        "activity": "",
        "domain": "",
        "attackdate": "2026-09-30T00:00:00+00:00",
        "discovered": "2026-10-02T08:00:00+00:00",
    }

    bundle_objects = connector.create_bundle_list(item, group_data=[])

    assert _report(bundle_objects)["published"] == datetime(
        2026, 9, 30, tzinfo=timezone.utc
    )


# ---------------------------------------------------------------------------
# RansomwareAPIConnector.collect_intelligence
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("discovered", ["", None, "invalid-date"])
def test_collect_intelligence_skips_victim_with_invalid_discovered_date(discovered):
    connector = _make_connector()
    connector.last_run = None
    connector.last_run_datetime_with_ingested_data = None
    connector.api_client = MagicMock()
    connector.api_client.get_groups.return_value = [{"name": "acme-ransomware"}]
    connector.api_client.get_recent_victims.return_value = [
        {"victim": "Broken Corp", "discovered": discovered},
        {"victim": "Acme Corp", "discovered": "2026-10-02T08:00:00+00:00"},
    ]
    connector.create_bundle_list = MagicMock(return_value=[])

    connector.collect_intelligence()

    connector.helper.connector_logger.warning.assert_called_once_with(
        "Invalid discovered date, victim skipped",
        {"discovered": discovered, "victim": "Broken Corp"},
    )
    # Only the victim with a valid date is converted
    connector.create_bundle_list.assert_called_once()
    assert (
        connector.create_bundle_list.call_args.kwargs["item"]["victim"] == "Acme Corp"
    )


@pytest.mark.parametrize("discovered", ["", None, "invalid-date"])
def test_create_bundle_list_skips_report_when_no_date_is_available(discovered):
    connector = _make_connector()
    item = {
        "victim": "Acme Corp",
        "group": "acme-ransomware",
        "country": "",
        "activity": "",
        "domain": "",
        "attackdate": "",
        "discovered": discovered,
    }

    bundle_objects = connector.create_bundle_list(item, group_data=[])

    # The Report is skipped, the victim is still returned
    assert not [obj for obj in bundle_objects if obj and obj.get("type") == "report"]
    assert any(obj.get("name") == "Acme Corp" for obj in bundle_objects if obj)
    connector.helper.connector_logger.warning.assert_called_once_with(
        "Missing attack and discovered dates, report skipped",
        {"victim": "Acme Corp"},
    )


def test_collect_historic_intelligence_sends_victim_without_dates():
    connector = _make_connector()
    connector.config.ransomwarelive.history_start_year = 202610
    connector.api_client = MagicMock()
    connector.api_client.get_groups.return_value = [{"name": "acme-ransomware"}]
    connector.api_client.get_victims.return_value = [
        {
            "victim": "Acme Corp",
            "group": "acme-ransomware",
            "country": "",
            "activity": "",
            "domain": "",
            "attackdate": "",
            "discovered": "",
        }
    ]
    connector.helper.stix2_deduplicate_objects.side_effect = lambda objects: objects

    connector.collect_historic_intelligence()

    # The victim bundle is still created and sent, without a Report
    sent_objects = [
        obj
        for call in connector.helper.stix2_create_bundle.call_args_list
        for obj in call.args[0]
    ]
    assert any(obj.get("name") == "Acme Corp" for obj in sent_objects)
    assert not [obj for obj in sent_objects if obj.get("type") == "report"]
    assert connector.helper.send_stix2_bundle.called


def test_create_bundle_list_keeps_attack_date_unknown_outside_the_report():
    connector = _make_connector()
    connector.config.ransomwarelive.create_threat_actor = True
    item = {
        "victim": "Acme Corp",
        "group": "acme-ransomware",
        "country": "",
        "activity": "",
        "domain": "",
        "attackdate": "",
        "discovered": "2026-10-02T08:00:00+00:00",
    }

    bundle_objects = connector.create_bundle_list(item, group_data=[])

    # The disclosure date is only used as the Report published date
    assert _report(bundle_objects)["published"] == datetime(
        2026, 10, 2, 8, 0, tzinfo=timezone.utc
    )
    # The attack timeline stays unknown instead of claiming the disclosure date
    relationships = [
        obj for obj in bundle_objects if obj and obj.get("type") == "relationship"
    ]
    assert relationships
    assert all("start_time" not in rel for rel in relationships)

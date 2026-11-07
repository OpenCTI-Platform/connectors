"""A victim with an empty or invalid date must not abort the run (#7420)."""

from datetime import datetime
from unittest.mock import MagicMock

from ransomwarelive.ransom_conn import RansomwareAPIConnector


def _connector():
    connector = RansomwareAPIConnector.__new__(RansomwareAPIConnector)
    connector.helper = MagicMock()
    connector.config = MagicMock()
    settings = connector.config.ransomwarelive
    settings.create_threat_actor = False
    settings.create_campaign = False
    settings.create_intrusion_set = False
    settings.create_report = True
    settings.create_leak_post_refs = False
    connector.converter_to_stix = MagicMock()
    connector.api_client = MagicMock()
    connector.last_run = None
    connector.last_run_datetime_with_ingested_data = None
    return connector


def test_create_bundle_list_falls_back_to_discovered_when_attackdate_is_empty():
    connector = _connector()
    item = {
        "victim": "acme",
        "group": "lockbit",
        "attackdate": "",
        "discovered": "2026-02-03 04:05:06.000000",
    }

    connector.create_bundle_list(item=item, group_data=[])

    kwargs = connector.converter_to_stix.process_report.call_args.kwargs
    assert kwargs["attack_date_iso"] == datetime(2026, 2, 3, 4, 5, 6)
    assert kwargs["discovered_iso"] == datetime(2026, 2, 3, 4, 5, 6)


def test_create_bundle_list_keeps_valid_attackdate():
    connector = _connector()
    item = {
        "victim": "acme",
        "group": "lockbit",
        "attackdate": "2026-01-01 00:00:00.000000",
        "discovered": "2026-02-03 04:05:06.000000",
    }

    connector.create_bundle_list(item=item, group_data=[])

    kwargs = connector.converter_to_stix.process_report.call_args.kwargs
    assert kwargs["attack_date_iso"] == datetime(2026, 1, 1)


def test_collect_intelligence_skips_victim_without_discovered_date():
    connector = _connector()
    connector.api_client.get_groups.return_value = [{"name": "lockbit"}]
    connector.api_client.get_recent_victims.return_value = [
        {"victim": "acme", "group": "lockbit", "discovered": ""}
    ]
    connector.create_bundle_list = MagicMock()

    connector.collect_intelligence()

    connector.create_bundle_list.assert_not_called()
    connector.helper.connector_logger.warning.assert_called_once()
    connector.helper.send_stix2_bundle.assert_not_called()

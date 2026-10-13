"""Unit tests for the GreedyBear connector orchestration.

The GreedyBear client is mocked so feed contents are controlled; the real
converter runs so the collection loop is exercised end to end.
"""

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock

from connector.connector import GreedyBearConnector


def _config(api_key=None, **overrides):
    greedybear = SimpleNamespace(
        api_base_url="https://gb.example.com",
        api_key=(
            SimpleNamespace(get_secret_value=lambda: api_key) if api_key else None
        ),
        tlp_level="green",
        operator_name="Test Operator",
        operator_description=None,
        operator_url=None,
        feed_type="all",
        attack_type="all",
        ioc_type="all",
        prioritize="recent",
        include_mass_scanners=False,
        include_tor_exit_nodes=True,
        max_age=3,
        feed_size=5000,
        min_score=None,
        create_indicators=True,
        deep_enrich=False,
    )
    for key, value in overrides.items():
        setattr(greedybear, key, value)
    connector = SimpleNamespace(duration_period=timedelta(hours=6))
    return SimpleNamespace(greedybear=greedybear, connector=connector)


def _make_connector(api_key=None, authenticated=False, **overrides):
    conn = GreedyBearConnector(config=_config(api_key, **overrides), helper=MagicMock())
    conn.client = MagicMock()
    conn.client.authenticated = authenticated
    conn.client.get_asn_feeds.return_value = []
    conn.client.get_advanced_feeds.return_value = []
    conn.client.get_standard_feeds.return_value = []
    conn.client.get_enrichment.return_value = None
    return conn


IPV4_IOC = {
    "value": "8.8.8.8",
    "first_seen": "2026-06-01",
    "last_seen": "2026-06-10",
    "scanner": True,
    "recurrence_probability": 0.9,
    "attacker_country_code": "US",
    "asn": 15169,
    "ip_reputation": "known attacker",
}


def test_effective_max_age_first_run_uses_config():
    conn = _make_connector(max_age=5)
    now = datetime(2026, 6, 10, tzinfo=timezone.utc)
    assert conn._effective_max_age(now, None) == 5


def test_effective_max_age_recent_run_is_one_day():
    conn = _make_connector(max_age=5)
    now = datetime(2026, 6, 10, 12, tzinfo=timezone.utc)
    last_run = datetime(2026, 6, 10, 11, 55, tzinfo=timezone.utc).isoformat()
    assert conn._effective_max_age(now, last_run) == 1


def test_effective_max_age_old_run_capped_at_config():
    conn = _make_connector(max_age=3)
    now = datetime(2026, 6, 30, tzinfo=timezone.utc)
    last_run = datetime(2026, 6, 1, tzinfo=timezone.utc).isoformat()
    assert conn._effective_max_age(now, last_run) == 3


def test_effective_max_age_invalid_last_run_falls_back():
    conn = _make_connector(max_age=4)
    now = datetime(2026, 6, 10, tzinfo=timezone.utc)
    assert conn._effective_max_age(now, "not-a-timestamp") == 4


def test_collect_uses_advanced_feed_and_appends_author():
    conn = _make_connector(authenticated=True)
    conn.client.get_advanced_feeds.return_value = [IPV4_IOC]
    now = datetime(2026, 6, 10, tzinfo=timezone.utc)
    objects = conn._collect_intelligence(now, None)
    types = {o.type for o in objects}
    assert "ipv4-addr" in types
    assert "identity" in types  # author appended
    conn.client.get_standard_feeds.assert_not_called()


def test_collect_falls_back_to_standard_when_advanced_empty_unauth():
    conn = _make_connector(authenticated=False)
    conn.client.get_advanced_feeds.return_value = []
    conn.client.get_standard_feeds.return_value = [IPV4_IOC]
    objects = conn._collect_intelligence(datetime.now(tz=timezone.utc), None)
    conn.client.get_standard_feeds.assert_called_once()
    assert any(o.type == "ipv4-addr" for o in objects)


def test_collect_fallback_warns_when_authenticated():
    conn = _make_connector(authenticated=True)
    conn.client.get_advanced_feeds.return_value = []
    conn.client.get_standard_feeds.return_value = [IPV4_IOC]
    conn._collect_intelligence(datetime.now(tz=timezone.utc), None)
    assert conn.helper.connector_logger.warning.called


def test_collect_deduplicates_by_value():
    conn = _make_connector(authenticated=True)
    conn.client.get_advanced_feeds.return_value = [IPV4_IOC, dict(IPV4_IOC)]
    objects = conn._collect_intelligence(datetime.now(tz=timezone.utc), None)
    observables = [o for o in objects if o.type == "ipv4-addr"]
    assert len(observables) == 1  # duplicate value collapsed


def test_collect_injects_as_name_from_asn_feed():
    conn = _make_connector(authenticated=True)
    conn.client.get_asn_feeds.return_value = [{"asn": 15169, "as_name": "GOOGLE"}]
    conn.client.get_advanced_feeds.return_value = [IPV4_IOC]
    objects = conn._collect_intelligence(datetime.now(tz=timezone.utc), None)
    assert any(o.type == "autonomous-system" for o in objects)


def test_collect_deep_enrich_merges_fields():
    conn = _make_connector(authenticated=True, deep_enrich=True)
    conn.client.get_advanced_feeds.return_value = [dict(IPV4_IOC)]
    conn.client.get_enrichment.return_value = {
        "found": True,
        "ioc": {"number_of_days_seen": 4},
    }
    conn._collect_intelligence(datetime.now(tz=timezone.utc), None)
    conn.client.get_enrichment.assert_called_once()


def test_collect_empty_returns_no_objects():
    conn = _make_connector(authenticated=True)
    assert conn._collect_intelligence(datetime.now(tz=timezone.utc), None) == []


def test_process_message_first_run_sends_bundle_and_sets_state():
    conn = _make_connector(authenticated=True)
    conn.client.get_advanced_feeds.return_value = [IPV4_IOC]
    conn.helper.get_state.return_value = None
    conn.helper.send_stix2_bundle.return_value = ["bundle"]
    conn.process_message()
    conn.helper.send_stix2_bundle.assert_called_once()
    assert conn.helper.set_state.call_args[0][0]["last_run"]
    conn.helper.api.work.to_processed.assert_called_once()


def test_process_message_no_objects_warns_but_sets_state():
    conn = _make_connector(authenticated=True)  # all feeds empty
    conn.helper.get_state.return_value = {"last_run": "2026-06-01T00:00:00+00:00"}
    conn.process_message()
    conn.helper.send_stix2_bundle.assert_not_called()
    conn.helper.set_state.assert_called_once()


def test_process_message_handles_collection_error():
    conn = _make_connector(authenticated=True)
    conn.helper.get_state.return_value = None
    conn.client.get_asn_feeds.side_effect = RuntimeError("api down")
    conn.process_message()
    # work is closed in error, run does not crash
    assert conn.helper.api.work.to_processed.call_args[1]["in_error"] is True


def test_run_schedules_process():
    conn = _make_connector()
    conn.run()
    conn.helper.schedule_process.assert_called_once()

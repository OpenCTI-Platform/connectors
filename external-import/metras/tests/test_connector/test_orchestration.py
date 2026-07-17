"""Orchestration tests for the Feed connector (helper + client mocked)."""

from datetime import timedelta
from types import SimpleNamespace
from unittest.mock import MagicMock

from connector.connector import MetrasFeedConnector
from pydantic import SecretStr

SHA256 = "27e38928588e5153becf77dabe6a5e5df8377ab814ef9127f68155ed176e1181"


def _feed():
    cfg = SimpleNamespace(
        metras=SimpleNamespace(
            api_base_url="http://x/api",
            api_key=SecretStr("k"),
            verify_ssl=True,
            tlp_level="amber",
            page_size=50,
            import_alerts=True,
            import_binaries=True,
            import_endpoints=True,
            binary_malicious_only=True,
        ),
        connector=SimpleNamespace(duration_period=timedelta(hours=1)),
    )
    helper = MagicMock()
    helper.connect_confidence_level = 50
    helper.get_state.return_value = {}
    helper.api.work.initiate_work.return_value = "work-1"
    helper.stix2_create_bundle.return_value = "{}"
    conn = MetrasFeedConnector(cfg, helper)
    conn.client = MagicMock()
    return conn, helper


def test_import_sends_bundle_with_cleanup_flag_and_advances_state():
    conn, helper = _feed()
    conn.client.iter_edr_alerts.return_value = iter(
        [
            {
                "id": "a1",
                "alert_name": "r1",
                "severity": "Critical",
                "mitre_ids": ["T1059"],
                "last_occurrence_time": "2025-11-11T11:36:20Z",
                "endpoint_name": "EP",
                "agent_ip": "10.0.0.1",
            }
        ]
    )
    conn.client.iter_binaries.return_value = iter(
        [
            {
                "md5": "2e9fc997dea8b0fc30761e7d2e2c54be",
                "sha256": SHA256,
                "name": "evil.dll",
                "runnability_status": "banned",
                "first_endpoint_name": "EP",
                "last_seen": "2025-11-12T09:00:00Z",
            }
        ]
    )
    conn.client.list_endpoints.return_value = {
        "endpoints": [{"name": "EP", "os": "windows"}]
    }

    conn._import_data()

    assert helper.send_stix2_bundle.called
    _, kwargs = helper.send_stix2_bundle.call_args
    assert kwargs.get("cleanup_inconsistent_bundle") is True
    state = helper.set_state.call_args[0][0]
    assert "alerts_last_occurrence" in state and "binaries_last_seen" in state


def test_import_skips_old_alerts_via_cursor():
    conn, helper = _feed()
    helper.get_state.return_value = {"alerts_last_occurrence": "2025-12-01T00:00:00Z"}
    conn.client.iter_edr_alerts.return_value = iter(
        [
            {
                "id": "old",
                "alert_name": "r",
                "last_occurrence_time": "2025-11-11T11:36:20Z",
            }
        ]
    )
    conn.client.iter_binaries.return_value = iter([])
    conn.client.list_endpoints.return_value = {"endpoints": []}

    conn._import_data()
    # Only the author object -> nothing new -> no bundle sent.
    assert not helper.send_stix2_bundle.called


def test_duration_seconds_parses_iso_and_timedelta():
    assert MetrasFeedConnector._duration_seconds(timedelta(minutes=10)) == 600
    assert MetrasFeedConnector._duration_seconds("PT2H") == 7200
    assert MetrasFeedConnector._duration_seconds("P1D") == 86400

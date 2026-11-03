"""Read-only check of the connector on a real Microsoft Defender XDR tenant.

Skipped unless MICROSOFT_DEFENDER_HUNT_TENANT_ID, MICROSOFT_DEFENDER_HUNT_CLIENT_ID
and MICROSOFT_DEFENDER_HUNT_CLIENT_SECRET are set (an app registration granted
ThreatHunting.Read.All). It only runs advanced hunting queries, and prints counts
and the key, host and time of the first hit: run it with ``pytest -s``.
"""

import copy
import os
from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock

import pytest
from conftest import HUNT_EVENT, make_settings
from connectors_sdk.connectors.internal_hunt import RunDeadline
from microsoft_defender_hunt import MicrosoftDefenderHuntConnector
from microsoft_defender_hunt.client import timespan

ENV = {
    "tenant_id": "MICROSOFT_DEFENDER_HUNT_TENANT_ID",
    "client_id": "MICROSOFT_DEFENDER_HUNT_CLIENT_ID",
    "client_secret": "MICROSOFT_DEFENDER_HUNT_CLIENT_SECRET",
}

pytestmark = pytest.mark.skipif(
    not all(os.environ.get(name) for name in ENV.values()),
    reason="No Microsoft Defender XDR credentials in the environment.",
)

SIGMA_RULE = """
title: PowerShell process creation (live check)
status: test
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith:
      - '\\powershell.exe'
      - '\\pwsh.exe'
  condition: selection
"""

LOOKBACK = timedelta(days=7)


@pytest.fixture(scope="module")
def live():
    """A started connector on the real tenant, with a mocked OpenCTI helper."""
    connector = MicrosoftDefenderHuntConnector(
        make_settings(
            {
                "microsoft_defender_hunt": {
                    key: os.environ[name] for key, name in ENV.items()
                }
            }
        )
    )
    connector._helper = MagicMock()
    connector._helper.stix2_create_bundle.return_value = '{"type": "bundle"}'
    connector._logger = MagicMock()
    connector.post_init()
    return connector


def _event(**hunt) -> dict:
    end = datetime.now(UTC).replace(microsecond=0)
    event = copy.deepcopy(HUNT_EVENT)
    event["hunt"].update(hunt)
    event["time_window"] = {
        "start": (end - LOOKBACK).isoformat(),
        "end": end.isoformat(),
    }
    event["limits"] = {"max_results": 1000, "timeout_seconds": 300}
    return event


def _report(connector) -> dict:
    args, kwargs = connector.helper.report_hunt_run.call_args
    assert args[1] == "completed", kwargs.get("error")
    return kwargs


def _first_hit(kwargs) -> str:
    hits = kwargs.get("hits_sample") or []
    if not hits:
        return "no hit"
    hit = hits[0]
    return (
        f"key={kwargs['hit_keys'][0][:16]}... event_id={hit.get('event_id')} "
        f"host={hit.get('host')} time={hit.get('timestamp')}"
    )


def _sample(connector, query: str) -> list[str]:
    end = datetime.now(UTC)
    rows = connector.client.run_query(
        query, timespan(end - LOOKBACK, end), RunDeadline(120)
    ).rows
    return [str(value) for row in rows for value in row.values() if value]


def test_live_token_and_connection_checks(live):
    # Given/When a token is requested and the connection is tested
    assert live.client.tokens.access_token(RunDeadline(60))
    checks = live.connection_checks(RunDeadline(120))

    # Then both checks pass
    for check in checks:
        print(f"\nLIVE connection check {check.name}: ok={check.ok} ({check.message})")
    assert all(check.ok for check in checks)


def test_live_sigma_rule_over_7_days(live):
    # Given a Sigma rule translated with the microsoft_xdr pipeline
    query = live.translate(SIGMA_RULE, None)
    print(f"\nLIVE sigma query:\n{query.query}")

    # When it runs over the last 7 days
    live.helper.report_hunt_run.reset_mock()
    live.process_message(_event(sigma_rule=SIGMA_RULE, name="PowerShell (live)"))

    # Then the run completes
    kwargs = _report(live)
    print(
        f"LIVE sigma run: hits={kwargs['hits_count']} truncated={kwargs['truncated']} "
        f"distinct_entities={kwargs['distinct_entities']} first: {_first_hit(kwargs)}"
    )


def _indicator_run(live, observable_type, value, **extra):
    live.helper.report_hunt_run.reset_mock()
    ioc = {"key": "k-live", "observable_type": observable_type, "value": value}
    ioc.update(extra)
    live.process_message(
        _event(hunt_type="indicators", sigma_rule=None, iocs=[ioc], name="IOC (live)")
    )
    kwargs = _report(live)
    [result] = kwargs["ioc_results"]
    print(
        f"\nLIVE {observable_type} lookup: seen={result['seen']} searched={result['searched']} "
        f"value_hits={result.get('hits_count')} hits={kwargs['hits_count']} "
        f"hosts={len(result.get('hosts') or [])} truncated={kwargs['truncated']} "
        f"first: {_first_hit(kwargs)}"
    )
    return result


def test_live_ip_lookup_with_an_ip_of_the_tenant(live):
    # Given a public IP the devices of the tenant reached in the last 7 days
    values = _sample(
        live,
        "DeviceNetworkEvents | where RemoteIPType == 'Public' and isnotempty(RemoteIP)"
        " | summarize n = count() by RemoteIP | top 1 by n | project RemoteIP",
    )
    if not values:
        pytest.skip("No device network telemetry in the last 7 days.")

    # When/Then the indicator hunt finds it
    assert _indicator_run(live, "IPv4-Addr", values[0])["seen"] is True


def test_live_domain_lookup_with_a_domain_of_the_tenant(live):
    # Given a domain the devices of the tenant reached in the last 7 days
    values = _sample(
        live,
        "DeviceNetworkEvents | where isnotempty(RemoteUrl)"
        " | extend Host = tostring(parse_url(strcat('https://', trim_start(@'[a-z]+://', RemoteUrl))).Host)"
        " | where Host matches regex @'^([a-z0-9-]+\\.)+[a-z]{2,}$'"
        " | extend Domain = extract(@'([a-z0-9-]+\\.[a-z]{2,})$', 1, Host)"
        " | summarize n = count() by Domain | top 1 by n | project Domain",
    )
    if not values:
        pytest.skip("No device URL telemetry in the last 7 days.")

    # When/Then the indicator hunt finds it (subdomains included)
    assert _indicator_run(live, "Domain-Name", values[0])["seen"] is True


def test_live_hash_lookup_with_a_hash_of_the_tenant(live):
    # Given the SHA-256 of a process started in the last 7 days
    values = _sample(
        live,
        "DeviceProcessEvents | where isnotempty(SHA256)"
        " | summarize n = count() by SHA256 | top 1 by n | project SHA256",
    )
    if not values:
        pytest.skip("No device process telemetry in the last 7 days.")

    # When/Then the indicator hunt finds it
    result = _indicator_run(live, "StixFile", values[0], hash_algorithm="SHA-256")
    assert result["seen"] is True

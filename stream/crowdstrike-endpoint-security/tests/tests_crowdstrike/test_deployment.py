"""Deployment write-back of the CrowdStrike Endpoint Security connector."""

import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock, call

import pytest
from connectors_sdk import (
    DeploymentAssurance,
    HitCollection,
    IndicatorDeployment,
    VendorIndicator,
)
from crowdstrike_connector import ConnectorSettings, CrowdstrikeConnector
from crowdstrike_connector.deployment import (
    CrowdstrikeDeploymentAdapter,
    build_deployment_assurance,
)
from crowdstrike_services import (
    IOC_SOURCE,
    TO_DELETE_TAG,
    CrowdstrikeApiError,
    IocOperationResult,
    IocOperationStatus,
)
from pycti import OpenCTIConnectorHelper

OPENCTI_EXTENSION_ID = "extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba"
PLATFORM_ID = "6c3b0f4e-2d41-4a77-8f0d-3e1c9b5a7d21"
INDICATOR_ID = "0d8b4f0e-6a43-4f11-8f6c-1d2f5e6a7b8c"
INDICATOR_STIX_ID = "indicator--5d4f2a3b-8c9d-4e1f-a2b3-c4d5e6f7a8b9"
OTHER_ID = "1e9c5f1f-7b54-4a22-9e7d-2e3f6a7b8c9d"
IOC_ID = "4f1d0b5c2a6e48d39b7e1c0a5f2d8e6b"
CLIENT_ID = "test-client-id"


def make_settings(**namespaces: dict[str, Any]) -> ConnectorSettings:
    """Build connector settings from a valid configuration and overrides."""
    config = {
        "opencti": {"url": "http://localhost:8080", "token": "test-token"},
        "connector": {"id": "connector-id", "live_stream_id": "live"},
        "crowdstrike": {"client_id": CLIENT_ID, "client_secret": "secret"},
    }
    for namespace, values in namespaces.items():
        config[namespace] = {**config.get(namespace, {}), **values}

    class StubConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(config)

    return StubConnectorSettings()


def make_helper(spec: list[str] | None = None) -> MagicMock:
    helper = MagicMock(spec=spec) if spec is not None else MagicMock()
    helper.get_attribute_in_extension = (
        OpenCTIConnectorHelper.get_attribute_in_extension
    )
    helper.get_attribute_in_mitre_extension = (
        OpenCTIConnectorHelper.get_attribute_in_mitre_extension
    )
    return helper


def make_indicator(
    indicator_id=INDICATOR_ID, pattern="[ipv4-addr:value = '198.51.100.7']"
):
    return {
        "id": INDICATOR_STIX_ID,
        "type": "indicator",
        "spec_version": "2.1",
        "name": "198.51.100.7",
        "pattern": pattern,
        "pattern_type": "stix",
        "valid_from": "2026-10-01T00:00:00.000Z",
        "extensions": {
            OPENCTI_EXTENSION_ID: {"id": indicator_id, "type": "Indicator", "score": 80}
        },
    }


def make_message(event, data):
    return SimpleNamespace(event=event, data=json.dumps({"data": data}))


def api_response(status_code=200, resources=None, after=None, errors=None):
    """Build a falconpy response dictionary."""
    body: dict[str, Any] = {"resources": resources or [], "errors": errors or []}
    if after is not None:
        body["meta"] = {"pagination": {"after": after}}
    return {"status_code": status_code, "body": body}


def make_ioc(ioc_id=IOC_ID, value="198.51.100.7", **extra):
    return {
        "id": ioc_id,
        "type": "ipv4",
        "value": value,
        "source": IOC_SOURCE,
        "action": "detect",
        "tags": [],
        "deleted": False,
        "expired": False,
        **extra,
    }


def make_deployment(indicator_id=INDICATOR_ID, status="deployed", external_id=None):
    return IndicatorDeployment(
        relationship_id=f"relationship-{indicator_id}",
        status=status,
        indicator_id=indicator_id,
        indicator_standard_id=INDICATOR_STIX_ID,
        external_id=external_id,
        pattern="[ipv4-addr:value = '198.51.100.7']",
        pattern_type="stix",
    )


@pytest.fixture(name="no_atexit")
def fixture_no_atexit(monkeypatch):
    """Do not register the exit flush of the deployment reporter during tests."""
    monkeypatch.setattr(
        "connectors_sdk.connectors.stream.deployment.reporter.atexit.register",
        lambda _handler: None,
    )


def build_connector(settings=None, helper=None, assurance=None):
    connector = CrowdstrikeConnector(
        config=settings or make_settings(),
        helper=helper or make_helper(),
        assurance=assurance,
    )
    connector.client.cs = MagicMock()
    connector.client._alerts = MagicMock()
    return connector


@pytest.fixture(name="connector")
def fixture_connector():
    return build_connector(assurance=MagicMock(spec=DeploymentAssurance))


@pytest.fixture(name="permanent_connector")
def fixture_permanent_connector():
    return build_connector(
        settings=make_settings(crowdstrike={"permanent_delete": True}),
        assurance=MagicMock(spec=DeploymentAssurance),
    )


# Stream path


def test_created_ioc_is_reported_deployed(connector):
    connector.client.cs.indicator_search.return_value = api_response(resources=[])
    connector.client.cs.indicator_create.return_value = api_response(
        201, resources=[{"id": IOC_ID}]
    )
    indicator = make_indicator()

    connector._process_message(make_message("create", indicator))

    connector.assurance.report_pushed.assert_called_once_with(
        indicator, external_id=IOC_ID
    )


def test_rejected_ioc_is_reported_failed(connector):
    connector.client.cs.indicator_search.return_value = api_response(resources=[])
    connector.client.cs.indicator_create.return_value = api_response(
        400, errors=[{"code": 400, "message": "Invalid expiration"}]
    )
    indicator = make_indicator()

    connector._process_message(make_message("create", indicator))

    connector.assurance.report_push_failed.assert_called_once_with(
        indicator, "Invalid expiration", external_id=None
    )
    connector.assurance.report_pushed.assert_not_called()


def test_api_exception_is_reported_failed_and_raised(connector):
    error = ConnectionError("Connection reset by peer")
    connector.client.cs.indicator_search.return_value = api_response(resources=[])
    connector.client.cs.indicator_create.side_effect = error
    indicator = make_indicator()

    with pytest.raises(ConnectionError):
        connector._process_message(make_message("create", indicator))

    connector.assurance.report_push_failed.assert_called_once_with(indicator, error)


def test_unsupported_ioc_type_is_not_reported(connector):
    connector.client.cs.indicator_search.return_value = api_response(resources=[])

    connector._process_message(
        make_message("create", make_indicator(pattern="[url:value = 'https://x.y']"))
    )

    connector.client.cs.indicator_create.assert_not_called()
    connector.assurance.report_pushed.assert_not_called()
    connector.assurance.report_push_failed.assert_not_called()


def test_updated_ioc_is_reported_deployed(connector):
    connector.client.cs.indicator_search.return_value = api_response(resources=[IOC_ID])
    connector.client.cs.indicator_update.return_value = api_response(200)
    indicator = make_indicator()

    connector._process_message(make_message("update", indicator))

    connector.assurance.report_pushed.assert_called_once_with(
        indicator, external_id=IOC_ID
    )


def test_update_of_an_absent_ioc_is_not_reported(connector):
    connector.client.cs.indicator_search.return_value = api_response(resources=[])

    connector._process_message(make_message("update", make_indicator()))

    connector.assurance.report_pushed.assert_not_called()
    connector.assurance.report_push_failed.assert_not_called()


def test_failed_search_is_reported_failed(connector):
    connector.client.cs.indicator_search.return_value = api_response(
        500, errors=[{"message": "Internal error"}]
    )
    indicator = make_indicator()

    connector._process_message(make_message("update", indicator))

    connector.assurance.report_push_failed.assert_called_once_with(
        indicator, "Internal error", external_id=None
    )


def test_permanent_delete_is_reported_removed(permanent_connector):
    permanent_connector.client.cs.indicator_search.return_value = api_response(
        resources=[IOC_ID]
    )
    permanent_connector.client.cs.indicator_delete.return_value = api_response(200)
    indicator = make_indicator()

    permanent_connector._process_message(make_message("delete", indicator))

    permanent_connector.assurance.report_removed.assert_called_once_with(
        indicator, external_id=IOC_ID
    )


def test_delete_of_an_absent_ioc_is_reported_removed(permanent_connector):
    permanent_connector.client.cs.indicator_search.return_value = api_response(
        resources=[]
    )
    indicator = make_indicator()

    permanent_connector._process_message(make_message("delete", indicator))

    permanent_connector.assurance.report_removed.assert_called_once_with(
        indicator, external_id=None
    )


def test_failed_delete_is_not_reported_removed(permanent_connector):
    permanent_connector.client.cs.indicator_search.return_value = api_response(
        resources=[IOC_ID]
    )
    permanent_connector.client.cs.indicator_delete.return_value = api_response(
        403, errors=[{"message": "access denied"}]
    )

    permanent_connector._process_message(make_message("delete", make_indicator()))

    permanent_connector.assurance.report_removed.assert_not_called()
    permanent_connector.helper.connector_logger.warning.assert_called_once_with(
        "[DELETE] IOC not deleted from Crowdstrike", meta={"error": "access denied"}
    )


def test_soft_delete_keeps_the_ioc_detecting_and_reports_nothing(connector):
    connector.client.cs.indicator_search.return_value = api_response(resources=[IOC_ID])
    connector.client.cs.indicator_update.return_value = api_response(200)

    connector._process_message(make_message("delete", make_indicator()))

    body = connector.client.cs.indicator_update.call_args.kwargs["body"]
    assert TO_DELETE_TAG in body["indicators"][0]["tags"]
    connector.assurance.report_removed.assert_not_called()
    connector.assurance.report_pushed.assert_not_called()


def test_connector_works_without_write_back():
    connector = build_connector()
    connector.client.cs.indicator_search.return_value = api_response(resources=[])
    connector.client.cs.indicator_create.return_value = api_response(
        201, resources=[{"id": IOC_ID}]
    )

    connector._process_message(make_message("create", make_indicator()))

    connector.client.cs.indicator_create.assert_called_once()


def test_run_starts_the_write_back(connector):
    connector.run()

    connector.assurance.start.assert_called_once_with()
    connector.helper.listen_stream.assert_called_once_with(connector._process_message)


# Settings and factory


def test_write_back_settings_defaults():
    settings = make_settings()

    assert settings.deployment.reporting_enabled is True
    assert settings.deployment.reconciliation_interval == 60
    assert settings.hits.reporting_enabled is True
    assert settings.security_platform.name == "CrowdStrike Falcon"
    assert settings.security_platform.type == "EDR"
    assert settings.security_platform.id is None


def test_build_deployment_assurance_wires_reconciliation_and_hits():
    connector = build_connector()

    assurance = build_deployment_assurance(connector)

    assert assurance.enabled is True
    assert assurance.reporter.hits_enabled is True
    assert assurance.reporter.options.security_platform_name == "CrowdStrike Falcon"
    assert isinstance(assurance.reconciler._adapter, CrowdstrikeDeploymentAdapter)


def test_disabled_write_back_is_a_no_op():
    connector = build_connector(
        settings=make_settings(deployment={"reporting_enabled": False})
    )

    assurance = build_deployment_assurance(connector)

    assert assurance.enabled is False
    assert assurance.start() is False
    assert assurance.report_pushed(make_indicator()) is False
    assert assurance.reconciler.start() is False
    connector.helper.api.query.assert_not_called()


# Client


def test_iter_connector_iocs_follows_pagination():
    connector = build_connector()
    connector.client.cs.indicator_combined.side_effect = [
        api_response(resources=[make_ioc()], after="token-1"),
        api_response(resources=[make_ioc(ioc_id="other")], after="token-2"),
        api_response(resources=[]),
    ]

    iocs = list(connector.client.iter_connector_iocs(page_size=2))

    assert [ioc["id"] for ioc in iocs] == [IOC_ID, "other"]
    assert connector.client.cs.indicator_combined.call_args_list == [
        call(parameters={"filter": f'created_by:"{CLIENT_ID}"', "limit": 2}),
        call(
            parameters={
                "filter": f'created_by:"{CLIENT_ID}"',
                "limit": 2,
                "after": "token-1",
            }
        ),
        call(
            parameters={
                "filter": f'created_by:"{CLIENT_ID}"',
                "limit": 2,
                "after": "token-2",
            }
        ),
    ]


def test_listings_reject_a_resource_that_is_not_an_object():
    """A dropped resource would make an IOC look absent, or move the hit window past
    an unread alert: the listing fails instead."""
    connector = build_connector()
    connector.client.cs.indicator_combined.return_value = api_response(
        resources=[make_ioc(), "not an IOC"], after="token-1"
    )
    with pytest.raises(CrowdstrikeApiError, match="a resource is not an object"):
        list(connector.client.iter_connector_iocs(page_size=2))

    connector.client._alerts.get_alerts_combined.return_value = api_response(
        resources=[None]
    )
    with pytest.raises(CrowdstrikeApiError, match="a resource is not an object"):
        list(connector.client.iter_alerts(datetime(2026, 10, 3, 11, 0, tzinfo=UTC), 10))


def test_alert_listing_rejects_an_alert_without_id():
    """A capped read continues by excluding the ids already read: an alert without
    id would be returned, and counted, on every continuation."""
    connector = build_connector()
    connector.client._alerts.get_alerts_combined.return_value = api_response(
        resources=[{"composite_id": "a1"}, {"ioc_value": "198.51.100.7"}]
    )

    with pytest.raises(CrowdstrikeApiError, match="an alert carries no id"):
        list(connector.client.iter_alerts(datetime(2026, 10, 3, 11, 0, tzinfo=UTC), 10))


def test_iter_connector_iocs_raises_on_api_errors():
    connector = build_connector()
    connector.client.cs.indicator_combined.return_value = api_response(
        403, errors=[{"message": "access denied"}]
    )

    with pytest.raises(CrowdstrikeApiError, match="access denied"):
        list(connector.client.iter_connector_iocs())


def test_iter_connector_iocs_never_returns_a_partial_listing():
    connector = build_connector()
    connector.client.cs.indicator_combined.return_value = api_response(
        resources=[make_ioc()], after="same-token"
    )

    with pytest.raises(CrowdstrikeApiError, match="same pagination token"):
        list(connector.client.iter_connector_iocs())

    connector.client.cs.indicator_combined.side_effect = [
        api_response(resources=[make_ioc()], after="token-1"),
        api_response(resources=[make_ioc()], after="token-2"),
    ]
    with pytest.raises(CrowdstrikeApiError, match="after 2 pages"):
        list(connector.client.iter_connector_iocs(max_pages=2))


def test_delete_ioc():
    connector = build_connector()
    connector.client.cs.indicator_delete.return_value = api_response(200)

    connector.client.delete_ioc(IOC_ID)

    connector.client.cs.indicator_delete.assert_called_once_with(ids=[IOC_ID])

    connector.client.cs.indicator_delete.return_value = api_response(404)
    with pytest.raises(CrowdstrikeApiError, match="HTTP 404"):
        connector.client.delete_ioc(IOC_ID)


def test_deactivate_ioc_stops_the_detection_and_tags_it():
    connector = build_connector()
    connector.client.cs.indicator_update.return_value = api_response(200)

    connector.client.deactivate_ioc(make_ioc(tags=["opencti"]))

    connector.client.cs.indicator_update.assert_called_once_with(
        body={
            "comment": "IOC withdrawn from OpenCTI",
            "indicators": [
                {
                    "id": IOC_ID,
                    "action": "no_action",
                    "mobile_action": "no_action",
                    "tags": ["opencti", TO_DELETE_TAG],
                }
            ],
        }
    )


def test_iter_alerts_is_bounded_and_paginated():
    connector = build_connector()
    alerts = connector.client._alerts
    alerts.get_alerts_combined.side_effect = [
        api_response(resources=[{"id": "a1"}, {"id": "a2"}], after="next"),
        api_response(resources=[{"id": "a3"}, {"id": "a4"}], after="last"),
    ]
    since = datetime(2026, 10, 3, 10, 0, tzinfo=UTC)

    result = list(connector.client.iter_alerts(since, max_alerts=3, page_size=2))

    assert [alert["id"] for alert in result] == ["a1", "a2", "a3"]
    first, second = alerts.get_alerts_combined.call_args_list
    assert first.kwargs == {
        "filter": "created_timestamp:>='2026-10-03T10:00:00Z'",
        "sort": "created_timestamp|asc",
        "limit": 2,
        "after": None,
    }
    assert second.kwargs["limit"] == 1
    assert second.kwargs["after"] == "next"


@pytest.mark.parametrize(
    "tokens", [["same", "same"], ["token-1", "token-2", "token-1"]]
)
def test_iter_alerts_never_returns_a_listing_cut_by_a_repeated_token(tokens):
    """A pagination token returned twice while alerts are still listed is an error,
    never the end of the listing: the hit read would skip the alerts behind it."""
    connector = build_connector()
    connector.client._alerts.get_alerts_combined.side_effect = [
        api_response(resources=[{"id": f"a{index}"}], after=token)
        for index, token in enumerate(tokens)
    ]
    since = datetime(2026, 10, 3, 10, 0, tzinfo=UTC)

    with pytest.raises(CrowdstrikeApiError, match="same pagination token"):
        list(connector.client.iter_alerts(since, max_alerts=10, page_size=1))


def test_listings_without_a_resource_list_are_rejected():
    """A malformed success is never read as an empty listing: reconciliation would
    report every deployment removed and the hit window would skip unread alerts."""
    connector = build_connector()
    malformed = {"status_code": 200, "body": {"errors": []}}
    connector.client.cs.indicator_combined.return_value = malformed
    with pytest.raises(CrowdstrikeApiError, match="IOC listing response"):
        list(connector.client.iter_connector_iocs())

    connector.client._alerts.get_alerts_combined.return_value = {
        "status_code": 200,
        "body": {"resources": {"unexpected": True}},
    }
    since = datetime(2026, 10, 3, 10, 0, tzinfo=UTC)
    with pytest.raises(CrowdstrikeApiError, match="alert listing response"):
        list(connector.client.iter_alerts(since, max_alerts=3))

    connector.client.cs.indicator_combined.return_value = {
        "status_code": 200,
        "body": {"resources": None, "meta": {"pagination": {"total": 0}}},
    }
    assert list(connector.client.iter_connector_iocs()) == []


def test_iter_alerts_skips_excluded_alerts_without_counting_them():
    connector = build_connector()
    alerts = connector.client._alerts
    alerts.get_alerts_combined.side_effect = [
        api_response(
            resources=[{"composite_id": "a1"}, {"id": "a2"}, {"composite_id": "a3"}],
            after="next",
        ),
        api_response(resources=[{"composite_id": "a4"}]),
    ]
    since = datetime(2026, 10, 3, 10, 0, tzinfo=UTC)

    result = list(
        connector.client.iter_alerts(
            since, max_alerts=2, page_size=3, exclude_ids=frozenset({"a1", "a2"})
        )
    )

    assert [alert["composite_id"] for alert in result] == ["a3", "a4"]
    first, second = alerts.get_alerts_combined.call_args_list
    assert first.kwargs["limit"] == 3
    assert second.kwargs["limit"] == 3


# Vendor adapter


@pytest.fixture(name="adapter_client")
def fixture_adapter_client():
    return MagicMock()


def make_adapter(client, permanent_delete=False):
    config = SimpleNamespace(permanent_delete=permanent_delete)
    now = datetime(2026, 10, 3, 12, 0, tzinfo=UTC)
    return CrowdstrikeDeploymentAdapter(client, config, clock=lambda: now)


def test_adapter_lists_the_iocs_of_the_connector(adapter_client):
    """Expired and deactivated IOCs stay in CrowdStrike: listed inactive, so that
    a withdrawal still deletes or deactivates them."""
    adapter_client.iter_connector_iocs.return_value = iter(
        [
            make_ioc(),
            make_ioc(ioc_id="soft-deleted", tags=[TO_DELETE_TAG]),
            make_ioc(ioc_id="withdrawn", tags=[TO_DELETE_TAG], action="no_action"),
            make_ioc(ioc_id="other-source", source="Another feed"),
            make_ioc(ioc_id="deleted", deleted=True),
            make_ioc(ioc_id="expired", expired=True),
            make_ioc(ioc_id="past", expiration="2026-10-01T00:00:00Z"),
            make_ioc(ioc_id="future", expiration="2026-12-01T00:00:00Z"),
        ]
    )

    vendor_indicators = list(make_adapter(adapter_client).list_vendor_indicators())

    assert [(item.external_id, item.active) for item in vendor_indicators] == [
        (IOC_ID, True),
        ("soft-deleted", True),
        ("withdrawn", False),
        ("expired", False),
        ("past", False),
        ("future", True),
    ]
    assert vendor_indicators[0] == VendorIndicator(
        external_id=IOC_ID, value="198.51.100.7"
    )
    assert vendor_indicators[0].raw["source"] == IOC_SOURCE


def test_adapter_read_back_rejects_an_ioc_without_id(adapter_client):
    """A skipped IOC would make its deployment look absent."""
    adapter_client.iter_connector_iocs.return_value = iter(
        [make_ioc(), make_ioc(ioc_id=None)]
    )

    with pytest.raises(CrowdstrikeApiError, match="carries no id"):
        list(make_adapter(adapter_client).list_vendor_indicators())


def test_adapter_withdrawal_follows_the_permanent_delete_option(adapter_client):
    vendor_indicator = VendorIndicator(external_id=IOC_ID, raw=make_ioc())

    make_adapter(adapter_client).remove_vendor_indicator(
        vendor_indicator, make_deployment()
    )
    adapter_client.deactivate_ioc.assert_called_once_with(make_ioc())
    adapter_client.delete_ioc.assert_not_called()

    make_adapter(adapter_client, permanent_delete=True).remove_vendor_indicator(
        vendor_indicator, make_deployment()
    )
    adapter_client.delete_ioc.assert_called_once_with(IOC_ID)


@pytest.mark.parametrize(
    "result, expected",
    [
        (IocOperationResult(IocOperationStatus.CREATED, ioc_id=IOC_ID), IOC_ID),
        (IocOperationResult(IocOperationStatus.EXISTS, ioc_id=IOC_ID), IOC_ID),
        (IocOperationResult(IocOperationStatus.UPDATED, ioc_id=IOC_ID), IOC_ID),
    ],
)
def test_adapter_push_returns_the_ioc_id(adapter_client, result, expected):
    adapter_client.create_indicator.return_value = result
    indicator = make_indicator()

    assert make_adapter(adapter_client).push_indicator(indicator) == expected
    adapter_client.create_indicator.assert_called_once_with(indicator, "create")


def test_adapter_push_errors(adapter_client):
    adapter = make_adapter(adapter_client)
    adapter_client.create_indicator.return_value = IocOperationResult(
        IocOperationStatus.SKIPPED
    )
    with pytest.raises(ValueError, match="not supported"):
        adapter.push_indicator(make_indicator())

    adapter_client.create_indicator.return_value = IocOperationResult(
        IocOperationStatus.FAILED, error="Invalid value"
    )
    with pytest.raises(CrowdstrikeApiError, match="Invalid value"):
        adapter.push_indicator(make_indicator())

    adapter_client.create_indicator.return_value = IocOperationResult(
        IocOperationStatus.ABSENT
    )
    with pytest.raises(CrowdstrikeApiError, match="IOC push absent"):
        adapter.push_indicator(make_indicator())


def test_adapter_hits_use_the_creation_time_the_listing_is_ordered_by(
    adapter_client,
):
    """The alerts are listed by creation time: an alert created after `since` for an
    older event is a hit at its creation time, never dropped by its event time."""
    since = datetime(2026, 10, 3, 11, 0, tzinfo=UTC)
    adapter_client.iter_alerts.return_value = iter(
        [
            {
                "timestamp": "2026-10-03T10:30:00Z",
                "created_timestamp": "2026-10-03T11:05:00Z",
                "ioc_value": "198.51.100.7",
            }
        ]
    )

    hits = list(make_adapter(adapter_client).collect_hits([make_deployment()], since))

    assert [hit.timestamp for hit in hits] == [since + timedelta(minutes=5)]


def test_adapter_collects_hits_from_alerts(adapter_client):
    since = datetime(2026, 10, 3, 11, 0, tzinfo=UTC)
    adapter_client.iter_alerts.return_value = iter(
        [
            {"timestamp": "2026-10-03T11:10:00Z", "ioc_value": "198.51.100.7"},
            {
                "created_timestamp": "2026-10-03T11:20:00Z",
                "ioc_values": ["198.51.100.7", "203.0.113.9"],
            },
            {
                "timestamp": "2026-10-03T11:30:00Z",
                "ioc_context": [{"ioc_value": "198.51.100.7"}],
            },
            {"timestamp": "2026-10-03T10:00:00Z", "ioc_value": "198.51.100.7"},
            {"timestamp": "2026-10-03T11:40:00Z", "ioc_value": "unrelated.example"},
        ]
    )

    hits = list(make_adapter(adapter_client).collect_hits([make_deployment()], since))

    assert [(hit.indicator_id, hit.timestamp.minute) for hit in hits] == [
        (INDICATOR_ID, 10),
        (INDICATOR_ID, 20),
        (INDICATOR_ID, 30),
    ]
    adapter_client.iter_alerts.assert_called_once_with(
        since, 10_000, exclude_ids=frozenset()
    )


@pytest.mark.parametrize(
    "alert",
    [
        {"ioc_value": "198.51.100.7"},
        {"created_timestamp": "not a date", "ioc_value": "198.51.100.7"},
    ],
)
def test_adapter_hit_read_rejects_an_alert_without_creation_time(adapter_client, alert):
    """A skipped alert would be lost: the hit cursor moves past its IOC matches."""
    since = datetime(2026, 10, 3, 11, 0, tzinfo=UTC)
    adapter_client.iter_alerts.return_value = iter(
        [
            {"created_timestamp": "2026-10-03T11:10:00Z", "ioc_value": "198.51.100.7"},
            alert,
        ]
    )

    with pytest.raises(CrowdstrikeApiError, match="carries no creation time"):
        make_adapter(adapter_client).collect_hits([make_deployment()], since)


@pytest.mark.parametrize(
    ("iocs", "message"),
    [
        ({"ioc_values": "198.51.100.7"}, "carries malformed IOCs"),
        ({"ioc_context": {"ioc_value": "198.51.100.7"}}, "carries malformed IOCs"),
        ({"ioc_context": ["198.51.100.7"]}, "IOC context that is not an object"),
    ],
)
def test_adapter_hit_read_rejects_an_alert_with_malformed_iocs(
    adapter_client, iocs, message
):
    """A skipped IOC would be lost: the hit cursor moves past its matches."""
    since = datetime(2026, 10, 3, 11, 0, tzinfo=UTC)
    adapter_client.iter_alerts.return_value = iter(
        [{"created_timestamp": "2026-10-03T11:10:00Z", **iocs}]
    )

    with pytest.raises(CrowdstrikeApiError, match=message):
        make_adapter(adapter_client).collect_hits([make_deployment()], since)


def test_adapter_capped_hit_read_is_complete_until_the_newest_alert(adapter_client):
    """Alerts are read oldest first: when the cap is reached, the next run resumes at
    the newest alert read instead of losing the alerts beyond the cap."""
    since = datetime(2026, 10, 3, 11, 0, tzinfo=UTC)
    adapter_client.iter_alerts.return_value = iter(
        [
            {"timestamp": "2026-10-03T11:10:00Z", "ioc_value": "198.51.100.7"},
            {"timestamp": "2026-10-03T11:20:00Z", "ioc_value": "198.51.100.7"},
        ]
    )
    adapter = CrowdstrikeDeploymentAdapter(
        adapter_client, SimpleNamespace(permanent_delete=False), max_alerts=2
    )

    collection = adapter.collect_hits([make_deployment()], since)

    assert isinstance(collection, HitCollection)
    assert collection.complete_until == datetime(2026, 10, 3, 11, 20, tzinfo=UTC)
    assert [hit.timestamp.minute for hit in collection.hits] == [10, 20]
    assert collection.resume is None


def test_adapter_capped_read_at_its_start_continues_after_the_alerts_read(
    adapter_client,
):
    """More alerts than the cap in the starting second: the next read skips the
    alerts already read there (those of that second before `since` included)."""
    since = datetime(2026, 10, 3, 11, 0, 0, 500000, tzinfo=UTC)
    adapter_client.iter_alerts.return_value = iter(
        [
            {
                "composite_id": "early",
                "timestamp": "2026-10-03T11:00:00.100Z",
                "ioc_value": "198.51.100.7",
            },
            {
                "composite_id": "tied",
                "timestamp": "2026-10-03T11:00:00.500Z",
                "ioc_value": "198.51.100.7",
            },
        ]
    )
    adapter = CrowdstrikeDeploymentAdapter(
        adapter_client, SimpleNamespace(permanent_delete=False), max_alerts=2
    )

    collection = adapter.collect_hits(
        [make_deployment()], since, resume=frozenset({"before"})
    )

    assert isinstance(collection, HitCollection)
    assert collection.complete_until == since
    assert collection.resume == frozenset({"before", "early", "tied"})
    assert [hit.timestamp for hit in collection.hits] == [since]
    adapter_client.iter_alerts.assert_called_once_with(
        since, 2, exclude_ids=frozenset({"before"})
    )


def test_adapter_credits_every_indicator_sharing_an_alert_value(adapter_client):
    since = datetime(2026, 10, 3, 11, 0, tzinfo=UTC)
    adapter_client.iter_alerts.return_value = iter(
        [{"timestamp": "2026-10-03T11:10:00Z", "ioc_value": "198.51.100.7"}]
    )
    other_id = "1f2e3d4c-5b6a-4789-8abc-def012345678"

    hits = list(
        make_adapter(adapter_client).collect_hits(
            [make_deployment(), make_deployment(indicator_id=other_id)], since
        )
    )

    assert sorted(hit.indicator_id for hit in hits) == sorted([INDICATOR_ID, other_id])


def test_adapter_hits_match_the_pushed_value_only(adapter_client):
    """CrowdStrike holds the first value of a composite pattern: an alert on another
    value of the pattern was not raised by the pushed IOC."""
    since = datetime(2026, 10, 3, 11, 0, tzinfo=UTC)
    adapter_client.iter_alerts.return_value = iter(
        [
            {"timestamp": "2026-10-03T11:10:00Z", "ioc_value": "203.0.113.9"},
            {"timestamp": "2026-10-03T11:20:00Z", "ioc_value": "198.51.100.7"},
        ]
    )
    deployment = replace(
        make_deployment(),
        pattern="[ipv4-addr:value = '198.51.100.7' OR ipv4-addr:value = '203.0.113.9']",
    )

    hits = list(make_adapter(adapter_client).collect_hits([deployment], since))

    assert [hit.timestamp.minute for hit in hits] == [20]


@pytest.mark.parametrize(
    "deployment",
    [
        IndicatorDeployment(
            relationship_id="r", status="deployed", indicator_id=INDICATOR_ID
        ),
        IndicatorDeployment(
            relationship_id="r",
            status="deployed",
            indicator_id=INDICATOR_ID,
            pattern="alert tcp any any -> any any",
            pattern_type="snort",
        ),
        IndicatorDeployment(
            relationship_id="r",
            status="deployed",
            indicator_id=INDICATOR_ID,
            pattern="[ipv4-addr:value='198.51.100.7']",
            pattern_type="stix",
        ),
    ],
)
def test_adapter_hits_without_values_read_no_alert(adapter_client, deployment):
    assert (
        make_adapter(adapter_client).collect_hits([deployment], datetime.now(UTC)) == []
    )
    adapter_client.iter_alerts.assert_not_called()


def test_adapter_expects_the_pushed_value_only(adapter_client):
    """Reconciliation matches the value CrowdStrike holds, as the hits do."""
    adapter = make_adapter(adapter_client)
    composite = replace(
        make_deployment(),
        pattern="[ipv4-addr:value = '198.51.100.7' OR ipv4-addr:value = '203.0.113.9']",
    )
    snort = replace(
        make_deployment(), pattern="alert tcp any any -> any any", pattern_type="snort"
    )

    assert adapter.expected_values(composite) == frozenset({"198.51.100.7"})
    assert adapter.expected_values(snort) == frozenset()


# End to end: stream processing and reconciliation through GraphQL


class GraphQLRouter:
    """Fake `helper.api.query` dispatching on the GraphQL operation name."""

    def __init__(self, deployments=None):
        self.calls = []
        self.deployments = deployments or []

    def __call__(self, query, variables=None):
        self.calls.append((query, variables))
        if "DeploymentWriteBackFeatures" in query:
            fields = [
                {"name": "indicatorReportDeployment"},
                {"name": "indicatorReportDeployments"},
                {"name": "indicatorReportHits"},
            ]
            return {"data": {"__type": {"fields": fields}}}
        if "DeploymentSecurityPlatformAdd" in query:
            return {"data": {"securityPlatformAdd": {"id": PLATFORM_ID}}}
        if "IndicatorReportDeployments(" in query:
            count = len(variables["reports"])
            return {
                "data": {
                    "indicatorReportDeployments": {
                        "processed": count,
                        "created": 0,
                        "updated": count,
                        "unchanged": 0,
                        "errors": [],
                    }
                }
            }
        if "IndicatorReportHits(" in query:
            return {"data": {"indicatorReportHits": {"id": "sighting-id"}}}
        if "IndicatorDeploymentsOfPlatform" in query:
            return {
                "data": {
                    "stixCoreRelationships": {
                        "edges": [{"node": node} for node in self.deployments],
                        "pageInfo": {"endCursor": None, "hasNextPage": False},
                    }
                }
            }
        raise AssertionError(f"Unexpected GraphQL document: {query}")

    def calls_of(self, marker):
        return [variables for query, variables in self.calls if marker in query]


def deployment_node(indicator_id, status, external_id=None, value="198.51.100.7"):
    return {
        "id": f"relationship-{indicator_id}",
        "deployment_status": status,
        "external_id": external_id,
        "revoked": False,
        "last_sync_at": "2026-10-01T00:00:00.000Z",
        "last_hit_at": None,
        "hit_count": 0,
        "from": {
            "id": indicator_id,
            "standard_id": f"indicator--{indicator_id}",
            "name": value,
            "pattern": f"[ipv4-addr:value = '{value}']",
            "pattern_type": "stix",
            "revoked": False,
            "valid_until": None,
        },
    }


@pytest.fixture(name="router")
def fixture_router():
    return GraphQLRouter()


@pytest.fixture(name="e2e_connector")
def fixture_e2e_connector(no_atexit, router):
    """Connector with a helper without the pycti deployment helpers (GraphQL path)."""
    helper = make_helper(
        spec=[
            "api",
            "connector_logger",
            "listen_stream",
            "get_attribute_in_extension",
            "get_attribute_in_mitre_extension",
        ]
    )
    helper.api.query.side_effect = router
    connector = build_connector(helper=helper)
    connector.assurance = DeploymentAssurance.from_settings(
        helper,
        connector.config,
        adapter=CrowdstrikeDeploymentAdapter(
            connector.client, connector.config.crowdstrike
        ),
        reporter_kwargs={"flush_interval": 3600.0},
    )
    return connector


def test_stream_outcomes_are_reported_in_one_batch(e2e_connector, router):
    cs = e2e_connector.client.cs
    cs.indicator_search.return_value = api_response(resources=[])
    cs.indicator_create.side_effect = [
        api_response(201, resources=[{"id": IOC_ID}]),
        api_response(400, errors=[{"message": "Invalid severity"}]),
    ]

    e2e_connector._process_message(make_message("create", make_indicator()))
    e2e_connector._process_message(
        make_message("create", make_indicator(indicator_id=OTHER_ID))
    )
    result = e2e_connector.assurance.flush()

    assert result.processed == 2
    assert router.calls_of("DeploymentSecurityPlatformAdd") == [
        {
            "input": {
                "name": "CrowdStrike Falcon",
                "update": True,
                "security_platform_type": "EDR",
            }
        }
    ]
    (batch,) = router.calls_of("IndicatorReportDeployments(")
    assert batch["platformId"] == PLATFORM_ID
    assert batch["reports"] == [
        {"indicatorId": INDICATOR_ID, "status": "deployed", "externalId": IOC_ID},
        {
            "indicatorId": OTHER_ID,
            "status": "failed",
            "metadata": {"error_message": "Invalid severity"},
        },
    ]


def test_reconciliation_and_hits_are_reported(e2e_connector, router):
    router.deployments = [
        deployment_node(INDICATOR_ID, "deployed", external_id=IOC_ID),
        deployment_node(OTHER_ID, "active", value="203.0.113.9"),
    ]
    e2e_connector.client.cs.indicator_combined.return_value = api_response(
        resources=[make_ioc()]
    )
    alert_time = (datetime.now(UTC) - timedelta(minutes=5)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    e2e_connector.client._alerts.get_alerts_combined.return_value = api_response(
        resources=[
            {
                "composite_id": "alert-1",
                "timestamp": alert_time,
                "ioc_value": "198.51.100.7",
            },
            {
                "composite_id": "alert-2",
                "timestamp": alert_time,
                "ioc_values": ["198.51.100.7"],
            },
        ]
    )

    summary = e2e_connector.assurance.reconciler.run_once()

    assert summary.skipped is False
    assert summary.confirmed_active == 1
    assert summary.marked_removed == 1
    assert summary.hits_reported == 1
    (batch,) = router.calls_of("IndicatorReportDeployments(")
    reports = {report["indicatorId"]: report for report in batch["reports"]}
    assert reports[INDICATOR_ID]["status"] == "active"
    assert reports[INDICATOR_ID]["externalId"] == IOC_ID
    assert reports[OTHER_ID]["status"] == "removed"
    (hits,) = router.calls_of("IndicatorReportHits(")
    assert hits["indicatorId"] == INDICATOR_ID
    assert hits["count"] == 2


def composite_node(revoked=False):
    """A deployment of a composite pattern: CrowdStrike only holds its first value."""
    node = deployment_node(INDICATOR_ID, "active")
    node["revoked"] = revoked
    node["from"][
        "pattern"
    ] = "[ipv4-addr:value = '198.51.100.7' OR ipv4-addr:value = '203.0.113.9']"
    return node


def reconcile_with_another_value_listed(e2e_connector, router, node):
    """Run a reconciliation whose read-back only holds an IOC of the second value."""
    router.deployments = [node]
    e2e_connector.client.cs.indicator_combined.return_value = api_response(
        resources=[make_ioc(ioc_id="other-ioc", value="203.0.113.9")]
    )
    e2e_connector.client._alerts.get_alerts_combined.return_value = api_response(
        resources=[]
    )
    summary = e2e_connector.assurance.reconciler.run_once()
    (batch,) = router.calls_of("IndicatorReportDeployments(")
    return summary, [(r["indicatorId"], r["status"]) for r in batch["reports"]]


def test_an_ioc_of_an_unpushed_value_does_not_confirm_a_composite(
    e2e_connector, router
):
    summary, reports = reconcile_with_another_value_listed(
        e2e_connector, router, composite_node()
    )

    assert summary.confirmed_active == 0
    assert reports == [(INDICATOR_ID, "removed")]


def test_an_ioc_of_an_unpushed_value_is_not_withdrawn_for_a_composite(
    e2e_connector, router
):
    summary, reports = reconcile_with_another_value_listed(
        e2e_connector, router, composite_node(revoked=True)
    )

    assert summary.withdrawn == 0
    assert reports == [(INDICATOR_ID, "removed")]
    e2e_connector.client.cs.indicator_update.assert_not_called()
    e2e_connector.client.cs.indicator_delete.assert_not_called()


def test_read_back_failure_skips_the_reconciliation(e2e_connector, router):
    router.deployments = [deployment_node(INDICATOR_ID, "active")]
    e2e_connector.client.cs.indicator_combined.return_value = api_response(
        500, errors=[{"message": "Service unavailable"}]
    )

    summary = e2e_connector.assurance.reconciler.run_once()

    assert summary.skipped is True
    assert "Service unavailable" in summary.reason
    assert router.calls_of("IndicatorReportDeployments(") == []

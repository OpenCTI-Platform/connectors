"""Deployment write-back of the Cortex XDR Intel connector."""

import json
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
import requests
from connector import Connector, ConnectorSettings
from connector.deployment import (
    CortexXdrDeploymentAdapter,
    CortexXdrDeploymentError,
    build_deployment_assurance,
    describe_error,
    rule_ids_of,
)
from connector.models import CortexXdrIoc
from connectors_sdk import (
    ApiClientError,
    ApiServerError,
    DeploymentAssurance,
    HitCollection,
    IndicatorDeployment,
    VendorIndicator,
)
from cortex_xdr_client import CortexXdrApiError
from cortex_xdr_client.client import CortexXdrClient
from pycti import OpenCTIConnectorHelper
from pydantic import HttpUrl

OPENCTI_EXTENSION_ID = "extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba"
PLATFORM_ID = "6c3b0f4e-2d41-4a77-8f0d-3e1c9b5a7d21"
INDICATOR_ID = "0d8b4f0e-6a43-4f11-8f6c-1d2f5e6a7b8c"
OTHER_ID = "1e9c5f1f-7b54-4a22-9e7d-2e3f6a7b8c9d"
SHA256 = "37c09c95f77e5677332de338b7e972cff67347ed2c807c15b415c41b0d4a9ac4"
MD5 = "44d88612fea8a8f36de82e1278abb02f"


def make_settings(**namespaces: dict[str, Any]) -> ConnectorSettings:
    """Build connector settings from a valid configuration and overrides."""
    config = {
        "opencti": {"url": "http://localhost:8080", "token": "test-token"},
        "connector": {"live_stream_id": "live"},
        "pan_cortex_xdr_intel": {
            "api_base_url": "https://api-tenant.xdr.eu.paloaltonetworks.com",
            "api_key_id": "1",
            "api_key": "secret",
        },
    }
    for namespace, values in namespaces.items():
        config[namespace] = {**config.get(namespace, {}), **values}

    class StubConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(config)

    return StubConnectorSettings()


def make_indicator(indicator_id=INDICATOR_ID, value="198.51.100.7"):
    return {
        "id": "indicator--5d4f2a3b-8c9d-4e1f-a2b3-c4d5e6f7a8b9",
        "type": "indicator",
        "spec_version": "2.1",
        "name": value,
        "pattern": f"[ipv4-addr:value = '{value}']",
        "pattern_type": "stix",
        "valid_from": "2026-10-01T00:00:00.000Z",
        "extensions": {
            OPENCTI_EXTENSION_ID: {
                "id": indicator_id,
                "type": "Indicator",
                "score": 80,
                "observable_values": [{"type": "IPv4-Addr", "value": value}],
            }
        },
    }


def make_message(event, data):
    return SimpleNamespace(event=event, data=json.dumps({"data": data}), id="1-0")


def make_helper(spec: list[str] | None = None) -> MagicMock:
    helper = MagicMock(spec=spec) if spec is not None else MagicMock()
    helper.get_attribute_in_extension = (
        OpenCTIConnectorHelper.get_attribute_in_extension
    )
    return helper


def api_error(cause: BaseException | None = None) -> CortexXdrApiError:
    """Build the error raised by the client, chained to its cause."""
    error = CortexXdrApiError("Error while fetching Cortex XDR API")
    error.__cause__ = cause
    return error


def build_connector(settings=None, helper=None, assurance=None, client=None):
    if client is None:
        client = MagicMock()
        client.get_iocs.return_value = {"objects": []}
    return Connector(
        helper=helper or make_helper(),
        settings=settings or make_settings(),
        client=client,
        assurance=assurance,
    )


def make_deployment(indicator_id=INDICATOR_ID, value="198.51.100.7", **fields):
    return IndicatorDeployment(
        relationship_id=f"relationship-{indicator_id}",
        status=fields.pop("status", "deployed"),
        indicator_id=indicator_id,
        pattern=fields.pop("pattern", f"[ipv4-addr:value = '{value}']"),
        pattern_type="stix",
        **fields,
    )


def mock_response(json_data, status_code=200):
    response = MagicMock(spec=requests.Response)
    response.status_code = status_code
    response.ok = 200 <= status_code < 400
    response.json.return_value = json_data
    response.headers = {"Content-Type": "application/json"}
    response.text = json.dumps(json_data)
    response.content = response.text.encode()
    return response


@pytest.fixture(name="connector")
def fixture_connector():
    return build_connector(assurance=MagicMock(spec=DeploymentAssurance))


@pytest.fixture(name="xdr_client")
def fixture_xdr_client():
    return CortexXdrClient(HttpUrl("https://api-test.com"), "1", "secret")


@pytest.fixture(name="no_atexit")
def fixture_no_atexit(monkeypatch):
    """Do not register the exit flush of the deployment reporter during tests."""
    monkeypatch.setattr(
        "connectors_sdk.connectors.stream.deployment.reporter.atexit.register",
        lambda _handler: None,
    )


# Stream path


@pytest.mark.parametrize("event", ["create", "update"])
def test_upserted_indicator_is_reported_deployed(connector, event):
    connector.client.insert_iocs.return_value = {
        "added_objects": [{"id": 123, "status": "Created"}]
    }
    indicator = make_indicator()

    connector._process_message(make_message(event, indicator))

    connector.assurance.report_pushed.assert_called_once_with(
        indicator, external_id="123"
    )
    connector.assurance.report_push_failed.assert_not_called()


def test_updated_ioc_reports_the_existing_rule_id(connector):
    connector.client.get_iocs.return_value = {
        "objects": [{"rule_id": 42, "indicator": "198.51.100.7", "type": "IP"}]
    }
    connector.client.insert_iocs.return_value = None
    indicator = make_indicator()

    connector._process_message(make_message("update", indicator))

    connector.assurance.report_pushed.assert_called_once_with(
        indicator, external_id="42"
    )


def test_rejected_indicator_is_reported_failed_and_the_stream_continues(connector):
    rejection = ApiClientError(
        "Bad request", status_code=400, response_body={"err_msg": "invalid IOC"}
    )
    connector.client.insert_iocs.side_effect = api_error(rejection)
    indicator = make_indicator()

    connector._process_message(make_message("create", indicator))

    reported, message = connector.assurance.report_push_failed.call_args.args
    assert reported == indicator
    assert message == "Cortex XDR refused the IOC upsert: invalid request"
    connector.assurance.report_pushed.assert_not_called()
    logged = connector.helper.connector_logger.error.call_args.args[1]["error"]
    assert logged == (
        'Error while fetching Cortex XDR API: Bad request (HTTP 400) - {"err_msg": '
        '"invalid IOC"}'
    )


def test_fatal_api_error_is_reported_failed_before_stopping(connector):
    connector.client.insert_iocs.side_effect = api_error(
        ApiServerError("Server error", status_code=503)
    )

    with pytest.raises(CortexXdrApiError):
        connector._process_message(make_message("create", make_indicator()))

    message = connector.assurance.report_push_failed.call_args.args[1]
    assert message == "Cortex XDR refused the IOC upsert: server error"


def test_unreachable_cortex_xdr_is_reported_failed(connector):
    connector.client.insert_iocs.side_effect = ConnectionError("connection reset")

    with pytest.raises(ConnectionError):
        connector._process_message(make_message("create", make_indicator()))

    message = connector.assurance.report_push_failed.call_args.args[1]
    assert message == "Cortex XDR could not be reached for the IOC upsert"


def test_unexpected_error_is_reported_failed_before_stopping(connector):
    connector.client.insert_iocs.side_effect = RuntimeError("boom")

    with pytest.raises(RuntimeError):
        connector._process_message(make_message("create", make_indicator()))

    assert connector.assurance.report_push_failed.call_args.args[1] == "boom"


def test_indicator_without_supported_observable_is_not_reported(connector):
    indicator = make_indicator()
    indicator["extensions"][OPENCTI_EXTENSION_ID]["observable_values"] = [
        {"type": "Mutex", "value": "mutex"}
    ]

    connector._process_message(make_message("create", indicator))

    connector.client.insert_iocs.assert_not_called()
    connector.assurance.report_pushed.assert_not_called()
    connector.assurance.report_push_failed.assert_not_called()


def test_delete_is_reported_removed(connector):
    indicator = make_indicator()

    connector._process_message(make_message("delete", indicator))

    connector.client.delete_iocs.assert_called_once()
    connector.assurance.report_removed.assert_called_once_with(indicator)


def test_failed_delete_is_not_reported(connector):
    connector.client.delete_iocs.side_effect = api_error(ValueError("rejected"))

    connector._process_message(make_message("delete", make_indicator()))

    connector.assurance.report_removed.assert_not_called()
    connector.assurance.report_push_failed.assert_not_called()


def file_indicator():
    indicator = make_indicator()
    indicator["pattern"] = (
        f"[file:hashes.'SHA-256' = '{SHA256}' OR file:hashes.MD5 = '{MD5}']"
    )
    indicator["extensions"][OPENCTI_EXTENSION_ID]["observable_values"] = [
        {"type": "StixFile", "hashes": {"SHA-256": SHA256, "MD5": MD5}}
    ]
    return indicator


def test_delete_keeps_the_iocs_another_valid_indicator_holds(connector):
    connector.helper.api.indicator.list.return_value = [
        {"id": INDICATOR_ID, "pattern": f"[file:hashes.MD5 = '{MD5}']"},
        {"id": OTHER_ID, "pattern": f"[file:hashes.MD5 = '{MD5.upper()}']"},
        {
            "id": "expired-id",
            "pattern": f"[file:hashes.'SHA-256' = '{SHA256}']",
            "valid_until": "2020-01-01T00:00:00.000Z",
        },
    ]
    indicator = file_indicator()

    connector._process_message(make_message("delete", indicator))

    connector.client.delete_iocs.assert_called_once_with(
        [{"field": "indicator", "operator": "IN", "value": [SHA256]}]
    )
    connector.assurance.report_removed.assert_called_once_with(indicator)
    filters = connector.helper.api.indicator.list.call_args.kwargs["filters"]
    assert filters["filters"] == [
        {
            "key": "pattern",
            "values": [f"'{SHA256}'", f"'{MD5}'"],
            "operator": "contains",
            "mode": "or",
        },
        {"key": "revoked", "values": ["false"]},
    ]


def test_delete_of_values_all_kept_sends_nothing_and_is_reported(connector):
    connector.helper.api.indicator.list.return_value = [
        {
            "id": OTHER_ID,
            "pattern": "[ipv4-addr:value = '198.51.100.7']",
            "valid_until": "2999-01-01T00:00:00.000Z",
        }
    ]
    indicator = make_indicator()

    connector._process_message(make_message("delete", indicator))

    connector.client.delete_iocs.assert_not_called()
    connector.assurance.report_removed.assert_called_once_with(indicator)


def test_delete_without_the_other_indicators_is_skipped(connector):
    connector.helper.api.indicator.list.side_effect = RuntimeError("OpenCTI down")

    connector._process_message(make_message("delete", make_indicator()))

    connector.client.delete_iocs.assert_not_called()
    connector.assurance.report_removed.assert_not_called()
    meta = connector.helper.connector_logger.error.call_args.args[1]
    assert meta["error"] == (
        "Cannot read the OpenCTI indicators sharing its values: OpenCTI down"
    )


def test_connector_works_without_write_back():
    connector = build_connector()

    connector._process_message(make_message("create", make_indicator()))
    connector._process_message(make_message("delete", make_indicator()))

    connector.client.insert_iocs.assert_called_once()
    connector.client.delete_iocs.assert_called_once()


def test_start_starts_the_write_back(connector):
    connector.start()

    connector.assurance.start.assert_called_once_with()
    connector.helper.listen_stream.assert_called_once_with(connector._process_message)


def test_describe_error():
    assert describe_error(ValueError()) == "ValueError"
    assert describe_error(api_error(ValueError("timeout"))) == (
        "Error while fetching Cortex XDR API: timeout"
    )
    error = api_error(ApiClientError("Bad request", response_body="x" * 600))
    assert describe_error(error).endswith(" - " + "x" * 500)


def test_rule_ids_of_prefers_the_response_ids():
    sent = [CortexXdrIoc(indicator="evil.com", type="DOMAIN_NAME", rule_id=7)]

    assert rule_ids_of(
        {"added_objects": [{"id": 1}, "ignored"], "updated_objects": [{"id": 2}]},
        sent,
    ) == ["1", "2"]
    assert rule_ids_of({"added_objects": [{"status": "Created"}]}, sent) == ["7"]
    assert rule_ids_of(None, []) == []


# Settings and factory


def test_write_back_settings_defaults():
    settings = make_settings()

    assert settings.deployment.reporting_enabled is True
    assert settings.deployment.reconciliation_interval == 60
    assert settings.hits.reporting_enabled is True
    assert settings.security_platform.name == "Palo Alto Cortex XDR"
    assert settings.security_platform.type == "XDR"
    assert settings.security_platform.id is None


def test_build_deployment_assurance_wires_reconciliation_and_hits():
    connector = build_connector()

    assurance = build_deployment_assurance(connector)

    assert assurance.enabled is True
    assert assurance.reporter.hits_enabled is True
    assert isinstance(assurance.reconciler._adapter, CortexXdrDeploymentAdapter)


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


# Client read-back


def test_iter_iocs_pages_with_search_from_and_search_to(xdr_client):
    with patch.object(xdr_client._session, "request") as request:
        request.side_effect = [
            mock_response({"objects": [{"rule_id": 1}, {"rule_id": 2}]}),
            mock_response({"reply": {"objects": [{"rule_id": 3}]}}),
        ]

        iocs = list(xdr_client.iter_iocs(page_size=2))

    assert [ioc["rule_id"] for ioc in iocs] == [1, 2, 3]
    first, second = request.call_args_list
    assert first.kwargs["json"] == {
        "request_data": {"filters": [], "search_from": 0, "search_to": 2}
    }
    assert second.kwargs["json"]["request_data"]["search_from"] == 2
    assert first.kwargs["headers"]["x-xdr-auth-id"] == "1"


def test_iter_iocs_never_returns_a_partial_listing(xdr_client):
    with patch.object(xdr_client._session, "request") as request:
        request.side_effect = [
            mock_response({"objects": [{"rule_id": page}]}) for page in range(3)
        ]

        with pytest.raises(CortexXdrApiError, match="after 3 pages"):
            list(xdr_client.iter_iocs(page_size=1, max_pages=3))


def test_iter_iocs_detects_an_ignored_pagination(xdr_client):
    with patch.object(xdr_client._session, "request") as request:
        request.return_value = mock_response({"objects": [{"rule_id": 1}]})

        with pytest.raises(CortexXdrApiError, match="same IOC page twice"):
            list(xdr_client.iter_iocs(page_size=1))

    assert request.call_count == 2


@pytest.mark.parametrize(
    "response",
    [
        mock_response({"objects_count": 0}),
        mock_response({"objects": [{"rule_id": 1}, "row"]}),
        mock_response({"message": "x"}, 500),
    ],
)
def test_iter_iocs_errors(xdr_client, response):
    with patch.object(xdr_client._session, "request") as request:
        request.return_value = response
        with pytest.raises(CortexXdrApiError):
            list(xdr_client.iter_iocs())


def test_get_ioc_alerts_filters_ioc_alerts_since_a_date(xdr_client, monkeypatch):
    monkeypatch.setattr("cortex_xdr_client.client.PAGE_SIZE", 2)
    since = datetime(2026, 10, 3, 10, 0, tzinfo=UTC)
    with patch.object(xdr_client._session, "request") as request:
        request.side_effect = [
            mock_response({"reply": {"alerts": [{"alert_id": 1}, {"alert_id": 2}]}}),
            mock_response({"reply": {"alerts": [{"alert_id": 3}, {"alert_id": 4}]}}),
        ]

        alerts = xdr_client.get_ioc_alerts(since, max_alerts=3)

    assert [alert["alert_id"] for alert in alerts] == [1, 2, 3]
    first, second = request.call_args_list
    request_data = first.kwargs["json"]["request_data"]
    assert request_data["filters"] == [
        {
            "field": "creation_time",
            "operator": "gte",
            "value": int(since.timestamp() * 1000),
        },
        {"field": "alert_source", "operator": "in", "value": ["XDR IOC"]},
    ]
    assert (request_data["search_from"], request_data["search_to"]) == (0, 2)
    assert request_data["sort"] == {"field": "creation_time", "keyword": "asc"}
    assert second.kwargs["json"]["request_data"]["search_to"] == 3


def test_get_ioc_alerts_stops_on_a_short_page_and_raises_on_errors(xdr_client):
    with patch.object(xdr_client._session, "request") as request:
        request.return_value = mock_response({"reply": {"alerts": []}})
        assert xdr_client.get_ioc_alerts(datetime.now(UTC)) == []
        assert request.call_count == 1

        request.return_value = mock_response({"message": "forbidden"}, 403)
        with pytest.raises(CortexXdrApiError):
            xdr_client.get_ioc_alerts(datetime.now(UTC))

        request.return_value = mock_response({"reply": {"alerts": ["row"]}})
        with pytest.raises(CortexXdrApiError, match="row is not an object"):
            xdr_client.get_ioc_alerts(datetime.now(UTC))


# Vendor adapter


def test_adapter_lists_the_iocs_and_the_expired_ones_inactive():
    connector = build_connector()
    future = int((datetime.now(UTC) + timedelta(days=1)).timestamp() * 1000)
    past = int((datetime.now(UTC) - timedelta(days=1)).timestamp() * 1000)
    connector.client.iter_iocs.return_value = iter(
        [
            {"rule_id": 1, "indicator": "198.51.100.7", "type": "IP"},
            {
                "rule_id": 2,
                "indicator": "evil.example",
                "type": "DOMAIN_NAME",
                "expiration_date": future,
            },
            {"rule_id": 3, "indicator": "old.example", "expiration_date": past},
            {"indicator": "no-id.example", "expiration_date": True},
            {"rule_id": 6, "indicator": "far.example", "expiration_date": 10**20},
        ]
    )

    vendor_indicators = list(
        CortexXdrDeploymentAdapter(connector).list_vendor_indicators()
    )

    assert vendor_indicators == [
        VendorIndicator(external_id="1", value="198.51.100.7"),
        VendorIndicator(external_id="2", value="evil.example"),
        VendorIndicator(external_id="3", value="old.example", active=False),
        VendorIndicator(external_id=None, value="no-id.example"),
        VendorIndicator(external_id="6", value="far.example"),
    ]
    assert vendor_indicators[1].raw == {
        "indicator": "evil.example",
        "type": "DOMAIN_NAME",
    }


@pytest.mark.parametrize("value", ["", None, 7])
def test_adapter_rejects_an_ioc_without_value(value):
    connector = build_connector()
    connector.client.iter_iocs.return_value = iter([{"rule_id": 4, "indicator": value}])

    with pytest.raises(CortexXdrDeploymentError, match="IOC without value"):
        list(CortexXdrDeploymentAdapter(connector).list_vendor_indicators())


def test_adapter_read_back_errors_are_readable():
    connector = build_connector()
    connector.client.iter_iocs.side_effect = api_error(
        ApiClientError("Unauthorized", status_code=401)
    )

    with pytest.raises(CortexXdrDeploymentError, match=r"HTTP 401"):
        list(CortexXdrDeploymentAdapter(connector).list_vendor_indicators())


def test_adapter_removes_the_ioc_read_back():
    connector = build_connector()
    adapter = CortexXdrDeploymentAdapter(connector)
    deployment = make_deployment(
        pattern=f"[file:hashes.'SHA-256' = '{SHA256}' OR file:hashes.MD5 = '{MD5}']"
    )
    vendor_indicator = VendorIndicator(
        external_id="9", value=SHA256.upper(), raw={"indicator": SHA256.upper()}
    )

    adapter.remove_vendor_indicator(vendor_indicator, deployment)

    connector.client.delete_iocs.assert_called_once_with(
        [{"field": "indicator", "operator": "IN", "value": [SHA256.upper()]}]
    )

    connector.client.delete_iocs.side_effect = api_error(ValueError("refused"))
    with pytest.raises(CortexXdrDeploymentError, match="refused"):
        adapter.remove_vendor_indicator(vendor_indicator, deployment)


def test_adapter_push():
    connector = build_connector()
    adapter = CortexXdrDeploymentAdapter(connector)
    connector.client.insert_iocs.return_value = {"added_objects": [{"id": 5}]}

    assert adapter.push_indicator(make_indicator()) == "5"

    connector.client.insert_iocs.return_value = {}
    assert adapter.push_indicator(make_indicator()) is None

    indicator = make_indicator()
    del indicator["extensions"][OPENCTI_EXTENSION_ID]["observable_values"]
    with pytest.raises(ValueError, match="No observable"):
        adapter.push_indicator(indicator)


@pytest.mark.parametrize(
    "error, reason",
    [
        (
            api_error(ApiClientError("Forbidden", status_code=403)),
            "Cortex XDR refused the IOC upsert: permission denied",
        ),
        (
            api_error(ValueError("invalid")),
            "Cortex XDR returned an unexpected response to the IOC upsert",
        ),
        (
            ConnectionError("reset"),
            "Cortex XDR could not be reached for the IOC upsert",
        ),
    ],
)
def test_adapter_push_raises_the_reason_and_logs_the_detail(error, reason):
    connector = build_connector()
    connector.client.insert_iocs.side_effect = error

    with pytest.raises(CortexXdrDeploymentError) as raised:
        CortexXdrDeploymentAdapter(connector).push_indicator(make_indicator())

    assert str(raised.value) == reason
    message, meta = connector.helper.connector_logger.warning.call_args.args
    assert message == "[DEPLOYMENT] Cortex XDR did not take an indicator pushed again."
    assert meta == {
        "indicator_id": make_indicator()["id"],
        "error": describe_error(error),
    }


def test_adapter_collects_hits_from_ioc_alerts():
    connector = build_connector()
    since = datetime(2026, 10, 3, 11, 0, tzinfo=UTC)

    def at(minute):
        return int(datetime(2026, 10, 3, 11, minute, tzinfo=UTC).timestamp() * 1000)

    connector.client.get_ioc_alerts.return_value = [
        {"detection_timestamp": at(10), "action_remote_ip": "198.51.100.7"},
        {
            "local_insert_ts": at(20),
            "events": [
                {"action_external_hostname": "https://EVIL.example/payload"},
                {"action_file_sha256": SHA256.upper(), "fw_email_recipient": [None]},
                "ignored",
            ],
        },
        {"detection_timestamp": at(30), "host_ip": "198.51.100.7"},
        {"detection_timestamp": int(since.timestamp() * 1000) - 1},
    ]
    deployments = [
        make_deployment(),
        make_deployment(OTHER_ID, pattern="[domain-name:value = 'evil.example']"),
        make_deployment("hash-indicator", pattern=f"[file:hashes.MD5 = '{SHA256}']"),
    ]

    hits = list(CortexXdrDeploymentAdapter(connector).collect_hits(deployments, since))

    assert [(hit.indicator_id, hit.timestamp.minute) for hit in hits] == [
        (INDICATOR_ID, 10),
        (OTHER_ID, 20),
        ("hash-indicator", 20),
    ]
    connector.client.get_ioc_alerts.assert_called_once_with(since, 10_000)


def test_adapter_fails_the_hit_read_on_an_alert_without_creation_time():
    connector = build_connector()
    connector.client.get_ioc_alerts.return_value = [
        {"events": [{"action_remote_ip": "198.51.100.7"}]}
    ]

    with pytest.raises(CortexXdrDeploymentError, match="without creation time"):
        CortexXdrDeploymentAdapter(connector).collect_hits(
            [make_deployment()], datetime(2026, 10, 3, 11, 0, tzinfo=UTC)
        )


def test_adapter_credits_every_indicator_sharing_a_value():
    connector = build_connector()
    since = datetime(2026, 10, 3, 11, 0, tzinfo=UTC)
    detection = int(datetime(2026, 10, 3, 11, 5, tzinfo=UTC).timestamp() * 1000)
    connector.client.get_ioc_alerts.return_value = [
        {"detection_timestamp": detection, "action_remote_ip": "198.51.100.7"}
    ]

    hits = CortexXdrDeploymentAdapter(connector).collect_hits(
        [make_deployment(), make_deployment(OTHER_ID)], since
    )

    assert sorted(hit.indicator_id for hit in hits) == sorted([INDICATOR_ID, OTHER_ID])


def test_adapter_capped_read_is_complete_until_the_newest_alert(monkeypatch):
    monkeypatch.setattr("connector.deployment.MAX_HIT_ALERTS", 2)
    connector = build_connector()
    since = datetime(2026, 10, 3, 11, 0, tzinfo=UTC)

    def at(minute):
        return int(datetime(2026, 10, 3, 11, minute, tzinfo=UTC).timestamp() * 1000)

    connector.client.get_ioc_alerts.return_value = [
        {
            "local_insert_ts": at(5),
            "detection_timestamp": at(20),
            "action_remote_ip": "198.51.100.7",
        },
        {
            "local_insert_ts": at(9),
            "detection_timestamp": at(8),
            "action_remote_ip": "203.0.113.9",
        },
    ]

    collected = CortexXdrDeploymentAdapter(connector).collect_hits(
        [make_deployment()], since
    )

    assert isinstance(collected, HitCollection)
    assert collected.complete_until == datetime(2026, 10, 3, 11, 9, tzinfo=UTC)
    assert [(hit.indicator_id, hit.timestamp.minute) for hit in collected.hits] == [
        (INDICATOR_ID, 5)
    ]
    assert connector.client.get_ioc_alerts.call_args.args == (since, 2)


def test_adapter_counts_alerts_created_in_the_window_but_detected_before():
    connector = build_connector()
    since = datetime(2026, 10, 3, 11, 0, tzinfo=UTC)
    connector.client.get_ioc_alerts.return_value = [
        {
            "local_insert_ts": int(
                datetime(2026, 10, 3, 11, 2, tzinfo=UTC).timestamp() * 1000
            ),
            "detection_timestamp": int(
                datetime(2026, 10, 3, 10, 40, tzinfo=UTC).timestamp() * 1000
            ),
            "action_remote_ip": "198.51.100.7",
        }
    ]

    hits = CortexXdrDeploymentAdapter(connector).collect_hits(
        [make_deployment()], since
    )

    assert [(hit.indicator_id, hit.timestamp.minute) for hit in hits] == [
        (INDICATOR_ID, 2)
    ]


def test_adapter_capped_read_without_creation_time_uses_the_detection(monkeypatch):
    monkeypatch.setattr("connector.deployment.MAX_HIT_ALERTS", 2)
    connector = build_connector()
    since = datetime(2026, 10, 3, 11, 0, tzinfo=UTC)
    detection = int(datetime(2026, 10, 3, 11, 7, tzinfo=UTC).timestamp() * 1000)
    connector.client.get_ioc_alerts.return_value = [
        {"detection_timestamp": detection, "action_remote_ip": "198.51.100.7"},
        {"detection_timestamp": detection - 60_000, "severity": "high"},
    ]

    collected = CortexXdrDeploymentAdapter(connector).collect_hits(
        [make_deployment()], since
    )

    assert collected.complete_until == datetime(2026, 10, 3, 11, 7, tzinfo=UTC)
    assert [hit.indicator_id for hit in collected.hits] == [INDICATOR_ID]


def test_adapter_hits_without_values_read_no_alert():
    connector = build_connector()
    deployment = IndicatorDeployment(
        relationship_id="r", status="deployed", indicator_id=INDICATOR_ID
    )

    adapter = CortexXdrDeploymentAdapter(connector)

    assert adapter.collect_hits([deployment], datetime.now(UTC)) == []
    connector.client.get_ioc_alerts.assert_not_called()


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


def deployment_node(indicator_id, status, value):
    return {
        "id": f"relationship-{indicator_id}",
        "deployment_status": status,
        "external_id": None,
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
    helper = make_helper(spec=["api", "connector_logger", "listen_stream"])
    helper.get_attribute_in_extension = (
        OpenCTIConnectorHelper.get_attribute_in_extension
    )
    helper.api.query.side_effect = router
    connector = build_connector(helper=helper)
    connector.assurance = DeploymentAssurance.from_settings(
        helper,
        connector.settings,
        adapter=CortexXdrDeploymentAdapter(connector),
        reporter_kwargs={"flush_interval": 3600.0},
    )
    return connector


def test_stream_outcomes_are_reported_in_one_batch(e2e_connector, router):
    e2e_connector.client.insert_iocs.side_effect = [
        {"added_objects": [{"id": 11}]},
        api_error(ApiClientError("Bad request", status_code=400)),
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
                "name": "Palo Alto Cortex XDR",
                "update": True,
                "security_platform_type": "XDR",
            }
        }
    ]
    (batch,) = router.calls_of("IndicatorReportDeployments(")
    deployed, failed = batch["reports"]
    assert deployed == {
        "indicatorId": INDICATOR_ID,
        "status": "deployed",
        "externalId": "11",
    }
    assert failed["indicatorId"] == OTHER_ID
    assert failed["status"] == "failed"
    assert failed["metadata"]["error_message"] == (
        "Cortex XDR refused the IOC upsert: invalid request"
    )


def test_reconciliation_and_hits_are_reported(e2e_connector, router):
    router.deployments = [
        deployment_node(INDICATOR_ID, "deployed", "198.51.100.7"),
        deployment_node(OTHER_ID, "active", "203.0.113.9"),
    ]
    alert_time = int((datetime.now(UTC) - timedelta(minutes=5)).timestamp() * 1000)
    e2e_connector.client = CortexXdrClient(
        HttpUrl("https://api-test.com"), "1", "secret"
    )
    with patch.object(e2e_connector.client._session, "request") as request:
        request.side_effect = [
            mock_response(
                {
                    "objects": [
                        {"rule_id": 77, "indicator": "198.51.100.7", "type": "IP"}
                    ]
                }
            ),
            mock_response(
                {
                    "reply": {
                        "alerts": [
                            {
                                "detection_timestamp": alert_time,
                                "events": [{"action_remote_ip": "198.51.100.7"}],
                            }
                        ]
                    }
                }
            ),
        ]

        summary = e2e_connector.assurance.reconciler.run_once()

    assert summary.skipped is False
    assert summary.confirmed_active == 1
    assert summary.marked_removed == 1
    assert summary.hits_reported == 1
    (batch,) = router.calls_of("IndicatorReportDeployments(")
    reports = {report["indicatorId"]: report for report in batch["reports"]}
    assert reports[INDICATOR_ID]["status"] == "active"
    assert reports[INDICATOR_ID]["externalId"] == "77"
    assert reports[OTHER_ID]["status"] == "removed"
    (hits,) = router.calls_of("IndicatorReportHits(")
    assert hits["indicatorId"] == INDICATOR_ID
    assert hits["count"] == 1


FILE_PATTERN = f"[file:hashes.'SHA-256' = '{SHA256}' OR file:hashes.MD5 = '{MD5}']"


def file_deployment_node(indicator_id, pattern, revoked=False):
    node = deployment_node(indicator_id, "active", "unused")
    node["revoked"] = revoked
    node["from"]["pattern"] = pattern
    return node


def test_adapter_expects_one_ioc_per_pushed_value():
    adapter = CortexXdrDeploymentAdapter(build_connector())

    assert adapter.expected_values(
        make_deployment(
            pattern=(
                f"[file:hashes.'SHA-256' = '{SHA256.upper()}' OR file:name = 'x.exe'"
                " OR domain-name:value = 'Evil.Example'"
                " OR email-addr:value = 'a@evil.example'"
                " OR url:value = 'http://evil.example/a' OR ipv4-addr:value = '1.2.3.4']"
            )
        )
    ) == {SHA256, "evil.example", "a@evil.example", "http://evil.example/a", "1.2.3.4"}
    assert (
        adapter.expected_values(make_deployment(pattern="[file:name = 'x.exe']"))
        is None
    )


def test_reconciliation_pushes_again_an_indicator_missing_an_ioc(e2e_connector, router):
    router.deployments = [file_deployment_node(INDICATOR_ID, FILE_PATTERN)]
    e2e_connector.client.iter_iocs.return_value = [
        {"rule_id": 5, "indicator": MD5, "type": "HASH"}
    ]
    exported = make_indicator()
    exported["pattern"] = FILE_PATTERN
    exported["extensions"][OPENCTI_EXTENSION_ID]["observable_values"] = [
        {"type": "StixFile", "hashes": {"SHA-256": SHA256, "MD5": MD5}}
    ]
    e2e_connector.helper.api.stix2.get_stix_bundle_or_object_from_entity_id.return_value = (
        exported
    )
    e2e_connector.client.get_iocs.return_value = {
        "objects": [{"rule_id": 5, "indicator": MD5, "type": "HASH"}]
    }
    e2e_connector.client.insert_iocs.return_value = {
        "added_objects": [{"id": 6}],
        "updated_objects": [{"id": 5}],
    }

    summary = e2e_connector.assurance.reconciler.run_once()

    assert (summary.incomplete, summary.repushed, summary.confirmed_active) == (
        1,
        1,
        0,
    )
    (pushed,) = e2e_connector.client.insert_iocs.call_args.args
    assert sorted(ioc["indicator"] for ioc in pushed) == sorted([SHA256, MD5])
    (batch,) = router.calls_of("IndicatorReportDeployments(")
    (report,) = batch["reports"]
    assert report["status"] == "deployed"
    assert report["externalId"] == "6"


def test_reconciliation_withdrawal_keeps_the_iocs_of_live_indicators(
    e2e_connector, router
):
    router.deployments = [
        file_deployment_node(INDICATOR_ID, FILE_PATTERN, revoked=True),
        file_deployment_node(OTHER_ID, f"[file:hashes.MD5 = '{MD5}']"),
    ]
    e2e_connector.client.iter_iocs.return_value = [
        {"rule_id": 5, "indicator": MD5, "type": "HASH"},
        {"rule_id": 6, "indicator": SHA256, "type": "HASH"},
    ]

    summary = e2e_connector.assurance.reconciler.run_once()

    e2e_connector.client.delete_iocs.assert_called_once_with(
        [{"field": "indicator", "operator": "IN", "value": [SHA256]}]
    )
    assert summary.withdrawn == 1
    assert summary.confirmed_active == 1
    (batch,) = router.calls_of("IndicatorReportDeployments(")
    reports = {report["indicatorId"]: report["status"] for report in batch["reports"]}
    assert reports == {INDICATOR_ID: "removed", OTHER_ID: "active"}


def test_read_back_failure_skips_the_reconciliation(e2e_connector, router):
    router.deployments = [deployment_node(INDICATOR_ID, "active", "198.51.100.7")]
    e2e_connector.client.iter_iocs.side_effect = api_error(
        ApiServerError("Unavailable", status_code=503)
    )

    summary = e2e_connector.assurance.reconciler.run_once()

    assert summary.skipped is True
    assert "Unavailable" in summary.reason
    assert router.calls_of("IndicatorReportDeployments(") == []

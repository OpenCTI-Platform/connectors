"""Deployment write-back of the Zscaler connector."""

import json
from dataclasses import replace
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock

import pytest
import requests
from connectors_sdk import (
    DeploymentAssurance,
    DeploymentReconciler,
    IndicatorDeployment,
)
from connectors_sdk.connectors.stream.deployment import VendorIndicator
from pycti import OpenCTIConnectorHelper
from stream_connector import ZscalerConnector
from stream_connector.connector import ZscalerActivationPendingError, ZscalerApiError
from stream_connector.deployment import (
    ZscalerDeploymentAdapter,
    ZscalerDeploymentError,
    build_deployment_assurance,
)
from stream_connector.settings import ConnectorSettings

OPENCTI_EXTENSION_ID = "extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba"
PLATFORM_ID = "6c3b0f4e-2d41-4a77-8f0d-3e1c9b5a7d21"
INDICATOR_ID = "0d8b4f0e-6a43-4f11-8f6c-1d2f5e6a7b8c"
OTHER_ID = "1e9c5f1f-7b54-4a22-9e7d-2e3f6a7b8c9d"
CATEGORY_URL = "https://zsapi.zscalertwo.net/api/v1/urlCategories/blacklist"


def make_settings(**namespaces: dict[str, Any]) -> ConnectorSettings:
    """Build connector settings from a valid configuration and overrides."""
    config = {
        "opencti": {"url": "http://localhost:8080", "token": "test-token"},
        "connector": {"live_stream_id": "live"},
        "zscaler": {"username": "user", "password": "pass", "api_key": "key"},
    }
    for namespace, values in namespaces.items():
        config[namespace] = {**config.get(namespace, {}), **values}

    class StubConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(config)

    return StubConnectorSettings()


def make_indicator(indicator_id=INDICATOR_ID, domain="evil.example"):
    return {
        "id": "indicator--5d4f2a3b-8c9d-4e1f-a2b3-c4d5e6f7a8b9",
        "type": "indicator",
        "spec_version": "2.1",
        "name": domain,
        "pattern": f"[domain-name:value = '{domain}']",
        "pattern_type": "stix",
        "extensions": {
            OPENCTI_EXTENSION_ID: {"id": indicator_id, "type": "Indicator", "score": 80}
        },
    }


def make_message(event, data):
    return SimpleNamespace(event=event, data=json.dumps({"data": data}), id="1-0")


def response(status_code=200, json_data=None, text=None, headers=None):
    mock = MagicMock()
    mock.status_code = status_code
    if isinstance(json_data, Exception):
        mock.json.side_effect = json_data
    else:
        mock.json.return_value = json_data
    mock.text = text if text is not None else json.dumps(json_data)
    mock.headers = headers or {}
    return mock


class FakeZscaler:
    """In-memory blacklist URL category served through a mocked session."""

    def __init__(self, urls=(), put_status=200, get_status=200):
        self.urls = list(urls)
        self.put_status = put_status
        self.get_status = get_status
        self.puts = []

    def get(self, url, *args, **kwargs):
        if self.get_status != 200:
            return response(self.get_status, text="category unavailable")
        return response(
            json_data={
                "id": "blacklist",
                "configuredName": "Blacklist",
                "urls": self.urls,
            }
        )

    def post(self, url, *args, **kwargs):
        return response(json_data=[{"urlClassifications": ["MISCELLANEOUS"]}])

    def put(self, url, json=None, **kwargs):
        self.puts.append((url, json))
        if self.put_status != 200:
            return response(self.put_status, text="INVALID_INPUT_ARGUMENT")
        for domain in json["urls"]:
            if url.endswith("ADD_TO_LIST"):
                self.urls.append(domain)
            else:
                self.urls.remove(domain)
        return response(json_data={})

    def install(self, connector):
        connector.session = MagicMock()
        connector.session.get.side_effect = self.get
        connector.session.post.side_effect = self.post
        connector.session.put.side_effect = self.put
        return self


def make_helper(spec: list[str] | None = None) -> MagicMock:
    helper = MagicMock(spec=spec) if spec is not None else MagicMock()
    helper.get_attribute_in_extension = (
        OpenCTIConnectorHelper.get_attribute_in_extension
    )
    return helper


def build_connector(helper=None, assurance=None):
    connector = ZscalerConnector(
        helper=helper or make_helper(),
        ssl_verify=False,
        zscaler_username="user",
        zscaler_password="pass",
        zscaler_api_key="key",
        zscaler_blacklist_name="blacklist",
    )
    connector.activate_zscaler_changes = MagicMock(return_value=True)
    connector.assurance = assurance
    return connector


def make_deployment(indicator_id=INDICATOR_ID, domain="evil.example", **fields):
    return IndicatorDeployment(
        relationship_id=f"relationship-{indicator_id}",
        status=fields.pop("status", "deployed"),
        indicator_id=indicator_id,
        pattern=f"[domain-name:value = '{domain}']",
        pattern_type="stix",
        **fields,
    )


@pytest.fixture(name="connector")
def fixture_connector():
    return build_connector(assurance=MagicMock(spec=DeploymentAssurance))


@pytest.fixture(name="no_atexit")
def fixture_no_atexit(monkeypatch):
    """Do not register the exit flush of the deployment reporter during tests."""
    monkeypatch.setattr(
        "connectors_sdk.connectors.stream.deployment.reporter.atexit.register",
        lambda _handler: None,
    )


@pytest.fixture(autouse=True)
def no_sleep(monkeypatch):
    monkeypatch.setattr("stream_connector.connector.time.sleep", lambda _: None)


# Stream path


def test_created_domain_is_added_and_reported_deployed(connector):
    zscaler = FakeZscaler().install(connector)
    indicator = make_indicator()

    connector._process_message(make_message("create", indicator))

    assert zscaler.puts == [
        (
            f"{CATEGORY_URL}?action=ADD_TO_LIST",
            {"configuredName": "Blacklist", "urls": ["evil.example"]},
        )
    ]
    connector.assurance.report_pushed.assert_called_once_with(indicator)
    connector.activate_zscaler_changes.assert_called_once()


def test_already_listed_domain_is_activated_then_reported_deployed(connector):
    zscaler = FakeZscaler(urls=["evil.example"]).install(connector)
    indicator = make_indicator()

    connector._process_message(make_message("create", indicator))

    assert zscaler.puts == []
    connector.activate_zscaler_changes.assert_called_once()
    connector.assurance.report_pushed.assert_called_once_with(indicator)


def test_already_listed_domain_still_pending_is_reported_failed(connector):
    zscaler = FakeZscaler(urls=["evil.example"]).install(connector)
    connector.activate_zscaler_changes.return_value = False
    indicator = make_indicator()

    connector._process_message(make_message("create", indicator))

    assert zscaler.puts == []
    connector.assurance.report_pushed.assert_not_called()
    (reported, _error), _ = connector.assurance.report_push_failed.call_args
    assert reported == indicator


def test_refused_domain_is_reported_failed(connector):
    FakeZscaler(put_status=400).install(connector)
    indicator = make_indicator()

    connector._process_message(make_message("create", indicator))

    (reported, error), _ = connector.assurance.report_push_failed.call_args
    assert reported == indicator
    assert error == "Zscaler refused the blacklist update: invalid request"
    connector.assurance.report_pushed.assert_not_called()
    connector.helper.connector_logger.error.assert_any_call(
        "Failed to send create event: "
        "Request failed with status 400: INVALID_INPUT_ARGUMENT"
    )


@pytest.mark.parametrize(
    "category",
    [
        response(json_data=ValueError("no json"), text="<html>"),
        response(json_data=["evil.example"]),
        response(json_data={"id": "blacklist", "urls": "evil.example.org"}),
    ],
)
def test_malformed_blacklist_on_create_is_reported_failed(connector, category):
    zscaler = FakeZscaler().install(connector)
    connector.session.get.side_effect = None
    connector.session.get.return_value = category
    indicator = make_indicator()

    connector._process_message(make_message("create", indicator))

    (reported, error), _ = connector.assurance.report_push_failed.call_args
    assert reported == indicator
    assert error == "Zscaler returned an unexpected response to the blacklist read"
    assert zscaler.puts == []
    connector.assurance.report_pushed.assert_not_called()


def test_malformed_configured_name_read_on_create_is_reported_failed(connector):
    zscaler = FakeZscaler().install(connector)
    connector.session.get.side_effect = [
        response(json_data={"id": "blacklist", "configuredName": "Blacklist"}),
        response(json_data=[]),
    ]
    indicator = make_indicator()

    connector._process_message(make_message("create", indicator))

    (reported, error), _ = connector.assurance.report_push_failed.call_args
    assert reported == indicator
    assert error == "Zscaler returned an unexpected response to the blacklist read"
    assert zscaler.puts == []


@pytest.mark.parametrize("failed_read", [0, 1])
def test_failed_category_read_on_create_stops_the_change(connector, failed_read):
    """Neither the blacklist read nor the configured name read lets a change through."""
    zscaler = FakeZscaler().install(connector)
    reads = [
        response(json_data={"id": "blacklist", "configuredName": "Blacklist"}),
        response(json_data={"id": "blacklist", "configuredName": "Blacklist"}),
    ]
    reads[failed_read] = response(status_code=503, text="Unavailable")
    connector.session.get.side_effect = reads
    indicator = make_indicator()

    connector._process_message(make_message("create", indicator))

    (reported, error), _ = connector.assurance.report_push_failed.call_args
    assert reported == indicator
    assert error == "Zscaler refused the blacklist read: server error"
    assert zscaler.puts == []
    connector.assurance.report_pushed.assert_not_called()


@pytest.mark.parametrize(
    "lookup",
    [
        response(json_data=ValueError("no json"), text="<html>"),
        response(json_data=["MISCELLANEOUS"]),
    ],
)
def test_unreadable_classification_does_not_block_the_create(connector, lookup):
    zscaler = FakeZscaler().install(connector)
    connector.session.post.side_effect = None
    connector.session.post.return_value = lookup
    indicator = make_indicator()

    connector._process_message(make_message("create", indicator))

    assert [url for url, _payload in zscaler.puts] == [
        f"{CATEGORY_URL}?action=ADD_TO_LIST"
    ]
    connector.assurance.report_pushed.assert_called_once_with(indicator)
    connector.helper.connector_logger.error.assert_any_call(
        "Failed to lookup domain evil.example in Zscaler."
    )


def test_deleted_domain_is_removed_and_reported(connector):
    zscaler = FakeZscaler(urls=["evil.example", "other.example"]).install(connector)
    indicator = make_indicator()

    connector._process_message(make_message("delete", indicator))

    assert zscaler.puts == [
        (
            f"{CATEGORY_URL}?action=REMOVE_FROM_LIST",
            {"configuredName": "Blacklist", "urls": ["evil.example"]},
        )
    ]
    assert zscaler.urls == ["other.example"]
    connector.assurance.report_removed.assert_called_once_with(indicator)


def test_deleted_domain_blocked_by_another_indicator_stays_listed(connector):
    zscaler = FakeZscaler(urls=["evil.example"]).install(connector)
    connector.helper.api.indicator.list.return_value = [
        {
            "id": OTHER_ID,
            "standard_id": "indicator--other",
            "pattern": "[domain-name:value = 'evil.example']",
        }
    ]
    indicator = make_indicator()

    connector._process_message(make_message("delete", indicator))

    assert zscaler.puts == []
    assert zscaler.urls == ["evil.example"]
    connector.assurance.report_removed.assert_called_once_with(indicator)
    connector.helper.api.indicator.list.assert_called_once_with(
        filters={
            "mode": "and",
            "filters": [
                {
                    "key": "pattern",
                    "values": ["'evil.example'"],
                    "operator": "contains",
                },
                {"key": "revoked", "values": ["false"]},
            ],
            "filterGroups": [],
        },
        getAll=True,
    )


def test_deleted_domain_blocked_by_another_indicator_with_another_casing_stays_listed(
    connector,
):
    zscaler = FakeZscaler(urls=["evil.example"]).install(connector)
    connector.helper.api.indicator.list.return_value = [
        {
            "id": OTHER_ID,
            "standard_id": "indicator--other",
            "pattern": "[domain-name:value = 'Evil.EXAMPLE']",
        }
    ]
    indicator = make_indicator()

    connector._process_message(make_message("delete", indicator))

    assert zscaler.puts == []
    assert zscaler.urls == ["evil.example"]
    connector.assurance.report_removed.assert_called_once_with(indicator)


def test_deleted_indicator_and_other_patterns_do_not_keep_the_domain(connector):
    zscaler = FakeZscaler(urls=["evil.example"]).install(connector)
    indicator = make_indicator()
    connector.helper.api.indicator.list.return_value = [
        {
            "id": INDICATOR_ID,
            "standard_id": "indicator--deleted",
            "pattern": "[domain-name:value = 'evil.example']",
        },
        {
            "id": "other-internal-id",
            "standard_id": indicator["id"].upper(),
            "pattern": "[domain-name:value = 'evil.example']",
        },
        {
            "id": OTHER_ID,
            "standard_id": "indicator--other",
            "pattern": "[email-addr:value = 'evil.example']",
        },
    ]

    connector._process_message(make_message("delete", indicator))

    assert zscaler.urls == []
    connector.assurance.report_removed.assert_called_once_with(indicator)


def test_delete_without_the_other_indicators_is_not_applied(connector):
    zscaler = FakeZscaler(urls=["evil.example"]).install(connector)
    connector.helper.api.indicator.list.side_effect = RuntimeError("OpenCTI down")

    connector._process_message(make_message("delete", make_indicator()))

    assert zscaler.puts == []
    connector.assurance.report_removed.assert_not_called()
    connector.helper.connector_logger.error.assert_called_with(
        "Failed to send delete event: Cannot read the OpenCTI indicators of "
        "evil.example: OpenCTI down"
    )


def test_expired_indicators_do_not_keep_a_deleted_domain(connector):
    zscaler = FakeZscaler(urls=["evil.example"]).install(connector)
    connector.helper.api.indicator.list.return_value = [
        {
            "id": OTHER_ID,
            "standard_id": "indicator--other",
            "pattern": "[domain-name:value = 'evil.example']",
            "valid_until": "2020-01-01T00:00:00.000Z",
        }
    ]
    indicator = make_indicator()

    connector._process_message(make_message("delete", indicator))

    assert zscaler.urls == []
    connector.assurance.report_removed.assert_called_once_with(indicator)


def test_deleted_domain_kept_for_an_indicator_valid_in_the_future(connector):
    zscaler = FakeZscaler(urls=["evil.example"]).install(connector)
    connector.helper.api.indicator.list.return_value = [
        {
            "id": OTHER_ID,
            "standard_id": "indicator--other",
            "pattern": "[domain-name:value = 'evil.example']",
            "valid_until": "2999-01-01T00:00:00.000Z",
        }
    ]

    connector._process_message(make_message("delete", make_indicator()))

    assert zscaler.urls == ["evil.example"]


def test_adapter_removes_the_domain_without_looking_up_other_indicators(connector):
    zscaler = FakeZscaler(urls=["evil.example"]).install(connector)

    ZscalerDeploymentAdapter(connector).remove_vendor_indicator(
        VendorIndicator(value="evil.example", raw={"domain": "evil.example"}),
        make_deployment(),
    )

    assert zscaler.urls == []
    connector.helper.api.indicator.list.assert_not_called()


def test_deleted_domain_already_absent_is_reported_removed(connector):
    zscaler = FakeZscaler(urls=["other.example"]).install(connector)
    indicator = make_indicator()

    connector._process_message(make_message("delete", indicator))

    assert zscaler.puts == []
    connector.assurance.report_removed.assert_called_once_with(indicator)


def test_delete_with_an_unreadable_blacklist_is_not_reported(connector):
    zscaler = FakeZscaler(urls=["evil.example"], get_status=500).install(connector)

    connector._process_message(make_message("delete", make_indicator()))

    assert zscaler.puts == []
    connector.assurance.report_removed.assert_not_called()
    connector.assurance.report_push_failed.assert_not_called()


def test_invalid_domain_is_not_reported(connector):
    zscaler = FakeZscaler().install(connector)

    connector._process_message(
        make_message("create", make_indicator(domain="not a domain"))
    )

    assert zscaler.puts == []
    connector.assurance.report_pushed.assert_not_called()
    connector.assurance.report_push_failed.assert_not_called()


def test_non_stix_indicators_and_other_events_are_ignored(connector):
    zscaler = FakeZscaler().install(connector)

    connector._process_message(make_message("create", {"type": "malware"}))
    connector._process_message(make_message("update", make_indicator()))

    assert zscaler.puts == []
    connector.assurance.report_pushed.assert_not_called()


def test_unsupported_event_type_is_not_applied(connector):
    FakeZscaler().install(connector)

    assert (
        connector.check_and_send_to_zscaler(
            {"pattern": "[domain-name:value = 'evil.example']"}, "update"
        )
        is None
    )


def test_connector_works_without_write_back():
    connector = build_connector()
    zscaler = FakeZscaler(urls=["gone.example"]).install(connector)

    connector._process_message(make_message("create", make_indicator()))
    connector._process_message(
        make_message("delete", make_indicator(domain="gone.example"))
    )
    zscaler.put_status = 400
    connector._process_message(
        make_message("create", make_indicator(domain="refused.example"))
    )

    assert zscaler.urls == ["evil.example"]


def test_start_starts_the_write_back_before_listening(connector):
    order = []
    connector.assurance.start.side_effect = lambda: order.append("assurance")
    connector.helper.listen_stream.side_effect = lambda _: order.append("stream")

    connector.start()

    assert order == ["assurance", "stream"]


def test_push_indicator(connector):
    zscaler = FakeZscaler().install(connector)

    assert connector.push_indicator(make_indicator()) is None
    assert zscaler.urls == ["evil.example"]

    with pytest.raises(ValueError, match="not a valid domain"):
        connector.push_indicator(make_indicator(domain="not a domain"))


# Requests


def test_request_without_response_raises(connector):
    connector.session = MagicMock()
    connector.session.get.return_value = None

    with pytest.raises(ZscalerApiError, match="No response"):
        connector.request_zscaler(connector.session.get, CATEGORY_URL)
    assert connector.handle_rate_limit(connector.session.get, CATEGORY_URL) is None


def test_throttled_request_is_retried_after_retry_after(connector, monkeypatch):
    sleeps = []
    monkeypatch.setattr("stream_connector.connector.time.sleep", sleeps.append)
    connector.session = MagicMock()
    connector.session.get.side_effect = [
        response(429, text="slow down", headers={"Retry-After": "3"}),
        response(json_data={"id": 1}),
    ]

    assert connector.request_zscaler(connector.session.get, CATEGORY_URL).json() == {
        "id": 1
    }
    assert sleeps == [3]


def test_retry_after_date_falls_back_to_the_default_delay(connector, monkeypatch):
    sleeps = []
    monkeypatch.setattr("stream_connector.connector.time.sleep", sleeps.append)
    connector.session = MagicMock()
    connector.session.get.side_effect = [
        response(429, headers={"Retry-After": "Wed, 21 Oct 2026 07:28:00 GMT"}),
        response(json_data={"id": 1}),
    ]

    connector.request_zscaler(connector.session.get, CATEGORY_URL)

    assert sleeps == [connector.retry_delay]


def test_persistent_throttling_raises(connector):
    connector.session = MagicMock()
    connector.session.get.return_value = response(429, text="slow down")

    with pytest.raises(ZscalerApiError, match="Max retries reached"):
        connector.request_zscaler(connector.session.get, CATEGORY_URL)
    assert connector.session.get.call_count == 3


def test_failed_re_authentication_raises(connector, monkeypatch):
    monkeypatch.setattr(connector, "authenticate_with_zscaler", lambda: None)
    connector.session = MagicMock()
    connector.session.cookies = {}
    connector.session.get.return_value = response(401, text="SESSION_NOT_VALID")

    with pytest.raises(ZscalerApiError, match="Re-authentication"):
        connector.request_zscaler(connector.session.get, CATEGORY_URL)


def test_rejected_credentials_do_not_recurse(connector, monkeypatch):
    monkeypatch.setattr(
        "stream_connector.connector.obfuscate_api_key", lambda key, ts: "obfuscated"
    )
    connector.session = MagicMock()
    connector.session.cookies = {}
    connector.session.post.return_value = response(401, text="INVALID_CREDENTIALS")

    connector.authenticate_with_zscaler()

    assert connector.session.post.call_count == 1
    connector.helper.connector_logger.error.assert_any_call(
        "Failed to authenticate with Zscaler: No response - No text"
    )


def test_transport_errors_are_readable_zscaler_errors(connector):
    connector.session = MagicMock()
    connector.session.get.side_effect = requests.ConnectionError("connection reset")

    with pytest.raises(ZscalerApiError, match="connection reset"):
        connector.request_zscaler(connector.session.get, CATEGORY_URL)
    assert connector.handle_rate_limit(connector.session.get, CATEGORY_URL) is None


def test_transport_error_on_create_is_reported_failed(connector):
    FakeZscaler().install(connector)
    connector.session.put.side_effect = requests.Timeout("timed out")
    indicator = make_indicator()

    connector._process_message(make_message("create", indicator))

    (reported, error), _ = connector.assurance.report_push_failed.call_args
    assert reported == indicator
    assert error == "Zscaler could not be reached for the blacklist update"


@pytest.mark.parametrize(
    "activation, reason",
    [
        (
            {"return_value": False},
            "Zscaler did not complete the configuration activation in time",
        ),
        (
            {
                "side_effect": ZscalerApiError(
                    "Activation failed: 500 boom",
                    status_code=500,
                    action="configuration activation",
                )
            },
            "Zscaler refused the configuration activation: server error",
        ),
        (
            {"side_effect": requests.ConnectionError("reset")},
            "Zscaler could not be reached for the configuration activation",
        ),
    ],
)
def test_activation_failure_is_reported_failed(connector, activation, reason):
    FakeZscaler().install(connector)
    connector.activate_zscaler_changes = MagicMock(**activation)
    indicator = make_indicator()

    connector._apply_and_report(indicator, "create")

    (reported, error), _ = connector.assurance.report_push_failed.call_args
    assert reported == indicator
    assert error == reason
    connector.assurance.report_pushed.assert_not_called()


def activate(connector, statuses, activations, max_retries=5):
    """Run the activation (without the tenacity retry) against scripted responses."""
    connector.session = MagicMock()
    connector.session.get.side_effect = [
        response(json_data={"status": status}) for status in statuses
    ]
    connector.session.post.side_effect = activations
    return ZscalerConnector.activate_zscaler_changes.__wrapped__(
        connector, max_retries=max_retries, delay=0
    )


def test_pending_changes_are_activated(connector):
    assert activate(connector, ["PENDING"], [response(json_data={"status": "ACTIVE"})])
    connector.session.post.assert_called_once()


def test_activation_in_progress_is_waited_for(connector):
    assert activate(
        connector,
        ["PENDING", "INPROGRESS", "ACTIVE"],
        [response(json_data={"status": "INPROGRESS"})],
    )
    assert connector.session.get.call_count == 3
    connector.session.post.assert_called_once()


def test_configuration_already_active_is_not_activated(connector):
    assert activate(connector, ["ACTIVE"], [])
    connector.session.post.assert_not_called()


def test_activation_never_completing_is_a_failure(connector):
    assert not activate(connector, ["INPROGRESS", "INPROGRESS"], [], max_retries=2)
    connector.helper.connector_logger.error.assert_called_with(
        "Zscaler configuration still not active after all checks."
    )


def test_unreadable_status_and_busy_zscaler_are_retried(connector):
    connector.session = MagicMock()
    connector.session.get.side_effect = [
        response(503, text="busy"),
        response(json_data=ValueError("not JSON"), text="<html>"),
        response(json_data=ValueError("not JSON"), text="<html>"),
    ]
    connector.session.post.side_effect = [
        response(503, json_data={"message": "busy"}),
        response(503, json_data=ValueError("not JSON"), text="busy"),
    ]

    assert not ZscalerConnector.activate_zscaler_changes.__wrapped__(
        connector, max_retries=3, delay=0
    )
    assert connector.session.get.call_count == 3
    assert connector.session.post.call_count == 2


def test_activation_renews_an_expired_session(connector):
    connector.session = MagicMock()
    connector.authenticate_with_zscaler = MagicMock()
    connector.session.get.side_effect = [
        response(401, text="SESSION_NOT_VALID"),
        response(json_data={"status": "ACTIVE"}),
    ]

    assert ZscalerConnector.activate_zscaler_changes.__wrapped__(
        connector, max_retries=1, delay=0
    )
    connector.authenticate_with_zscaler.assert_called_once_with()


@pytest.mark.parametrize(
    "activation, message, status_code",
    [
        (response(403, text="forbidden"), "status 403: forbidden", 403),
        (None, "No response from Zscaler", None),
    ],
)
def test_refused_activation_raises(connector, activation, message, status_code):
    with pytest.raises(ZscalerApiError, match=message) as error:
        activate(connector, ["PENDING"], [activation])
    assert error.value.status_code == status_code
    assert error.value.action == "configuration activation"


def test_rejected_request_message_is_truncated(connector):
    connector.session = MagicMock()
    connector.session.put.return_value = response(500, text="x" * 2000)

    with pytest.raises(ZscalerApiError) as error:
        connector.request_zscaler(connector.session.put, CATEGORY_URL)
    assert str(error.value) == f"Request failed with status 500: {'x' * 500}"


def test_list_blocked_domains(connector):
    connector.session = MagicMock()
    connector.session.get.side_effect = [
        response(json_data={"id": "blacklist", "urls": ["a.example"]}),
        response(json_data={"id": "blacklist", "configuredName": "Blacklist"}),
    ]

    assert connector.list_blocked_domains() == ["a.example"]
    assert connector.list_blocked_domains() == []


@pytest.mark.parametrize(
    "reply, message",
    [
        (response(json_data=ValueError("no json"), text="<html>"), "not JSON"),
        (response(json_data=["a.example"]), "not a URL category"),
        (response(json_data={"message": "error"}), "not a URL category"),
        (response(json_data={"id": "blacklist", "urls": "a"}), "'urls' is not a list"),
        (
            response(json_data={"id": "blacklist", "urls": ["a.example", 42]}),
            "'urls' is not a list of URL entries",
        ),
        (
            response(json_data={"id": "blacklist", "urls": ["a.example", ""]}),
            "'urls' is not a list of URL entries",
        ),
        (response(403, text="Forbidden"), "status 403: Forbidden"),
    ],
)
def test_list_blocked_domains_errors(connector, reply, message):
    connector.session = MagicMock()
    connector.session.get.return_value = reply

    with pytest.raises(ZscalerApiError, match=message):
        connector.list_blocked_domains()


# Adapter


def test_adapter_lists_removes_and_pushes(connector):
    zscaler = FakeZscaler(urls=["evil.example", "other.example"]).install(connector)
    adapter = ZscalerDeploymentAdapter(connector)

    indicators = list(adapter.list_vendor_indicators())
    assert indicators == [
        VendorIndicator(value="evil.example"),
        VendorIndicator(value="other.example"),
    ]

    adapter.remove_vendor_indicator(indicators[0], make_deployment())
    assert zscaler.urls == ["other.example"]

    assert adapter.push_indicator(make_indicator(domain="new.example")) is None
    assert zscaler.urls == ["other.example", "new.example"]


def test_adapter_reads_back_only_an_active_configuration(connector):
    FakeZscaler(urls=["evil.example"]).install(connector)
    adapter = ZscalerDeploymentAdapter(connector)

    assert list(adapter.list_vendor_indicators()) == [
        VendorIndicator(value="evil.example")
    ]
    connector.activate_zscaler_changes.assert_called_once()

    # Changes staged but not active: no listing, so no domain is confirmed
    connector.activate_zscaler_changes.return_value = False
    with pytest.raises(ZscalerActivationPendingError):
        list(adapter.list_vendor_indicators())


def test_adapter_push_of_a_listed_domain_activates_it_again(connector):
    zscaler = FakeZscaler(urls=["new.example"]).install(connector)

    assert (
        ZscalerDeploymentAdapter(connector).push_indicator(
            make_indicator(domain="new.example")
        )
        is None
    )

    assert zscaler.puts == []
    connector.activate_zscaler_changes.assert_called_once()


def test_adapter_push_of_a_listed_domain_still_pending_raises_the_reason(connector):
    FakeZscaler(urls=["new.example"]).install(connector)
    connector.activate_zscaler_changes.return_value = False

    with pytest.raises(ZscalerDeploymentError):
        ZscalerDeploymentAdapter(connector).push_indicator(
            make_indicator(domain="new.example")
        )


def test_adapter_push_raises_the_reason_and_logs_the_detail(connector):
    FakeZscaler(put_status=403).install(connector)
    indicator = make_indicator(domain="new.example")

    with pytest.raises(ZscalerDeploymentError) as raised:
        ZscalerDeploymentAdapter(connector).push_indicator(indicator)

    assert str(raised.value) == (
        "Zscaler refused the blacklist update: permission denied"
    )
    logged = connector.helper.connector_logger.warning.call_args
    message, meta = logged.args[0], logged.kwargs["meta"]
    assert message == "[DEPLOYMENT] Zscaler did not take an indicator pushed again."
    assert meta == {
        "indicator_id": indicator["id"],
        "error": "Request failed with status 403: INVALID_INPUT_ARGUMENT",
    }


def test_adapter_push_with_a_malformed_blacklist_raises_the_reason(connector):
    zscaler = FakeZscaler().install(connector)
    connector.session.get.side_effect = None
    connector.session.get.return_value = response(json_data=["new.example"])

    with pytest.raises(ZscalerDeploymentError) as raised:
        ZscalerDeploymentAdapter(connector).push_indicator(
            make_indicator(domain="new.example")
        )

    assert str(raised.value) == (
        "Zscaler returned an unexpected response to the blacklist read"
    )
    assert zscaler.puts == []


# Settings and wiring


def test_write_back_settings_defaults():
    settings = make_settings()

    assert settings.deployment.reporting_enabled is True
    assert settings.deployment.reconciliation_interval == 60
    assert settings.security_platform.name == "Zscaler Internet Access"
    assert settings.security_platform.type is None
    assert settings.security_platform.id is None


def test_build_deployment_assurance_wires_the_reconciliation_without_hits():
    assurance = build_deployment_assurance(build_connector(), make_settings())

    assert isinstance(assurance.reconciler, DeploymentReconciler)
    assert isinstance(assurance.reconciler._adapter, ZscalerDeploymentAdapter)
    assert assurance.reporter.hits_enabled is False


def test_disabled_write_back_is_a_no_op():
    assurance = build_deployment_assurance(
        build_connector(), make_settings(deployment={"reporting_enabled": False})
    )

    assert assurance.enabled is False
    assert assurance.start() is False


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


def deployment_node(indicator_id, status, domain, revoked=False):
    return {
        "id": f"relationship-{indicator_id}",
        "deployment_status": status,
        "external_id": None,
        "revoked": revoked,
        "last_sync_at": "2026-10-01T00:00:00.000Z",
        "last_hit_at": None,
        "hit_count": 0,
        "from": {
            "id": indicator_id,
            "standard_id": f"indicator--{indicator_id}",
            "name": domain,
            "pattern": f"[domain-name:value = '{domain}']",
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
        make_settings(),
        adapter=ZscalerDeploymentAdapter(connector),
        reporter_kwargs={"flush_interval": 3600.0},
    )
    return connector


def test_stream_outcomes_are_reported_in_one_batch(e2e_connector, router):
    zscaler = FakeZscaler().install(e2e_connector)

    e2e_connector._process_message(make_message("create", make_indicator()))
    zscaler.put_status = 400
    e2e_connector._process_message(
        make_message(
            "create", make_indicator(indicator_id=OTHER_ID, domain="other.example")
        )
    )
    result = e2e_connector.assurance.flush()

    assert result.processed == 2
    assert router.calls_of("DeploymentSecurityPlatformAdd") == [
        {"input": {"name": "Zscaler Internet Access", "update": True}}
    ]
    (batch,) = router.calls_of("IndicatorReportDeployments(")
    deployed, failed = batch["reports"]
    assert deployed == {"indicatorId": INDICATOR_ID, "status": "deployed"}
    assert failed["indicatorId"] == OTHER_ID
    assert failed["status"] == "failed"
    assert failed["metadata"]["error_message"] == (
        "Zscaler refused the blacklist update: invalid request"
    )


def test_reconciliation_confirms_removes_and_withdraws(e2e_connector, router):
    router.deployments = [
        deployment_node(INDICATOR_ID, "deployed", "evil.example"),
        deployment_node(OTHER_ID, "active", "gone.example"),
        deployment_node("withdrawn-id", "active", "withdrawn.example", revoked=True),
    ]
    zscaler = FakeZscaler(urls=["evil.example", "withdrawn.example"]).install(
        e2e_connector
    )

    summary = e2e_connector.assurance.reconciler.run_once()

    assert summary.skipped is False
    assert summary.confirmed_active == 1
    assert summary.marked_removed == 1
    assert summary.withdrawn == 1
    assert zscaler.urls == ["evil.example"]
    (batch,) = router.calls_of("IndicatorReportDeployments(")
    reports = {report["indicatorId"]: report["status"] for report in batch["reports"]}
    assert reports == {
        INDICATOR_ID: "active",
        OTHER_ID: "removed",
        "withdrawn-id": "removed",
    }


def test_reconciliation_removes_a_shared_domain_once_all_its_deployments_leave(
    e2e_connector, router
):
    """Two withdrawn deployments of one domain remove it once; a live one keeps it."""
    router.deployments = [
        deployment_node("a", "active", "shared.example", revoked=True),
        deployment_node("b", "active", "shared.example", revoked=True),
        deployment_node("c", "active", "kept.example", revoked=True),
        deployment_node("d", "active", "kept.example"),
    ]
    zscaler = FakeZscaler(urls=["shared.example", "kept.example"]).install(
        e2e_connector
    )

    summary = e2e_connector.assurance.reconciler.run_once()

    assert summary.withdrawn == 3
    assert zscaler.urls == ["kept.example"]
    assert len(zscaler.puts) == 1
    e2e_connector.helper.api.indicator.list.assert_not_called()
    (batch,) = router.calls_of("IndicatorReportDeployments(")
    reports = {report["indicatorId"]: report["status"] for report in batch["reports"]}
    assert reports == {"a": "removed", "b": "removed", "c": "removed", "d": "active"}


COMPOUND_PATTERN = (
    "[domain-name:value = 'Evil.example'] OR [url:value = 'kept.example']"
)


def test_adapter_expects_only_the_domain_the_connector_pushes(connector):
    adapter = ZscalerDeploymentAdapter(connector)
    compound = IndicatorDeployment(
        relationship_id="relationship-compound",
        status="active",
        indicator_id="compound",
        pattern=COMPOUND_PATTERN,
        pattern_type="stix",
    )

    assert adapter.expected_values(compound) == frozenset({"evil.example"})
    assert (
        adapter.expected_values(make_deployment(domain="not a domain")) == frozenset()
    )
    assert adapter.expected_values(replace(compound, pattern=None)) == frozenset()


def test_reconciliation_never_withdraws_a_value_the_connector_did_not_push(
    e2e_connector, router
):
    """Only the domain of the pattern is on the blacklist for the indicator: another
    value of the pattern listed for another reason stays."""
    node = deployment_node("a", "active", "evil.example", revoked=True)
    node["from"]["pattern"] = COMPOUND_PATTERN
    router.deployments = [node]
    zscaler = FakeZscaler(urls=["evil.example", "kept.example"]).install(e2e_connector)

    summary = e2e_connector.assurance.reconciler.run_once()

    assert summary.withdrawn == 1
    assert zscaler.urls == ["kept.example"]
    (batch,) = router.calls_of("IndicatorReportDeployments(")
    assert {report["indicatorId"]: report["status"] for report in batch["reports"]} == {
        "a": "removed"
    }


def test_read_back_failure_skips_the_reconciliation(e2e_connector, router):
    router.deployments = [deployment_node(INDICATOR_ID, "active", "evil.example")]
    FakeZscaler(get_status=503).install(e2e_connector)

    summary = e2e_connector.assurance.reconciler.run_once()

    assert summary.skipped is True
    assert "category unavailable" in summary.reason
    assert router.calls_of("IndicatorReportDeployments(") == []

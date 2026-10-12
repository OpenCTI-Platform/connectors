"""Deployment write-back of the Microsoft Defender Intel connector."""

import json
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any
from unittest.mock import ANY, MagicMock, call

import pytest
import requests
from connectors_sdk import (
    DeploymentAssurance,
    HitCollection,
    IndicatorDeployment,
    VendorIndicator,
)
from connectors_sdk.connectors.stream.deployment import PENDING_WITHDRAWALS_STATE_KEY
from microsoft_defender_intel_connector import (
    ConnectorSettings,
    MicrosoftDefenderIntelConnector,
)
from microsoft_defender_intel_connector.api_handler import (
    APPLICATION_NAME,
    DefenderApiHandlerError,
)
from microsoft_defender_intel_connector.deployment import (
    DefenderDeploymentError,
    MicrosoftDefenderDeploymentAdapter,
    build_deployment_assurance,
    describe_error,
    failure_reason,
)
from pycti import OpenCTIConnectorHelper

OPENCTI_EXTENSION_ID = "extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba"
PLATFORM_ID = "6c3b0f4e-2d41-4a77-8f0d-3e1c9b5a7d21"
INDICATOR_ID = "0d8b4f0e-6a43-4f11-8f6c-1d2f5e6a7b8c"
OTHER_ID = "1e9c5f1f-7b54-4a22-9e7d-2e3f6a7b8c9d"
DEFENDER_ID = "6371"
INDICATORS_URL = "https://api.securitycenter.microsoft.com/api/indicators"
ALERTS_URL = "https://api.securitycenter.microsoft.com/api/alerts"


def make_settings(**namespaces: dict[str, Any]) -> ConnectorSettings:
    """Build connector settings from a valid configuration and overrides."""
    config = {
        "opencti": {"url": "http://localhost:8080", "token": "test-token"},
        "connector": {"live_stream_id": "live"},
        "microsoft_defender_intel": {
            "tenant_id": "tenant",
            "client_id": "client",
            "client_secret": "secret",
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
                "updated_at": "2026-10-01T00:00:00.000Z",
                "observable_values": [{"type": "IPv4-Addr", "value": value}],
            }
        },
    }


def make_message(event, data, context=None):
    payload = {"data": data}
    if context is not None:
        payload["context"] = context
    return SimpleNamespace(event=event, data=json.dumps(payload))


def http_error(status_code: int, text: str) -> DefenderApiHandlerError:
    """Build the error raised by the API handler for an HTTP error."""
    response = requests.Response()
    response.status_code = status_code
    response._content = text.encode()
    error = DefenderApiHandlerError(
        "[API] An error occurred during request", {"url_path": "POST /api"}
    )
    error.__cause__ = requests.HTTPError(
        f"{status_code} Client Error", response=response
    )
    return error


def make_deployment(indicator_id=INDICATOR_ID, value="198.51.100.7"):
    return IndicatorDeployment(
        relationship_id=f"relationship-{indicator_id}",
        status="deployed",
        indicator_id=indicator_id,
        pattern=f"[ipv4-addr:value = '{value}']",
        pattern_type="stix",
    )


def make_helper(spec: list[str] | None = None) -> MagicMock:
    helper = MagicMock(spec=spec) if spec is not None else MagicMock()
    helper.connect_live_stream_id = "live"
    helper.get_attribute_in_extension = (
        OpenCTIConnectorHelper.get_attribute_in_extension
    )
    return helper


def build_connector(settings=None, helper=None, assurance=None):
    connector = MicrosoftDefenderIntelConnector(
        config=settings or make_settings(),
        helper=helper or make_helper(),
        assurance=assurance,
    )
    connector.api._send_request = MagicMock()
    return connector


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


# Stream path


def test_created_indicator_is_reported_deployed(connector):
    connector.api._send_request.return_value = {"id": DEFENDER_ID}
    indicator = make_indicator()

    connector.process_message(make_message("create", indicator))

    connector.assurance.report_pushed.assert_called_once_with(
        indicator, external_id=DEFENDER_ID
    )
    body = connector.api._send_request.call_args.kwargs["json"]
    assert body["application"] == APPLICATION_NAME
    assert body["externalId"] == INDICATOR_ID
    assert body["indicatorValue"] == "198.51.100.7"


def test_rejected_indicator_is_reported_failed(connector):
    connector.api._send_request.side_effect = http_error(
        400, '{"error": {"message": "Invalid indicator value"}}'
    )
    indicator = make_indicator()

    connector.process_message(make_message("create", indicator))

    connector.assurance.report_push_failed.assert_called_once_with(
        indicator,
        "Microsoft Defender refused the indicator submission: invalid request",
    )
    connector.assurance.report_pushed.assert_not_called()
    # The Defender response is left to the log.
    connector.helper.connector_logger.warning.assert_called_once()
    message, kwargs = connector.helper.connector_logger.warning.call_args
    assert message == ("Indicator not deployed on Microsoft Defender",)
    assert kwargs["meta"]["opencti_id"] == INDICATOR_ID
    assert kwargs["meta"]["error"].startswith(
        "[API] An error occurred during request: 400 Client"
    )
    assert kwargs["meta"]["error"].endswith('Invalid indicator value"}}')


def test_external_reference_errors_do_not_abort_the_dissemination(connector):
    connector.api._send_request.return_value = {"id": DEFENDER_ID}
    connector.helper.api.external_reference.create.side_effect = ValueError("boom")

    connector.process_message(make_message("create", make_indicator()))

    connector.assurance.report_pushed.assert_called_once()
    connector.helper.connector_logger.warning.assert_called_once_with(
        "[CREATE] Cannot add the Microsoft Defender external reference",
        meta={"defender_id": DEFENDER_ID, "error": "boom"},
    )


def test_indicator_without_observable_is_not_reported(connector):
    indicator = make_indicator()
    del indicator["extensions"][OPENCTI_EXTENSION_ID]["observable_values"]

    connector.process_message(make_message("create", indicator))

    connector.api._send_request.assert_not_called()
    connector.assurance.report_pushed.assert_not_called()
    connector.assurance.report_push_failed.assert_not_called()


def test_streamed_observables_are_not_reported(connector):
    connector.api._send_request.return_value = {"id": DEFENDER_ID}
    observable = {
        "id": "ipv4-addr--x",
        "type": "ipv4-addr",
        "value": "198.51.100.7",
        "extensions": {
            OPENCTI_EXTENSION_ID: {
                "id": OTHER_ID,
                "score": 50,
                "updated_at": "2026-10-01T00:00:00.000Z",
            }
        },
    }

    connector.process_message(make_message("create", observable))

    connector.api._send_request.assert_called_once()
    connector.assurance.report_pushed.assert_not_called()


def test_updated_indicator_is_reported_deployed(connector):
    connector.api._send_request.side_effect = [
        {"value": [own(DEFENDER_ID)]},
        {"id": DEFENDER_ID},
    ]
    indicator = make_indicator()

    connector.process_message(make_message("update", indicator))

    connector.assurance.report_pushed.assert_called_once_with(
        indicator, external_id=DEFENDER_ID
    )


def test_update_never_takes_a_defender_indicator_of_another_indicator(connector):
    """Defender may hold the value for another application or another OpenCTI
    indicator: that one is neither updated nor reported as this deployment."""
    connector.api._send_request.return_value = {
        "value": [own("77", opencti_id="another-indicator"), {"id": "78"}]
    }

    connector.process_message(make_message("update", make_indicator()))

    assert [entry for entry in _sent(connector) if entry[0] != "get"] == []
    connector.assurance.report_pushed.assert_not_called()


def test_update_of_an_absent_indicator_is_not_reported(connector):
    connector.api._send_request.return_value = {"value": []}

    connector.process_message(make_message("update", make_indicator()))

    connector.assurance.report_pushed.assert_not_called()
    connector.assurance.report_push_failed.assert_not_called()


def test_failed_update_is_reported_failed(connector):
    connector.api._send_request.side_effect = [
        {"value": [own(DEFENDER_ID)]},
        http_error(403, "Forbidden"),
    ]

    connector.process_message(make_message("update", make_indicator()))

    message = connector.assurance.report_push_failed.call_args.args[1]
    assert message == (
        "Microsoft Defender refused the indicator submission: permission denied"
    )


@pytest.mark.parametrize(
    ("cause", "reason"),
    [
        (
            requests.exceptions.RetryError("too many 429 error responses"),
            "Microsoft Defender refused the indicator submission: rate limit reached",
        ),
        (
            requests.exceptions.ConnectionError("connection reset"),
            "Microsoft Defender could not be reached for the indicator submission",
        ),
        (
            requests.exceptions.ReadTimeout("read timeout"),
            "Microsoft Defender could not be reached for the indicator submission",
        ),
        (
            None,
            "Microsoft Defender returned an unexpected response to the indicator "
            "submission",
        ),
    ],
)
def test_failure_reasons_name_the_cause_without_the_defender_response(cause, reason):
    error = DefenderApiHandlerError("[API] Failed", {})
    error.__cause__ = cause

    assert failure_reason(error) == reason
    assert failure_reason(ValueError("No observable")) == "No observable"
    assert failure_reason(ValueError()) == "ValueError"


def own(defender_id, opencti_id=INDICATOR_ID):
    """A Defender indicator the connector pushed for an OpenCTI indicator."""
    return {"id": defender_id, "externalId": opencti_id}


def pattern_edit(former_pattern):
    """The context of an update event that replaced the pattern of an indicator."""
    return {
        "patch": [{"op": "replace", "path": "/pattern", "value": "new"}],
        "reverse_patch": [
            {"op": "replace", "path": "/name", "value": "former name"},
            {"op": "replace", "path": "/pattern", "value": former_pattern},
        ],
    }


@pytest.mark.parametrize(
    "former_pattern, former_value",
    [
        ("[ipv4-addr:value = '198.51.100.7']", "198.51.100.7"),
        (f"[file:hashes.'SHA-256' = '{'a' * 64}']", "a" * 64),
    ],
    ids=["an IP address", "a file"],
)
def test_a_pattern_edit_replaces_the_defender_indicator_of_the_former_value(
    connector, former_pattern, former_value
):
    """The Defender indicator of a value the indicator no longer holds would stay
    active: it is deleted once the new value is live."""
    connector.api._send_request.side_effect = [
        {"value": []},
        {"value": [own("1")]},
        {"id": "2"},
        None,
    ]
    connector.helper.api.external_reference.read.return_value = {"id": "ref"}
    indicator = make_indicator(value="203.0.113.9")

    connector.process_message(
        make_message("update", indicator, pattern_edit(former_pattern))
    )

    assert _sent(connector) == [
        ("get", ""),
        ("get", ""),
        ("post", ""),
        ("delete", "/1"),
    ]
    looked_up = connector.api._send_request.call_args_list[1].kwargs["params"]
    assert looked_up.endswith(f"%27{former_value}%27")
    created = connector.api._send_request.call_args_list[2].kwargs["json"]
    assert created["indicatorValue"] == "203.0.113.9"
    connector.helper.api.external_reference.delete.assert_called_once_with("ref")
    connector.assurance.report_pushed.assert_called_once_with(
        indicator, external_id="2"
    )
    connector.assurance.report_removed.assert_not_called()


def test_an_update_without_pattern_edit_reads_no_former_value(connector):
    connector.api._send_request.side_effect = [
        {"value": [own(DEFENDER_ID)]},
        {"id": DEFENDER_ID},
    ]
    indicator = make_indicator()

    connector.process_message(
        make_message(
            "update",
            indicator,
            {"reverse_patch": [{"op": "replace", "path": "/name", "value": "x"}]},
        )
    )

    assert _sent(connector) == [("get", ""), ("post", "")]
    connector.assurance.report_pushed.assert_called_once_with(
        indicator, external_id=DEFENDER_ID
    )


def test_a_pattern_edit_never_deletes_a_defender_indicator_of_another_indicator(
    connector,
):
    connector.api._send_request.side_effect = [
        {"value": []},
        {"value": [own("77", opencti_id="another-indicator"), {"id": "78"}]},
    ]

    connector.process_message(
        make_message(
            "update",
            make_indicator(value="203.0.113.9"),
            pattern_edit("[ipv4-addr:value = '198.51.100.7']"),
        )
    )

    assert _sent(connector) == [("get", ""), ("get", "")]
    connector.assurance.report_pushed.assert_not_called()
    connector.assurance.report_removed.assert_not_called()


def test_a_pattern_edit_without_a_value_defender_takes_is_reported_removed(
    connector,
):
    connector.api._send_request.side_effect = [{"value": [own("1")]}, None]
    indicator = make_multi_indicator(EMAIL)

    connector.process_message(
        make_message(
            "update", indicator, pattern_edit("[ipv4-addr:value = '198.51.100.7']")
        )
    )

    assert _sent(connector) == [("get", ""), ("delete", "/1")]
    connector.assurance.report_removed.assert_called_once_with(
        indicator, external_id=None
    )
    connector.assurance.report_pushed.assert_not_called()


def test_a_failed_pattern_edit_keeps_the_defender_indicator_of_the_former_value(
    connector,
):
    """The former value stays live with the previous version: it is kept for the
    next update or delete of the indicator to delete it."""
    connector.helper.get_state.return_value = {"start_from": "1-0"}
    connector.api._send_request.side_effect = [
        {"value": []},
        {"value": [own("1")]},
        http_error(400, "Invalid indicator value"),
    ]

    connector.process_message(
        make_message(
            "update",
            make_indicator(value="203.0.113.9"),
            pattern_edit("[ipv4-addr:value = '198.51.100.7']"),
        )
    )

    assert [entry for entry in _sent(connector) if entry[0] == "delete"] == []
    connector.assurance.report_push_failed.assert_called_once()
    connector.assurance.report_pushed.assert_not_called()
    assert kept_former_values(connector) == ["198.51.100.7"]


def test_a_failed_deletion_of_a_former_value_is_logged_and_kept(connector):
    connector.helper.get_state.return_value = {"start_from": "1-0"}
    connector.api._send_request.side_effect = [
        {"value": []},
        {"value": [own("1")]},
        {"id": "2"},
        http_error(503, "Unavailable"),
    ]
    indicator = make_indicator(value="203.0.113.9")

    connector.process_message(
        make_message(
            "update", indicator, pattern_edit("[ipv4-addr:value = '198.51.100.7']")
        )
    )

    connector.helper.connector_logger.warning.assert_any_call(
        "[UPDATE] Cannot delete the Defender indicator of a former value",
        meta={
            "opencti_id": INDICATOR_ID,
            "values": ["198.51.100.7"],
            "error": ANY,
        },
    )
    connector.helper.api.external_reference.delete.assert_not_called()
    connector.assurance.report_pushed.assert_called_once_with(
        indicator, external_id="2"
    )
    assert kept_former_values(connector) == ["198.51.100.7"]


FORMER_VALUE = "203.0.113.9"


def keep_former_value(connector, value=FORMER_VALUE):
    """Leave a former value an earlier update could not delete in the state."""
    connector.helper.get_state.return_value = {
        "start_from": "1-0",
        PENDING_WITHDRAWALS_STATE_KEY: {INDICATOR_ID: [value]},
    }


def kept_former_values(connector):
    state = connector.helper.get_state.return_value
    return state.get(PENDING_WITHDRAWALS_STATE_KEY, {}).get(INDICATOR_ID, [])


def test_update_deletes_the_former_values_an_earlier_update_left(connector):
    keep_former_value(connector)
    connector.api._send_request.side_effect = [
        {"value": [own(DEFENDER_ID)]},
        {"id": DEFENDER_ID},
        {"value": [own("1")]},
        None,
    ]
    indicator = make_indicator()

    connector.process_message(make_message("update", indicator))

    assert _sent(connector) == [
        ("get", ""),
        ("post", ""),
        ("get", ""),
        ("delete", "/1"),
    ]
    connector.assurance.report_pushed.assert_called_once_with(
        indicator, external_id=DEFENDER_ID
    )
    assert kept_former_values(connector) == []


def test_a_kept_former_value_back_in_the_pattern_is_never_deleted(connector):
    keep_former_value(connector, "198.51.100.7")
    connector.api._send_request.side_effect = [
        {"value": [own(DEFENDER_ID)]},
        {"id": DEFENDER_ID},
    ]

    connector.process_message(make_message("update", make_indicator()))

    assert _sent(connector) == [("get", ""), ("post", "")]
    assert kept_former_values(connector) == []


def test_delete_after_a_failed_deletion_deletes_the_former_indicator_first(
    connector,
):
    """The delete carries the current pattern only: the kept former value is
    deleted before the indicator is reported removed."""
    keep_former_value(connector)
    connector.api._send_request.side_effect = [
        {"value": [own("1")]},
        None,
        {"value": [own(DEFENDER_ID)]},
        None,
    ]
    indicator = make_indicator()

    connector.process_message(make_message("delete", indicator))

    assert [entry for entry in _sent(connector) if entry[0] == "delete"] == [
        ("delete", "/1"),
        ("delete", f"/{DEFENDER_ID}"),
    ]
    connector.assurance.report_removed.assert_called_once_with(
        indicator, external_id=DEFENDER_ID
    )
    assert kept_former_values(connector) == []


def test_delete_whose_former_indicator_is_still_refused_is_not_reported_removed(
    connector,
):
    keep_former_value(connector)
    connector.api._send_request.side_effect = [
        {"value": [own("1")]},
        http_error(503, "Unavailable"),
        {"value": [own(DEFENDER_ID)]},
        None,
    ]

    connector.process_message(make_message("delete", make_indicator()))

    assert ("delete", f"/{DEFENDER_ID}") in _sent(connector)
    connector.assurance.report_removed.assert_not_called()
    assert kept_former_values(connector) == [FORMER_VALUE]


def test_a_failed_deletion_leaves_an_edited_indicator_unreported(connector):
    connector.api._send_request.side_effect = [
        {"value": [own("1")]},
        http_error(503, "Unavailable"),
    ]

    connector.process_message(
        make_message(
            "update",
            make_multi_indicator(EMAIL),
            pattern_edit("[ipv4-addr:value = '198.51.100.7']"),
        )
    )

    connector.assurance.report_removed.assert_not_called()
    connector.assurance.report_pushed.assert_not_called()


def make_multi_indicator(*observables):
    indicator = make_indicator()
    indicator["extensions"][OPENCTI_EXTENSION_ID]["observable_values"] = list(
        observables
    )
    return indicator


IP = {"type": "IPv4-Addr", "value": "198.51.100.7"}
DOMAIN = {"type": "Domain-Name", "value": "evil.example"}
URL = {"type": "Url", "value": "http://evil.example/x"}
EMAIL = {"type": "Email-Addr", "value": "x@evil.example"}


def _sent(connector):
    return [
        (method, url.removeprefix(INDICATORS_URL))
        for method, url, *_ in (
            entry.args for entry in connector.api._send_request.call_args_list
        )
    ]


def test_a_failed_create_deletes_the_defender_indicators_it_created(connector):
    """A partial push would be promoted to active by reconciliation: none survives."""
    connector.api._send_request.side_effect = [
        {"id": "1"},
        http_error(400, "Invalid indicator value"),
        None,
    ]
    connector.helper.api.external_reference.read.return_value = {"id": "ref"}
    indicator = make_multi_indicator(IP, DOMAIN)

    connector.process_message(make_message("create", indicator))

    assert _sent(connector) == [("post", ""), ("post", ""), ("delete", "/1")]
    connector.helper.api.external_reference.delete.assert_called_once_with("ref")
    connector.assurance.report_push_failed.assert_called_once()
    connector.assurance.report_pushed.assert_not_called()


def test_a_create_confirmed_without_its_id_is_a_failed_push(connector):
    connector.api._send_request.side_effect = [{"id": "1"}, None, None]

    connector.process_message(make_message("create", make_multi_indicator(IP, DOMAIN)))

    assert _sent(connector)[-1] == ("delete", "/1")
    connector.assurance.report_push_failed.assert_called_once()


def test_a_failed_rollback_is_logged(connector):
    connector.api._send_request.side_effect = [
        {"id": "1"},
        http_error(400, "Invalid indicator value"),
        http_error(503, "Unavailable"),
    ]

    connector.process_message(make_message("create", make_multi_indicator(IP, DOMAIN)))

    connector.helper.connector_logger.warning.assert_any_call(
        "[CREATE] Cannot delete a Defender indicator of an incomplete push",
        meta={"defender_id": "1", "error": ANY},
    )
    connector.helper.api.external_reference.delete.assert_not_called()
    connector.assurance.report_push_failed.assert_called_once()


def test_observables_defender_does_not_take_are_not_pushed(connector):
    connector.api._send_request.return_value = {"id": "1"}
    indicator = make_multi_indicator(IP, EMAIL)

    connector.process_message(make_message("create", indicator))

    assert _sent(connector) == [("post", "")]
    connector.assurance.report_pushed.assert_called_once_with(
        indicator, external_id="1"
    )


def test_an_update_creates_the_missing_defender_indicators(connector):
    connector.api._send_request.side_effect = [
        {"value": [own("1")]},
        {"value": []},
        {"id": "1"},
        {"id": "2"},
    ]
    indicator = make_multi_indicator(IP, DOMAIN)

    connector.process_message(make_message("update", indicator))

    created = connector.api._send_request.call_args_list[-1].kwargs["json"]
    assert created["indicatorValue"] == "evil.example"
    assert "id" not in created
    connector.assurance.report_pushed.assert_called_once_with(
        indicator, external_id="1"
    )


def test_a_failed_update_deletes_only_the_defender_indicators_it_created(connector):
    connector.api._send_request.side_effect = [
        {"value": [own("1")]},
        {"value": []},
        {"value": []},
        {"id": "1"},
        {"id": "2"},
        http_error(400, "Invalid indicator value"),
        {"id": "1"},
        None,
    ]

    connector.process_message(
        make_message("update", make_multi_indicator(IP, DOMAIN, URL))
    )

    assert [entry for entry in _sent(connector) if entry[0] == "delete"] == [
        ("delete", "/2")
    ]
    connector.assurance.report_push_failed.assert_called_once()
    connector.assurance.report_pushed.assert_not_called()


PREVIOUS_IP = {
    "id": "1",
    "externalId": INDICATOR_ID,
    "indicatorValue": "198.51.100.7",
    "indicatorType": "IpAddress",
    "application": "OpenCTI Microsoft Defender Intel",
    "action": "Alert",
    "title": "198.51.100.7",
    "description": "Previous description",
    "expirationTime": "2026-12-01T00:00:00Z",
    "severity": "Low",
    "generateAlert": True,
    "createdBy": "not written back",
}


def test_a_failed_update_restores_the_defender_indicators_it_updated(connector):
    """A half-applied update would be read back as complete: the updated
    indicators get their previous values again."""
    connector.api._send_request.side_effect = [
        {"value": [PREVIOUS_IP]},
        {"value": [own("2")]},
        {"id": "1"},
        http_error(400, "Invalid indicator value"),
        {"id": "1"},
    ]

    connector.process_message(make_message("update", make_multi_indicator(IP, DOMAIN)))

    assert _sent(connector) == [
        ("get", ""),
        ("get", ""),
        ("post", ""),
        ("post", ""),
        ("post", ""),
    ]
    restored = connector.api._send_request.call_args_list[-1].kwargs["json"]
    assert restored == {
        key: value for key, value in PREVIOUS_IP.items() if key != "createdBy"
    }
    connector.assurance.report_push_failed.assert_called_once()
    connector.assurance.report_pushed.assert_not_called()


def test_a_failed_restore_is_logged(connector):
    connector.api._send_request.side_effect = [
        {"value": [PREVIOUS_IP]},
        {"value": [own("2")]},
        {"id": "1"},
        http_error(400, "Invalid indicator value"),
        http_error(503, "Unavailable"),
    ]

    connector.process_message(make_message("update", make_multi_indicator(IP, DOMAIN)))

    connector.helper.connector_logger.warning.assert_any_call(
        "[UPDATE] Cannot restore a Defender indicator of an incomplete update",
        meta={"defender_id": "1", "error": ANY},
    )
    connector.assurance.report_push_failed.assert_called_once()


def make_pattern_deployment(pattern, pattern_type="stix"):
    return IndicatorDeployment(
        relationship_id="relationship",
        status="active",
        indicator_id=INDICATOR_ID,
        pattern=pattern,
        pattern_type=pattern_type,
    )


def vendor_values(*values):
    return [
        VendorIndicator(indicator_id=INDICATOR_ID, external_id=str(n), value=value)
        for n, value in enumerate(values)
    ]


SHA256 = "a" * 64
MD5 = "b" * 32


@pytest.mark.parametrize(
    "pattern, values, complete",
    [
        (
            "[ipv4-addr:value = '198.51.100.7' OR domain-name:value = 'evil.example']",
            ("198.51.100.7", "EVIL.example"),
            True,
        ),
        (
            "[ipv4-addr:value = '198.51.100.7' OR domain-name:value = 'evil.example']",
            ("198.51.100.7",),
            False,
        ),
        (
            f"[file:hashes.'SHA-256' = '{SHA256}' OR file:hashes.MD5 = '{MD5}']",
            (SHA256,),
            True,
        ),
        (
            f"[file:hashes.'SHA-256' = '{SHA256}' OR ipv4-addr:value = '198.51.100.7']",
            ("198.51.100.7",),
            False,
        ),
        (
            "[ipv4-addr:value = '198.51.100.7' OR email-addr:value = 'x@evil.example']",
            ("198.51.100.7",),
            True,
        ),
        (
            f"[file:hashes.'SHA-512' = '{'c' * 128}' OR ipv4-addr:value = '198.51.100.7']",
            ("198.51.100.7",),
            True,
        ),
        ("[email-addr:value = 'x@evil.example']", ("198.51.100.7",), False),
        (f"[file:hashes.'SHA-512' = '{'c' * 128}']", ("198.51.100.7",), False),
    ],
    ids=[
        "every value",
        "a value missing",
        "a file by one of its hashes",
        "a file missing",
        "a type Defender does not take",
        "a hash Defender does not take",
        "only a type Defender does not take",
        "only a hash Defender does not take",
    ],
)
def test_adapter_completeness_requires_every_observable(pattern, values, complete):
    adapter = MicrosoftDefenderDeploymentAdapter(build_connector())

    assert (
        adapter.is_complete(make_pattern_deployment(pattern), vendor_values(*values))
        is complete
    )


@pytest.mark.parametrize(
    "pattern, pattern_type",
    [("process.name = 'x'", "kql"), (None, "stix")],
    ids=["not STIX", "missing"],
)
def test_adapter_completeness_of_a_pattern_it_cannot_read(pattern, pattern_type):
    adapter = MicrosoftDefenderDeploymentAdapter(build_connector())

    assert adapter.is_complete(
        make_pattern_deployment(pattern, pattern_type), vendor_values("x")
    )


IP_AND_DOMAIN = (
    "[ipv4-addr:value = '198.51.100.7' OR domain-name:value = 'evil.example']"
)


def test_adapter_confirms_an_absence_by_looking_each_value_up():
    """The paged read-back has no documented order: an indicator it missed is found
    by its exact value and never reported removed."""
    connector = build_connector()
    adapter = MicrosoftDefenderDeploymentAdapter(connector)
    assert adapter.confirms_absence is True
    connector.api._send_request.side_effect = [
        {"value": []},
        {"value": [{"id": "9", "application": APPLICATION_NAME}]},
    ]

    assert adapter.confirm_absent(make_pattern_deployment(IP_AND_DOMAIN)) is False
    looked_up = [
        entry.kwargs["params"] for entry in connector.api._send_request.call_args_list
    ]
    assert looked_up == [
        "$filter=indicatorValue%20eq%20%27198.51.100.7%27",
        "$filter=indicatorValue%20eq%20%27evil.example%27",
    ]


def test_adapter_only_looks_the_pushed_values_up_to_confirm_an_absence():
    """A Defender indicator holding a value the connector never pushes (an email
    address, a SHA-512 hash) does not keep the deployment."""
    connector = build_connector()
    adapter = MicrosoftDefenderDeploymentAdapter(connector)
    connector.api._send_request.side_effect = [{"value": []}]
    pattern = (
        "[ipv4-addr:value = '198.51.100.7' OR email-addr:value = 'x@evil.example'"
        f" OR file:hashes.'SHA-512' = '{'c' * 128}']"
    )

    assert adapter.confirm_absent(make_pattern_deployment(pattern)) is True
    looked_up = [
        entry.kwargs["params"] for entry in connector.api._send_request.call_args_list
    ]
    assert looked_up == ["$filter=indicatorValue%20eq%20%27198.51.100.7%27"]


def test_adapter_confirms_the_absence_of_a_pattern_without_a_pushed_value():
    connector = build_connector()
    adapter = MicrosoftDefenderDeploymentAdapter(connector)

    assert (
        adapter.confirm_absent(
            make_pattern_deployment("[email-addr:value = 'x@evil.example']")
        )
        is True
    )
    connector.api._send_request.assert_not_called()


def test_adapter_confirms_an_absence_when_no_value_is_held_by_the_connector():
    """Indicators of another application holding the same value do not count."""
    connector = build_connector()
    adapter = MicrosoftDefenderDeploymentAdapter(connector)
    connector.api._send_request.side_effect = [
        {"value": [{"id": "1", "application": "Another integration"}]},
        {"value": []},
    ]

    assert adapter.confirm_absent(make_pattern_deployment(IP_AND_DOMAIN)) is True


def test_adapter_confirms_an_absence_when_the_connector_indicators_expired():
    """Defender keeps expired indicators: as in the read-back, they are not live."""
    connector = build_connector()
    now = datetime(2026, 10, 3, 12, 0, tzinfo=UTC)
    adapter = MicrosoftDefenderDeploymentAdapter(connector, clock=lambda: now)
    connector.api._send_request.side_effect = [
        {
            "value": [
                {
                    "id": "9",
                    "application": APPLICATION_NAME,
                    "expirationTime": "2026-10-03T11:59:59Z",
                }
            ]
        },
        {"value": []},
    ]

    assert adapter.confirm_absent(make_pattern_deployment(IP_AND_DOMAIN)) is True

    connector.api._send_request.side_effect = [
        {
            "value": [
                {
                    "id": "9",
                    "application": APPLICATION_NAME,
                    "expirationTime": "2026-10-03T12:00:01Z",
                }
            ]
        },
    ]

    assert adapter.confirm_absent(make_pattern_deployment(IP_AND_DOMAIN)) is False


def test_adapter_confirms_an_absence_when_the_value_is_held_for_another_indicator():
    """A Defender indicator pushed for another OpenCTI indicator holding the same
    value is not the deployment's: the read-back would not match it either."""
    connector = build_connector()
    adapter = MicrosoftDefenderDeploymentAdapter(connector)
    connector.api._send_request.side_effect = [
        {
            "value": [
                {"id": "9", "application": APPLICATION_NAME, "externalId": OTHER_ID}
            ]
        },
        {
            "value": [
                {"id": "10", "application": APPLICATION_NAME, "externalID": OTHER_ID}
            ]
        },
    ]

    assert adapter.confirm_absent(make_pattern_deployment(IP_AND_DOMAIN)) is True


@pytest.mark.parametrize(
    "defender_indicator",
    [
        {"id": "9", "externalId": INDICATOR_ID},
        {"id": "9", "externalID": INDICATOR_ID.upper()},
        {"id": "9", "externalId": f"indicator--{INDICATOR_ID}"},
        {"id": DEFENDER_ID, "externalId": OTHER_ID},
        {"id": "9"},
    ],
    ids=[
        "its OpenCTI id",
        "its OpenCTI id in another case",
        "its STIX id",
        "its Defender id",
        "no OpenCTI id",
    ],
)
def test_adapter_absence_counts_the_defender_indicators_of_the_deployment(
    defender_indicator,
):
    connector = build_connector()
    adapter = MicrosoftDefenderDeploymentAdapter(connector)
    connector.api._send_request.side_effect = [
        {"value": [{**defender_indicator, "application": APPLICATION_NAME}]},
    ]
    deployment = IndicatorDeployment(
        relationship_id="relationship",
        status="active",
        indicator_id=INDICATOR_ID,
        indicator_standard_id=f"indicator--{INDICATOR_ID}",
        external_id=DEFENDER_ID,
        pattern="[ipv4-addr:value = '198.51.100.7']",
        pattern_type="stix",
    )

    assert adapter.confirm_absent(deployment) is False


def test_adapter_absence_lookup_errors_are_readable():
    connector = build_connector()
    adapter = MicrosoftDefenderDeploymentAdapter(connector)
    connector.api._send_request.side_effect = http_error(503, "Unavailable")

    with pytest.raises(DefenderDeploymentError, match="503"):
        adapter.confirm_absent(make_pattern_deployment(IP_AND_DOMAIN))


def test_delete_is_reported_removed(connector):
    connector.api._send_request.side_effect = [
        {"value": [own(DEFENDER_ID)]},
        None,
    ]
    connector.helper.api.external_reference.read.return_value = {"id": "ref"}
    indicator = make_indicator()

    connector.process_message(make_message("delete", indicator))

    connector.assurance.report_removed.assert_called_once_with(
        indicator, external_id=DEFENDER_ID
    )
    connector.helper.api.external_reference.delete.assert_called_once_with("ref")


def test_delete_never_removes_a_defender_indicator_of_another_indicator(connector):
    connector.api._send_request.return_value = {
        "value": [own("77", opencti_id="another-indicator"), {"id": "78"}]
    }
    indicator = make_indicator()

    connector.process_message(make_message("delete", indicator))

    assert [entry for entry in _sent(connector) if entry[0] == "delete"] == []
    connector.assurance.report_removed.assert_called_once_with(
        indicator, external_id=None
    )


def test_delete_of_an_absent_indicator_is_reported_removed(connector):
    connector.api._send_request.return_value = {"value": []}
    indicator = make_indicator()

    connector.process_message(make_message("delete", indicator))

    connector.assurance.report_removed.assert_called_once_with(
        indicator, external_id=None
    )


def test_failed_delete_is_not_reported_removed(connector):
    connector.api._send_request.side_effect = [
        {"value": [own(DEFENDER_ID)]},
        http_error(500, "Internal error"),
    ]

    connector.process_message(make_message("delete", make_indicator()))

    connector.assurance.report_removed.assert_not_called()


def test_external_reference_cleanup_errors_are_logged(connector):
    connector.api._send_request.side_effect = [
        {"value": [own(DEFENDER_ID)]},
        None,
    ]
    connector.helper.api.external_reference.read.side_effect = ValueError("boom")

    connector.process_message(make_message("delete", make_indicator()))

    connector.assurance.report_removed.assert_called_once()
    connector.helper.connector_logger.warning.assert_called_once_with(
        "[DELETE] Cannot delete the Microsoft Defender external reference",
        meta={"defender_id": DEFENDER_ID, "error": "boom"},
    )


def test_connector_works_without_write_back():
    connector = build_connector()
    connector.api._send_request.return_value = {"id": DEFENDER_ID}

    connector.process_message(make_message("create", make_indicator()))

    connector.api._send_request.assert_called_once()


def retried_withdrawal(connector):
    """Run the connector and return the withdrawal its retries call."""
    connector.pending_withdrawals.start_retries = MagicMock()
    connector.run()
    return connector.pending_withdrawals.start_retries.call_args.args[0]


def test_run_starts_the_write_back(connector):
    retried_withdrawal(connector)

    connector.assurance.start.assert_called_once_with()
    connector.helper.listen_stream.assert_called_once_with(
        message_callback=connector.process_message
    )


def test_a_former_value_a_delete_left_is_deleted_by_the_retries(connector):
    """A deleted indicator gets no later event: the periodic retries delete the
    Defender indicators of the former value, found by the OpenCTI id they carry."""
    keep_former_value(connector)
    connector.api._send_request.side_effect = [
        {"value": [own("1"), own("77", opencti_id="another-indicator")]},
        None,
    ]
    retry = retried_withdrawal(connector)

    connector.pending_withdrawals.retry_all(retry)

    assert [entry for entry in _sent(connector) if entry[0] == "delete"] == [
        ("delete", "/1")
    ]
    assert kept_former_values(connector) == []


def test_a_retry_waits_for_an_update_in_progress(connector):
    """A retry never deletes a value an update in progress makes current again."""
    pending = connector.pending_withdrawals
    in_update = []
    connector._apply_update_event = lambda data, context: in_update.append(
        pending.lock._is_owned()
    )

    connector._handle_update_event(make_indicator())

    assert in_update == [True]


def test_describe_error():
    error = DefenderApiHandlerError("[API] Failed", {})

    assert describe_error(error) == "[API] Failed"
    error.__cause__ = requests.Timeout("read timeout")
    assert describe_error(error) == "[API] Failed: read timeout"
    assert describe_error(ValueError()) == "ValueError"


# Settings and factory


def test_write_back_settings_defaults():
    settings = make_settings()

    assert settings.deployment.reporting_enabled is True
    assert settings.deployment.reconciliation_interval == 60
    assert settings.hits.reporting_enabled is True
    assert settings.security_platform.name == "Microsoft Defender for Endpoint"
    assert settings.security_platform.type == "EDR"
    assert settings.security_platform.id is None


def test_build_deployment_assurance_wires_reconciliation_and_hits():
    connector = build_connector()

    assurance = build_deployment_assurance(connector)

    assert assurance.enabled is True
    assert assurance.reporter.hits_enabled is True
    assert isinstance(assurance.reconciler._adapter, MicrosoftDefenderDeploymentAdapter)


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


# API handler


def serve_pages(rows, before_page=None):
    """Serve `rows` with the `$top` / `$skip` of each request (an OData collection).

    :param before_page: Called with the page number before serving it, to change rows
    """
    pages = []

    def _send_request(method, url, params):
        query = dict(part.split("=", 1) for part in params.split("&"))
        if before_page is not None:
            before_page(len(pages))
        skip, top = int(query["$skip"]), int(query["$top"])
        pages.append(skip)
        return {"value": [{"id": row} for row in rows[skip : skip + top]]}

    return _send_request, pages


def test_iter_application_indicators_pages_with_top_and_overlapping_skip():
    connector = build_connector()
    connector.api._send_request.side_effect = [
        {"value": [{"id": "1"}, {"id": "2"}]},
        {"value": [{"id": "2"}, {"id": "3"}]},
        {"value": [{"id": "3"}]},
    ]

    indicators = list(connector.api.iter_application_indicators(page_size=2))

    assert [indicator["id"] for indicator in indicators] == ["1", "2", "3"]
    first, second, third = connector.api._send_request.call_args_list
    assert first.args == ("get", INDICATORS_URL)
    assert first.kwargs["params"] == (
        "$filter=application%20eq%20%27OpenCTI%20Microsoft%20Defender%20Intel%27"
        "&$top=2&$skip=0"
    )
    assert second.kwargs["params"].endswith("&$top=2&$skip=1")
    assert third.kwargs["params"].endswith("&$top=2&$skip=2")


def test_iter_application_indicators_reads_every_row_once():
    connector = build_connector()
    rows = [str(row) for row in range(10)]
    connector.api._send_request.side_effect, pages = serve_pages(rows)

    indicators = list(connector.api.iter_application_indicators(page_size=4))

    assert [indicator["id"] for indicator in indicators] == rows
    assert pages == [0, 3, 6, 9]


@pytest.mark.parametrize("change", ["deleted", "created"])
def test_iter_application_indicators_fails_when_rows_move_between_pages(change):
    """A row deleted (or created) before the page boundary shifts the offsets: the
    next page would skip (or repeat) a row, so the listing is discarded."""
    connector = build_connector()
    rows = [str(row) for row in range(10)]

    def before_page(page):
        if page == 1:
            if change == "deleted":
                rows.remove("0")
            else:
                rows.insert(0, "new")

    connector.api._send_request.side_effect, _pages = serve_pages(rows, before_page)

    with pytest.raises(DefenderApiHandlerError) as error:
        list(connector.api.iter_application_indicators(page_size=4))

    assert error.value.msg.startswith("[API] Indicators changed during the read-back")
    assert error.value.metadata == {"page": 1, "skip": 3}


def test_iter_application_indicators_needs_two_rows_per_page():
    connector = build_connector()

    with pytest.raises(ValueError, match="at least 2"):
        list(connector.api.iter_application_indicators(page_size=1))

    connector.api._send_request.assert_not_called()


def test_iter_application_indicators_never_returns_a_partial_listing():
    connector = build_connector()
    rows = [str(row) for row in range(10)]
    connector.api._send_request.side_effect, _pages = serve_pages(rows)

    with pytest.raises(DefenderApiHandlerError) as error:
        list(connector.api.iter_application_indicators(page_size=2, max_pages=3))

    assert error.value.metadata == {"max_pages": 3, "page_size": 2}

    connector.api._send_request.side_effect = None
    connector.api._send_request.return_value = None
    with pytest.raises(DefenderApiHandlerError) as error:
        list(connector.api.iter_application_indicators())
    assert error.value.msg.startswith("[API] Unexpected response format")


def test_a_page_with_a_malformed_row_is_rejected_not_shortened():
    """A shortened full page would end the listing early: the indicators of the
    following pages would be reported removed."""
    connector = build_connector()
    connector.api._send_request.return_value = {
        "value": [{"id": "1"}, "not an indicator", {"id": "3"}]
    }

    with pytest.raises(DefenderApiHandlerError) as error:
        list(connector.api.iter_application_indicators(page_size=3))
    assert error.value.msg == (
        "[API] Unexpected response format: a 'value' row is not an object"
    )
    with pytest.raises(DefenderApiHandlerError):
        connector.api.list_alerts(datetime(2026, 10, 3, 10, 0, tzinfo=UTC))


def test_list_alerts_expands_the_evidence_and_is_bounded(monkeypatch):
    monkeypatch.setattr(
        "microsoft_defender_intel_connector.api_handler.MAX_PAGE_SIZE", 2
    )
    connector = build_connector()
    connector.api._send_request.side_effect = [
        {"value": [{"id": "a1"}, {"id": "a2"}]},
        {"value": [{"id": "a3"}, {"id": "a4"}]},
    ]
    since = datetime(2026, 10, 3, 10, 0, tzinfo=UTC)

    alerts = connector.api.list_alerts(since, max_alerts=3)

    assert [alert["id"] for alert in alerts] == ["a1", "a2", "a3"]
    first, second = connector.api._send_request.call_args_list
    assert first.args == ("get", ALERTS_URL)
    assert first.kwargs["params"] == (
        "$filter=alertCreationTime%20ge%202026-10-03T10%3A00%3A00Z"
        "&$expand=evidence&$top=2&$skip=0"
    )
    assert second.kwargs["params"].endswith("&$top=1&$skip=2")


def test_list_alerts_stops_on_a_short_page():
    connector = build_connector()
    connector.api._send_request.return_value = {"value": [{"id": "a1"}]}

    alerts = connector.api.list_alerts(datetime.now(UTC), max_alerts=50)

    assert alerts == [{"id": "a1"}]
    connector.api._send_request.assert_called_once()


# Vendor adapter


def test_adapter_lists_the_indicators_of_the_connector():
    """Expired Defender indicators stay in Defender: listed inactive, so that a
    withdrawal still deletes them."""
    connector = build_connector()
    future = (datetime.now(UTC) + timedelta(days=1)).isoformat()
    past = (datetime.now(UTC) - timedelta(days=1)).isoformat()
    connector.api.iter_application_indicators = MagicMock(
        return_value=iter(
            [
                {
                    "id": 1,
                    "indicatorValue": "198.51.100.7",
                    "externalId": INDICATOR_ID,
                    "expirationTime": future,
                },
                {"id": 2, "indicatorValue": "203.0.113.9", "externalId": None},
                {"id": 3, "indicatorValue": "old.example", "expirationTime": past},
            ]
        )
    )

    vendor_indicators = list(
        MicrosoftDefenderDeploymentAdapter(connector).list_vendor_indicators()
    )

    assert vendor_indicators == [
        VendorIndicator(
            indicator_id=INDICATOR_ID, external_id="1", value="198.51.100.7"
        ),
        VendorIndicator(indicator_id=None, external_id="2", value="203.0.113.9"),
        VendorIndicator(
            indicator_id=None, external_id="3", value="old.example", active=False
        ),
    ]
    connector.api.iter_application_indicators.assert_called_once_with(APPLICATION_NAME)


def test_adapter_read_back_expiry_uses_the_injected_clock():
    connector = build_connector()
    connector.api.iter_application_indicators = MagicMock(
        return_value=iter(
            [{"id": 1, "expirationTime": "2026-10-03T12:00:00Z"}],
        )
    )
    before = datetime(2026, 10, 3, 11, 0, tzinfo=UTC)

    (listed,) = MicrosoftDefenderDeploymentAdapter(
        connector, clock=lambda: before
    ).list_vendor_indicators()

    assert listed.active is True


def test_adapter_read_back_rejects_an_indicator_without_id():
    """A skipped indicator would make its deployment look absent."""
    connector = build_connector()
    connector.api.iter_application_indicators = MagicMock(
        return_value=iter([{"id": 1}, {"indicatorValue": "no-id.example"}])
    )

    with pytest.raises(DefenderDeploymentError, match="carries no id"):
        list(MicrosoftDefenderDeploymentAdapter(connector).list_vendor_indicators())


@pytest.mark.parametrize("expiration", ["next week", 1893456000, {}])
def test_adapter_read_back_rejects_an_unreadable_expiration(expiration):
    """Read as no expiry, an expired indicator would confirm its deployment."""
    connector = build_connector()
    connector.api.iter_application_indicators = MagicMock(
        return_value=iter([{"id": 1, "expirationTime": expiration}])
    )

    with pytest.raises(DefenderDeploymentError, match="unreadable expirationTime"):
        list(MicrosoftDefenderDeploymentAdapter(connector).list_vendor_indicators())


def test_adapter_read_back_reads_a_blank_expiration_as_none():
    connector = build_connector()
    connector.api.iter_application_indicators = MagicMock(
        return_value=iter([{"id": 1, "expirationTime": " "}])
    )

    (listed,) = MicrosoftDefenderDeploymentAdapter(connector).list_vendor_indicators()

    assert listed.active is True


def test_adapter_does_not_confirm_an_absence_on_an_unreadable_expiration():
    connector = build_connector()
    adapter = MicrosoftDefenderDeploymentAdapter(connector)
    connector.api._send_request.side_effect = [
        {
            "value": [
                {
                    "id": "9",
                    "application": APPLICATION_NAME,
                    "expirationTime": "next week",
                }
            ]
        },
    ]

    with pytest.raises(DefenderDeploymentError, match="unreadable expirationTime"):
        adapter.confirm_absent(make_pattern_deployment(IP_AND_DOMAIN))


def test_adapter_read_back_errors_are_readable():
    connector = build_connector()
    connector.api.iter_application_indicators = MagicMock(
        side_effect=http_error(401, "Unauthorized")
    )

    with pytest.raises(DefenderDeploymentError, match="401 Client Error"):
        list(MicrosoftDefenderDeploymentAdapter(connector).list_vendor_indicators())


def test_adapter_removal():
    connector = build_connector()
    adapter = MicrosoftDefenderDeploymentAdapter(connector)
    vendor_indicator = VendorIndicator(external_id=DEFENDER_ID, raw={"id": 6371})

    adapter.remove_vendor_indicator(vendor_indicator, make_deployment())
    connector.api._send_request.assert_called_once_with(
        "delete", f"{INDICATORS_URL}/6371"
    )

    connector.api._send_request.side_effect = http_error(404, "Not found")
    adapter.remove_vendor_indicator(vendor_indicator, make_deployment())

    connector.api._send_request.side_effect = http_error(403, "Forbidden")
    with pytest.raises(DefenderDeploymentError, match="Forbidden"):
        adapter.remove_vendor_indicator(vendor_indicator, make_deployment())


def test_adapter_push():
    connector = build_connector()
    adapter = MicrosoftDefenderDeploymentAdapter(connector)
    connector.api._send_request.return_value = {"id": DEFENDER_ID}

    assert adapter.push_indicator(make_indicator()) == DEFENDER_ID

    indicator = make_indicator()
    del indicator["extensions"][OPENCTI_EXTENSION_ID]["observable_values"]
    with pytest.raises(ValueError, match="No observable"):
        adapter.push_indicator(indicator)

    connector.api._send_request.side_effect = http_error(400, "Invalid value")
    with pytest.raises(DefenderDeploymentError) as error:
        adapter.push_indicator(make_indicator())
    assert str(error.value) == (
        "Microsoft Defender refused the indicator submission: invalid request"
    )
    connector.helper.connector_logger.warning.assert_called_with(
        "Indicator not pushed again to Microsoft Defender",
        meta={
            "error": "[API] An error occurred during request: 400 Client Error"
            " - Invalid value"
        },
    )


def test_adapter_collects_hits_from_alert_evidence():
    connector = build_connector()
    since = datetime(2026, 10, 3, 11, 0, tzinfo=UTC)
    sha256 = "37c09c95f77e5677332de338b7e972cff67347ed2c807c15b415c41b0d4a9ac4"
    connector.api.list_alerts = MagicMock(
        return_value=[
            {
                "alertCreationTime": "2026-10-03T11:10:00Z",
                "evidence": [{"entityType": "Ip", "ipAddress": "198.51.100.7"}],
            },
            {
                "alertCreationTime": "2026-10-03T11:20:00Z",
                "evidence": [
                    {"entityType": "Url", "url": "https://evil.example/payload"},
                    {"entityType": "File", "sha256": sha256.upper()},
                ],
            },
            {
                "alertCreationTime": "2026-10-03T11:30:00Z",
                "evidence": [{"entityType": "User", "domainName": "EVIL.EXAMPLE"}],
            },
            {
                "alertCreationTime": "2026-10-03T10:00:00Z",
                "evidence": [{"ipAddress": "198.51.100.7"}],
            },
        ]
    )
    deployments = [
        make_deployment(),
        IndicatorDeployment(
            relationship_id="r2",
            status="active",
            indicator_id=OTHER_ID,
            pattern="[domain-name:value = 'evil.example']",
            pattern_type="stix",
        ),
        IndicatorDeployment(
            relationship_id="r3",
            status="active",
            indicator_id="hash-indicator",
            pattern=f"[file:hashes.'SHA-256' = '{sha256}']",
            pattern_type="stix",
        ),
    ]

    until = datetime(2026, 10, 3, 12, 0, tzinfo=UTC)
    adapter = MicrosoftDefenderDeploymentAdapter(connector, clock=lambda: until)

    hits = list(adapter.collect_hits(deployments, since))

    assert [(hit.indicator_id, hit.timestamp.minute) for hit in hits] == [
        (INDICATOR_ID, 10),
        (OTHER_ID, 20),
        ("hash-indicator", 20),
    ]
    connector.api.list_alerts.assert_called_once_with(since, 10_000, until=until)


def test_adapter_credits_every_indicator_sharing_an_evidence_value():
    connector = build_connector()
    since = datetime(2026, 10, 3, 11, 0, tzinfo=UTC)
    connector.api.list_alerts = MagicMock(
        return_value=[
            {
                "alertCreationTime": "2026-10-03T11:10:00Z",
                "evidence": [{"entityType": "Ip", "ipAddress": "198.51.100.7"}],
            }
        ]
    )
    deployments = [
        make_deployment(),
        IndicatorDeployment(
            relationship_id="r2",
            status="active",
            indicator_id=OTHER_ID,
            pattern="[ipv4-addr:value = '198.51.100.7']",
            pattern_type="stix",
        ),
    ]
    adapter = MicrosoftDefenderDeploymentAdapter(
        connector, clock=lambda: datetime(2026, 10, 3, 12, 0, tzinfo=UTC)
    )

    hits = list(adapter.collect_hits(deployments, since))

    assert sorted(hit.indicator_id for hit in hits) == sorted([INDICATOR_ID, OTHER_ID])


def test_adapter_credits_no_hit_to_a_value_never_pushed_to_defender():
    """Only the values the connector pushes match the evidence: a network traffic
    address or an artifact hash of the pattern never has a Defender indicator."""
    connector = build_connector()
    since = datetime(2026, 10, 3, 11, 0, tzinfo=UTC)
    sha256 = "37c09c95f77e5677332de338b7e972cff67347ed2c807c15b415c41b0d4a9ac4"
    connector.api.list_alerts = MagicMock(
        return_value=[
            {
                "alertCreationTime": "2026-10-03T11:10:00Z",
                "evidence": [
                    {"entityType": "Ip", "ipAddress": "203.0.113.9"},
                    {"entityType": "File", "sha256": sha256},
                ],
            }
        ]
    )
    deployments = [
        IndicatorDeployment(
            relationship_id="r1",
            status="active",
            indicator_id=INDICATOR_ID,
            pattern=(
                "[network-traffic:dst_ref.value = '203.0.113.9'] OR "
                f"[artifact:hashes.'SHA-256' = '{sha256}'] OR "
                "[ipv4-addr:value = '198.51.100.7']"
            ),
            pattern_type="stix",
        ),
        IndicatorDeployment(
            relationship_id="r2",
            status="active",
            indicator_id=OTHER_ID,
            pattern=f"[file:hashes.'SHA-256' = '{sha256}']",
            pattern_type="stix",
        ),
    ]
    adapter = MicrosoftDefenderDeploymentAdapter(
        connector, clock=lambda: datetime(2026, 10, 3, 12, 0, tzinfo=UTC)
    )

    hits = list(adapter.collect_hits(deployments, since))

    assert [hit.indicator_id for hit in hits] == [OTHER_ID]


def serve_alerts(minutes):
    """Fake `list_alerts`: the alerts created at `11:<minute>` within the window,
    capped like the API (in no particular order)."""
    times = [datetime(2026, 10, 3, 11, minute, tzinfo=UTC) for minute in minutes]

    def _list_alerts(since, max_alerts, until):
        return [
            {
                "alertCreationTime": time.isoformat(),
                "evidence": [{"ipAddress": "198.51.100.7"}],
            }
            for time in reversed(times)
            if since <= time < until
        ][:max_alerts]

    return MagicMock(side_effect=_list_alerts)


HIT_SINCE = datetime(2026, 10, 3, 11, 0, tzinfo=UTC)
HIT_UNTIL = datetime(2026, 10, 3, 12, 0, tzinfo=UTC)


@pytest.mark.parametrize(
    "alert",
    [
        {"evidence": [{"ipAddress": "198.51.100.7"}]},
        {
            "alertCreationTime": "not a date",
            "evidence": [{"ipAddress": "198.51.100.7"}],
        },
    ],
)
def test_adapter_hit_read_rejects_an_alert_without_creation_time(alert):
    """A skipped alert would be lost: the hit window moves past its evidence."""
    connector = build_connector()
    since = datetime(2026, 10, 3, 11, 0, tzinfo=UTC)
    connector.api.list_alerts = MagicMock(
        return_value=[
            {
                "alertCreationTime": "2026-10-03T11:10:00Z",
                "evidence": [{"ipAddress": "198.51.100.7"}],
            },
            alert,
        ]
    )
    until = datetime(2026, 10, 3, 12, 0, tzinfo=UTC)
    adapter = MicrosoftDefenderDeploymentAdapter(connector, clock=lambda: until)

    with pytest.raises(DefenderDeploymentError, match="carries no creation time"):
        adapter.collect_hits([make_deployment()], since)


@pytest.mark.parametrize(
    ("alert", "message"),
    [
        ({}, "carries no evidence list"),
        ({"evidence": None}, "carries no evidence list"),
        ({"evidence": {"ipAddress": "198.51.100.7"}}, "carries no evidence list"),
        ({"evidence": ["198.51.100.7"]}, "evidence that is not an object"),
    ],
)
def test_adapter_hit_read_rejects_an_alert_with_malformed_evidence(alert, message):
    """A skipped evidence would be lost: the hit window moves past its matches."""
    connector = build_connector()
    since = datetime(2026, 10, 3, 11, 0, tzinfo=UTC)
    connector.api.list_alerts = MagicMock(
        return_value=[{"alertCreationTime": "2026-10-03T11:10:00Z", **alert}]
    )
    until = datetime(2026, 10, 3, 12, 0, tzinfo=UTC)
    adapter = MicrosoftDefenderDeploymentAdapter(connector, clock=lambda: until)

    with pytest.raises(DefenderDeploymentError, match=message):
        adapter.collect_hits([make_deployment()], since)


def test_adapter_halves_capped_alert_windows(monkeypatch):
    """The alerts API is unordered: a capped window is read again by halves until
    every alert of the period is read."""
    monkeypatch.setattr(
        "microsoft_defender_intel_connector.deployment.MAX_HIT_ALERTS", 2
    )
    connector = build_connector()
    connector.api.list_alerts = serve_alerts([5, 10, 40])
    adapter = MicrosoftDefenderDeploymentAdapter(connector, clock=lambda: HIT_UNTIL)

    hits = adapter.collect_hits([make_deployment()], HIT_SINCE)

    assert sorted(hit.timestamp.minute for hit in hits) == [5, 10, 40]
    windows = [
        (call.args[0].minute, call.kwargs["until"].minute)
        for call in connector.api.list_alerts.call_args_list
    ]
    assert windows[:3] == [(0, 0), (0, 30), (0, 15)]


def test_adapter_hit_windows_resume_after_the_read_budget(monkeypatch):
    """Once the read budget is spent, the hits are complete until the first window
    left unread, where the next run resumes."""
    monkeypatch.setattr(
        "microsoft_defender_intel_connector.deployment.MAX_HIT_ALERTS", 2
    )
    monkeypatch.setattr(
        "microsoft_defender_intel_connector.deployment.MAX_HIT_WINDOW_READS", 3
    )
    connector = build_connector()
    connector.api.list_alerts = serve_alerts([5, 40, 50])
    adapter = MicrosoftDefenderDeploymentAdapter(connector, clock=lambda: HIT_UNTIL)

    collection = adapter.collect_hits([make_deployment()], HIT_SINCE)

    assert isinstance(collection, HitCollection)
    assert collection.complete_until == datetime(2026, 10, 3, 11, 30, tzinfo=UTC)
    assert [hit.timestamp.minute for hit in collection.hits] == [5]


def test_adapter_resumes_halving_where_the_read_budget_ran_out(monkeypatch):
    """The alerts API is unordered, so a read is never continued by offset: when the
    requests run out before the first window is read, the next read halves that
    window further instead of starting again from the whole period."""
    monkeypatch.setattr(
        "microsoft_defender_intel_connector.deployment.MAX_HIT_ALERTS", 2
    )
    monkeypatch.setattr(
        "microsoft_defender_intel_connector.deployment.MAX_HIT_WINDOW_READS", 2
    )
    connector = build_connector()
    connector.api.list_alerts = serve_alerts([5, 20, 25, 40])
    adapter = MicrosoftDefenderDeploymentAdapter(connector, clock=lambda: HIT_UNTIL)
    quarter = HIT_SINCE + timedelta(minutes=15)

    first = adapter.collect_hits([make_deployment()], HIT_SINCE)
    assert isinstance(first, HitCollection)
    assert (first.complete_until, first.resume, first.hits) == (HIT_SINCE, quarter, [])

    connector.api.list_alerts.reset_mock()
    second = adapter.collect_hits([make_deployment()], HIT_SINCE, resume=quarter)
    assert connector.api.list_alerts.call_args_list[0] == call(
        HIT_SINCE, 2, until=quarter
    )
    assert (second.complete_until, second.resume) == (quarter, None)
    assert [hit.timestamp.minute for hit in second.hits] == [5]


def test_adapter_reports_a_capped_minimal_window_at_the_start_as_a_lower_bound(
    monkeypatch,
):
    """A smallest window still capped cannot be split: its alerts are a lower bound
    and the next read starts at its end, never re-reading it by offset."""
    monkeypatch.setattr(
        "microsoft_defender_intel_connector.deployment.MAX_HIT_ALERTS", 2
    )
    monkeypatch.setattr(
        "microsoft_defender_intel_connector.deployment.MIN_HIT_WINDOW",
        timedelta(hours=1),
    )
    connector = build_connector()
    connector.api.list_alerts = serve_alerts([5, 10, 20])
    adapter = MicrosoftDefenderDeploymentAdapter(connector, clock=lambda: HIT_UNTIL)

    collection = adapter.collect_hits([make_deployment()], HIT_SINCE)

    assert isinstance(collection, HitCollection)
    assert (collection.complete_until, collection.resume) == (HIT_UNTIL, None)
    assert len(collection.hits) == 2
    connector.api.list_alerts.assert_called_once_with(HIT_SINCE, 2, until=HIT_UNTIL)


def test_adapter_hit_windows_are_split_and_resumed_on_whole_seconds(monkeypatch):
    """The alerts filter has a one-second precision: a window bound or a returned
    date with a fraction of a second would leave alerts between the read and it."""
    monkeypatch.setattr(
        "microsoft_defender_intel_connector.deployment.MAX_HIT_ALERTS", 2
    )
    monkeypatch.setattr(
        "microsoft_defender_intel_connector.deployment.MAX_HIT_WINDOW_READS", 2
    )
    since = datetime(2026, 10, 3, 11, 0, 0, 300000, tzinfo=UTC)
    connector = build_connector()
    connector.api.list_alerts = MagicMock(
        return_value=[
            {
                "alertCreationTime": "2026-10-03T11:00:00.500Z",
                "evidence": [{"ipAddress": "198.51.100.7"}],
            }
        ]
        * 2
    )
    clock = datetime(2026, 10, 3, 11, 0, 9, 700000, tzinfo=UTC)
    adapter = MicrosoftDefenderDeploymentAdapter(connector, clock=lambda: clock)

    collection = adapter.collect_hits([make_deployment()], since)

    bounds = [call.kwargs["until"] for call in connector.api.list_alerts.call_args_list]
    assert bounds == [
        datetime(2026, 10, 3, 11, 0, 10, tzinfo=UTC),
        datetime(2026, 10, 3, 11, 0, 5, tzinfo=UTC),
    ]
    assert collection.complete_until == since
    assert collection.resume == datetime(2026, 10, 3, 11, 0, 2, tzinfo=UTC)

    connector.api.list_alerts.reset_mock()
    capped_second = adapter.collect_hits(
        [make_deployment()], since, resume=collection.resume
    )

    # [since, 11:00:02) splits to [since, 11:00:01), the smallest window: the next
    # read starts at its whole-second end, not at `since` plus a step.
    assert capped_second.complete_until == datetime(2026, 10, 3, 11, 0, 1, tzinfo=UTC)
    assert capped_second.resume is None


def test_adapter_ignores_a_resume_outside_the_read_period(monkeypatch):
    monkeypatch.setattr(
        "microsoft_defender_intel_connector.deployment.MAX_HIT_ALERTS", 2
    )
    connector = build_connector()
    connector.api.list_alerts = serve_alerts([5])
    adapter = MicrosoftDefenderDeploymentAdapter(connector, clock=lambda: HIT_UNTIL)

    hits = adapter.collect_hits([make_deployment()], HIT_SINCE, resume=HIT_UNTIL)

    assert [hit.timestamp.minute for hit in hits] == [5]
    connector.api.list_alerts.assert_called_once_with(HIT_SINCE, 2, until=HIT_UNTIL)


def test_adapter_stops_at_a_capped_minimal_window_after_the_start(monkeypatch):
    monkeypatch.setattr(
        "microsoft_defender_intel_connector.deployment.MAX_HIT_ALERTS", 2
    )
    monkeypatch.setattr(
        "microsoft_defender_intel_connector.deployment.MIN_HIT_WINDOW",
        timedelta(minutes=30),
    )
    connector = build_connector()
    connector.api.list_alerts = serve_alerts([5, 40, 45, 50])
    adapter = MicrosoftDefenderDeploymentAdapter(connector, clock=lambda: HIT_UNTIL)

    collection = adapter.collect_hits([make_deployment()], HIT_SINCE)

    middle = HIT_SINCE + timedelta(minutes=30)
    assert isinstance(collection, HitCollection)
    assert (collection.complete_until, collection.resume) == (middle, None)
    assert [hit.timestamp.minute for hit in collection.hits] == [5]


def test_list_alerts_bounds_the_window():
    connector = build_connector()
    connector.api._send_request.return_value = {"value": []}

    connector.api.list_alerts(HIT_SINCE, max_alerts=5, until=HIT_UNTIL)

    params = connector.api._send_request.call_args.kwargs["params"]
    assert params.startswith(
        "$filter=alertCreationTime%20ge%202026-10-03T11%3A00%3A00Z"
        "%20and%20alertCreationTime%20lt%202026-10-03T12%3A00%3A00Z"
    )


def test_adapter_hits_without_values_read_no_alert():
    connector = build_connector()
    connector.api.list_alerts = MagicMock()
    deployment = IndicatorDeployment(
        relationship_id="r", status="deployed", indicator_id=INDICATOR_ID
    )

    adapter = MicrosoftDefenderDeploymentAdapter(connector)
    assert adapter.collect_hits([deployment], datetime.now(UTC)) == []
    connector.api.list_alerts.assert_not_called()


# End to end: stream processing and reconciliation through GraphQL


class GraphQLRouter:
    """Fake `helper.api.query` dispatching on the GraphQL operation name."""

    def __init__(self, deployments=None):
        self.calls = []
        self.deployments = deployments or []

    def __call__(self, query, variables=None):
        self.calls.append((query, variables))
        if "DeploymentWriteBackFeatures" in query:
            return {"data": {"indicators": {"edges": []}}}
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


def deployment_node(indicator_id, status, value, revoked=False):
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
            "connect_live_stream_id",
            "get_attribute_in_extension",
        ]
    )
    helper.api.query.side_effect = router
    connector = build_connector(helper=helper)
    connector.assurance = DeploymentAssurance.from_settings(
        helper,
        connector.config,
        adapter=MicrosoftDefenderDeploymentAdapter(connector),
        reporter_kwargs={"flush_interval": 3600.0},
    )
    return connector


def test_stream_outcomes_are_reported_in_one_batch(e2e_connector, router):
    e2e_connector.api._send_request.side_effect = [
        {"id": DEFENDER_ID},
        http_error(400, "Invalid value"),
    ]

    e2e_connector.process_message(make_message("create", make_indicator()))
    e2e_connector.process_message(
        make_message("create", make_indicator(indicator_id=OTHER_ID))
    )
    result = e2e_connector.assurance.flush()

    assert result.processed == 2
    assert router.calls_of("DeploymentSecurityPlatformAdd") == [
        {
            "input": {
                "name": "Microsoft Defender for Endpoint",
                "update": True,
                "security_platform_type": "EDR",
            }
        }
    ]
    (batch,) = router.calls_of("IndicatorReportDeployments(")
    deployed, failed = batch["reports"]
    assert deployed == {
        "indicatorId": INDICATOR_ID,
        "status": "deployed",
        "externalId": DEFENDER_ID,
    }
    assert failed["indicatorId"] == OTHER_ID
    assert failed["status"] == "failed"
    assert failed["metadata"]["error_message"] == (
        "Microsoft Defender refused the indicator submission: invalid request"
    )


def test_reconciliation_and_hits_are_reported(e2e_connector, router):
    router.deployments = [
        deployment_node(INDICATOR_ID, "deployed", "198.51.100.7"),
        deployment_node(OTHER_ID, "active", "203.0.113.9"),
    ]
    alert_time = (datetime.now(UTC) - timedelta(minutes=5)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    e2e_connector.api._send_request.side_effect = [
        {
            "value": [
                {
                    "id": 6371,
                    "indicatorValue": "198.51.100.7",
                    "externalId": INDICATOR_ID,
                }
            ]
        },
        # The absent indicator is looked up by its value before it is reported removed
        {"value": []},
        {
            "value": [
                {
                    "alertCreationTime": alert_time,
                    "evidence": [{"ipAddress": "198.51.100.7"}],
                }
            ]
        },
    ]

    summary = e2e_connector.assurance.reconciler.run_once()

    assert summary.skipped is False
    assert summary.confirmed_active == 1
    assert summary.marked_removed == 1
    assert summary.hits_reported == 1
    (batch,) = router.calls_of("IndicatorReportDeployments(")
    reports = {report["indicatorId"]: report for report in batch["reports"]}
    assert reports[INDICATOR_ID]["status"] == "active"
    assert reports[INDICATOR_ID]["externalId"] == "6371"
    assert reports[OTHER_ID]["status"] == "removed"
    (hits,) = router.calls_of("IndicatorReportHits(")
    assert hits["indicatorId"] == INDICATOR_ID
    assert hits["count"] == 1


def test_ioc_left_from_an_earlier_pattern_does_not_confirm_the_indicator(
    e2e_connector, router
):
    """The pattern no longer holds a value Defender takes: the Defender indicator
    of its earlier value is not confirmed, the indicator is pushed again."""
    email_pattern = "[email-addr:value = 'x@evil.example']"
    node = deployment_node(INDICATOR_ID, "active", "198.51.100.7")
    node["from"]["pattern"] = email_pattern
    router.deployments = [node]
    indicator = make_indicator()
    indicator["pattern"] = email_pattern
    indicator["extensions"][OPENCTI_EXTENSION_ID]["observable_values"] = [
        {"type": "Email-Addr", "value": "x@evil.example"}
    ]
    e2e_connector.helper.api.stix2.get_stix_bundle_or_object_from_entity_id.return_value = (
        indicator
    )
    e2e_connector.api._send_request.side_effect = [
        {
            "value": [
                {
                    "id": 6371,
                    "indicatorValue": "198.51.100.7",
                    "externalId": INDICATOR_ID,
                }
            ]
        },
        {"value": []},
    ]

    summary = e2e_connector.assurance.reconciler.run_once()

    assert summary.confirmed_active == 0
    assert summary.incomplete == 1
    assert summary.repush_failed == 1
    (batch,) = router.calls_of("IndicatorReportDeployments(")
    (report,) = batch["reports"]
    assert report["indicatorId"] == INDICATOR_ID
    assert report["status"] == "failed"
    assert report["metadata"]["error_message"] == (
        "No observable of the indicator can be pushed to Microsoft Defender"
    )


def test_withdrawal_deletes_every_ioc_of_the_indicator(e2e_connector, router):
    """An indicator pushed as several Defender IOCs (one per hash) is only reported
    removed once all of them are deleted."""
    router.deployments = [
        deployment_node(INDICATOR_ID, "active", "198.51.100.7", revoked=True)
    ]
    e2e_connector.api._send_request.side_effect = [
        {
            "value": [
                {"id": 6371, "indicatorValue": "a" * 64, "externalId": INDICATOR_ID},
                {"id": 6372, "indicatorValue": "b" * 32, "externalId": INDICATOR_ID},
            ]
        },
        None,
        None,
    ]

    summary = e2e_connector.assurance.reconciler.run_once()

    assert summary.withdrawn == 1
    assert summary.discovered == 0
    deletions = [
        call.args[1]
        for call in e2e_connector.api._send_request.call_args_list
        if call.args[0] == "delete"
    ]
    assert [url.rsplit("/", 1)[1] for url in deletions] == ["6371", "6372"]
    (batch,) = router.calls_of("IndicatorReportDeployments(")
    assert batch["reports"][0]["indicatorId"] == INDICATOR_ID
    assert batch["reports"][0]["status"] == "removed"


def test_withdrawal_of_a_value_held_for_another_indicator_is_reported(
    e2e_connector, router
):
    """A withdrawn indicator whose Defender indicator is gone is reported removed,
    even though Defender holds its value for another OpenCTI indicator, which stays."""
    router.deployments = [
        deployment_node(INDICATOR_ID, "active", "198.51.100.7", revoked=True),
        deployment_node(OTHER_ID, "active", "198.51.100.7"),
    ]
    other_indicator = {
        "id": 6372,
        "indicatorValue": "198.51.100.7",
        "externalId": OTHER_ID,
    }
    e2e_connector.api._send_request.side_effect = [
        {"value": [other_indicator]},
        # The withdrawn indicator is looked up by its value before it is reported removed
        {"value": [{**other_indicator, "application": APPLICATION_NAME}]},
        {"value": []},
    ]

    summary = e2e_connector.assurance.reconciler.run_once()

    assert summary.marked_removed == 1
    assert summary.confirmed_active == 1
    assert summary.absence_unconfirmed == 0
    assert [
        entry
        for entry in e2e_connector.api._send_request.call_args_list
        if entry.args[0] == "delete"
    ] == []
    (batch,) = router.calls_of("IndicatorReportDeployments(")
    reports = {report["indicatorId"]: report for report in batch["reports"]}
    assert reports[INDICATOR_ID]["status"] == "removed"
    assert reports[OTHER_ID]["status"] == "active"
    assert reports[OTHER_ID]["externalId"] == "6372"


def test_read_back_failure_skips_the_reconciliation(e2e_connector, router):
    router.deployments = [deployment_node(INDICATOR_ID, "active", "198.51.100.7")]
    e2e_connector.api._send_request.side_effect = http_error(503, "Unavailable")

    summary = e2e_connector.assurance.reconciler.run_once()

    assert summary.skipped is True
    assert "Unavailable" in summary.reason
    assert router.calls_of("IndicatorReportDeployments(") == []

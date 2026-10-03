from queue import Queue
from unittest.mock import MagicMock, call

import pytest
import requests
import splunk
from connectors_sdk import DeploymentAssurance
from splunk import SplunkConnector
from splunk_test_support import (
    INDICATOR_ID,
    INDICATOR_STIX_ID,
    OPENCTI_EXTENSION_ID,
    make_indicator,
    make_message,
)


@pytest.fixture
def assurance():
    return MagicMock(spec=DeploymentAssurance)


@pytest.fixture
def kvstore():
    return MagicMock()


@pytest.fixture
def connector(helper, kvstore, assurance):
    return SplunkConnector(
        helper,
        kvstore,
        Queue(),
        ignore_types=["identity"],
        consumer_count=1,
        assurance=assurance,
    )


def test_create_reports_the_pushed_indicator(connector, kvstore, assurance):
    indicator = make_indicator()

    connector.process_message(make_message("create", indicator))

    key, payload = kvstore.create.call_args.args
    assert key == INDICATOR_ID
    assert "extensions" not in payload
    assert payload["stream_name"] == "Splunk stream"
    assurance.report_pushed.assert_called_once_with(indicator, external_id=INDICATOR_ID)
    assurance.report_push_failed.assert_not_called()


def test_update_reports_the_pushed_indicator(connector, kvstore, assurance):
    indicator = make_indicator()

    connector.process_message(make_message("update", indicator))

    assert kvstore.update.call_args.args[0] == INDICATOR_ID
    assurance.report_pushed.assert_called_once_with(indicator, external_id=INDICATOR_ID)


@pytest.mark.parametrize("event", ["create", "update"])
def test_rejected_push_reports_the_failure_and_raises(
    connector, kvstore, assurance, event
):
    response = requests.Response()
    response.status_code = 400
    response._content = b"invalid document"
    error = requests.HTTPError("400 Client Error: Bad Request", response=response)
    getattr(kvstore, event).side_effect = error
    indicator = make_indicator()

    with pytest.raises(requests.HTTPError):
        connector.process_message(make_message(event, indicator))

    assurance.report_push_failed.assert_called_once_with(
        indicator, "400 Client Error: Bad Request - invalid document"
    )
    assurance.report_pushed.assert_not_called()


def test_delete_reports_the_removed_indicator(connector, kvstore, assurance):
    indicator = make_indicator()

    connector.process_message(make_message("delete", indicator))

    kvstore.delete.assert_called_once_with(INDICATOR_ID)
    assurance.report_removed.assert_called_once_with(
        indicator, external_id=INDICATOR_ID
    )


def test_failed_delete_is_not_reported_removed(connector, kvstore, assurance):
    kvstore.delete.side_effect = requests.HTTPError("500 Server Error")

    with pytest.raises(requests.HTTPError):
        connector.process_message(make_message("delete", make_indicator()))

    assurance.report_removed.assert_not_called()


def test_filtered_items_are_not_reported(connector, kvstore, assurance):
    identity = {
        "id": "identity--5d4f2a3b-8c9d-4e1f-a2b3-c4d5e6f7a8b9",
        "type": "identity",
        "name": "ACME",
        "extensions": {OPENCTI_EXTENSION_ID: {"id": "identity-id"}},
    }

    connector.process_message(make_message("create", identity))

    kvstore.create.assert_not_called()
    assurance.report_pushed.assert_not_called()


def test_items_without_extension_are_keyed_and_reported_by_stix_id(
    connector, kvstore, assurance
):
    indicator = make_indicator()
    del indicator["extensions"]

    connector.process_message(make_message("create", indicator))

    kvstore.create.assert_called_once()
    assert kvstore.create.call_args.args[0] == INDICATOR_STIX_ID
    assurance.report_pushed.assert_called_once_with(
        indicator, external_id=INDICATOR_STIX_ID
    )


def test_items_without_any_id_are_not_reported(connector, kvstore, assurance):
    indicator = make_indicator()
    del indicator["extensions"]
    del indicator["id"]

    connector.process_message(make_message("create", indicator))

    assurance.report_pushed.assert_not_called()


def test_connector_works_without_write_back(helper, kvstore):
    connector = SplunkConnector(helper, kvstore, Queue(), [], 1)

    connector.process_message(make_message("create", make_indicator()))
    connector.flush_deployment_reports()

    kvstore.create.assert_called_once()


def test_push_indicator_uses_the_create_path(connector, kvstore):
    indicator = make_indicator()

    assert connector.push_indicator(indicator) == INDICATOR_ID

    key, payload = kvstore.create.call_args.args
    assert key == INDICATOR_ID
    assert payload["type"] == "indicator"
    assert OPENCTI_EXTENSION_ID in indicator["extensions"]


def test_push_indicator_rejects_unusable_indicators(helper, kvstore, assurance):
    connector = SplunkConnector(
        helper, kvstore, Queue(), ["indicator"], 1, assurance=assurance
    )
    without_id = make_indicator()
    del without_id["extensions"]

    with pytest.raises(ValueError):
        connector.push_indicator(without_id)
    with pytest.raises(ValueError):
        connector.push_indicator(make_indicator())
    kvstore.create.assert_not_called()


def test_consume_flushes_the_reports_before_exiting(
    connector, kvstore, assurance, monkeypatch
):
    exit_codes = []

    def fake_exit(code):
        exit_codes.append(code)
        raise SystemExit(code)

    monkeypatch.setattr(splunk.os, "_exit", fake_exit)
    kvstore.create.side_effect = requests.HTTPError("500 Server Error")
    connector.queue.put(make_message("create", make_indicator()))

    with pytest.raises(SystemExit):
        connector.consume()

    assert exit_codes == [1]
    assurance.report_push_failed.assert_called_once()
    assurance.flush.assert_called_once_with()


def test_flush_errors_never_break_the_exit_path(connector, assurance, helper):
    assurance.flush.side_effect = RuntimeError("OpenCTI unavailable")

    connector.flush_deployment_reports()

    helper.log_warning.assert_called_once()


def test_start_starts_the_write_back_before_listening(
    connector, kvstore, assurance, monkeypatch
):
    events = MagicMock()
    assurance.start.side_effect = lambda: events.assurance_start()
    monkeypatch.setattr(connector, "register_producer", events.register_producer)
    monkeypatch.setattr(connector, "start_consumers", events.start_consumers)

    connector.start()

    kvstore.init.assert_called_once_with()
    assert events.mock_calls == [
        call.assurance_start(),
        call.register_producer(),
        call.start_consumers(),
    ]

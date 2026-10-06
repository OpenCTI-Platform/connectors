import json
from unittest.mock import Mock

from zscaler_responses import make_response

DOMAIN_PATTERN = "[domain-name:value = 'malicious.example.com']"


def _stream_message(event, data):
    msg = Mock()
    msg.event = event
    msg.data = json.dumps({"data": data})
    return msg


def _indicator(pattern=DOMAIN_PATTERN):
    return {"type": "indicator", "pattern_type": "stix", "pattern": pattern}


def _route(responses):
    """Return a fake ``client.request`` answering by (method, path)."""

    def fake_request(method, path, **kwargs):
        return responses[(method, path)]

    return fake_request


def test_create_event_should_add_domain_and_activate(connector):
    connector.client.request.side_effect = _route(
        {
            ("POST", "/urlLookup"): make_response(200, [{"urlClassifications": []}]),
            ("GET", "/urlCategories/CUSTOM_01"): make_response(
                200, {"configuredName": "OpenCTI blocklist", "urls": []}
            ),
            ("PUT", "/urlCategories/CUSTOM_01"): make_response(200),
            ("GET", "/status"): make_response(200, {"status": "PENDING"}),
        }
    )

    connector._process_message(_stream_message("create", _indicator()))

    put_call = next(
        c for c in connector.client.request.call_args_list if c.args[0] == "PUT"
    )
    assert put_call.kwargs == {
        "params": {"action": "ADD_TO_LIST"},
        "json": {
            "configuredName": "OpenCTI blocklist",
            "urls": ["malicious.example.com"],
        },
    }
    # The category is read once and the activation status is checked once
    methods = [c.args[:2] for c in connector.client.request.call_args_list]
    assert methods.count(("GET", "/urlCategories/CUSTOM_01")) == 1
    assert methods.count(("GET", "/status")) == 1


def test_create_event_should_skip_domain_already_blacklisted(connector):
    connector.client.request.side_effect = _route(
        {
            ("POST", "/urlLookup"): make_response(200, [{"urlClassifications": []}]),
            ("GET", "/urlCategories/CUSTOM_01"): make_response(
                200, {"configuredName": "x", "urls": ["malicious.example.com"]}
            ),
        }
    )

    connector._process_message(_stream_message("create", _indicator()))

    methods = [c.args[0] for c in connector.client.request.call_args_list]
    assert "PUT" not in methods


def test_send_should_not_activate_when_update_fails(connector):
    connector.client.request.return_value = make_response(500, {"code": "ERR"})

    connector.send_to_zscaler("malicious.example.com", "create", "x")

    methods = [c.args[:2] for c in connector.client.request.call_args_list]
    assert methods == [("PUT", "/urlCategories/CUSTOM_01")]


def test_non_stix_indicator_should_be_ignored(connector):
    connector._process_message(
        _stream_message("create", {"type": "indicator", "pattern_type": "yara"})
    )

    connector.client.request.assert_not_called()


def test_invalid_domain_should_not_call_zscaler(connector):
    connector._process_message(
        _stream_message("create", _indicator("[ipv4-addr:value = '1.2.3.4']"))
    )

    connector.client.request.assert_not_called()


def test_activation_should_retry_on_503(connector, monkeypatch):
    monkeypatch.setattr("stream_connector.connector.time.sleep", Mock())
    connector.client.request.side_effect = [
        make_response(200, {"status": "UNKNOWN"}),
        make_response(503, {"message": "busy"}),
        make_response(200, {"status": "UNKNOWN"}),
        make_response(200),
    ]

    assert connector.activate_zscaler_changes() is True


def test_activation_should_fail_on_unexpected_error(connector):
    connector.client.request.side_effect = [
        make_response(200, {"status": "UNKNOWN"}),
        make_response(400, {"message": "bad"}),
    ]

    assert connector.activate_zscaler_changes() is False

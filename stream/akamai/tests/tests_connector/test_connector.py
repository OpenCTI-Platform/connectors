"""Tests for Akamai connector."""

import json
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from akamai_connector.connector import AkamaiConnector, is_asn, is_ip


@pytest.fixture
def connector():
    """Create a lightweight AkamaiConnector instance for unit tests."""
    instance = AkamaiConnector.__new__(AkamaiConnector)

    instance.base_url = "https://example.akamaiapis.net"
    instance.client_list_id = "12345_IP_LIST"
    instance.asn_client_list_id = "12345_ASN_LIST"
    instance.helper = MagicMock()
    instance.session = MagicMock()

    return instance


def test_is_ip():
    assert is_ip("1.2.3.4") is True
    assert is_ip("2001:db8::1") is True
    assert is_ip("not-an-ip") is False


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("0", True),
        ("64512", True),
        ("200651", True),
        ("4294967295", True),
        ("-1", False),
        ("4294967296", False),
        ("invalid", False),
        ("AS64512", False),
        (None, False),
    ],
)
def test_is_asn(value, expected):
    assert is_asn(value) is expected


def test_connector_initialization():
    helper = MagicMock()

    client_token = MagicMock()
    client_token.get_secret_value.return_value = "client-token"

    client_secret = MagicMock()
    client_secret.get_secret_value.return_value = "client-secret"

    access_token = MagicMock()
    access_token.get_secret_value.return_value = "access-token"

    config = SimpleNamespace(
        akamai=SimpleNamespace(
            base_url="https://example.akamaiapis.net/",
            client_list_id="12345_IP_LIST",
            asn_client_list_id="12345_ASN_LIST",
            client_token=client_token,
            client_secret=client_secret,
            access_token=access_token,
        )
    )

    session = MagicMock()

    with (
        patch(
            "akamai_connector.connector.requests.Session",
            return_value=session,
        ),
        patch("akamai_connector.connector.EdgeGridAuth") as edgegrid_auth,
    ):
        connector = AkamaiConnector(config, helper)

    assert connector.base_url == "https://example.akamaiapis.net"
    assert connector.client_list_id == "12345_IP_LIST"
    assert connector.asn_client_list_id == "12345_ASN_LIST"
    assert connector.session is session
    assert connector.session.verify is True

    edgegrid_auth.assert_called_once_with(
        client_token="client-token",
        client_secret="client-secret",
        access_token="access-token",
    )

    session.headers.update.assert_called_once_with(
        {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
    )

    helper.connector_logger.info.assert_called_once()


def test_run(connector):
    connector.run()

    connector.helper.listen_stream.assert_called_once()

    callback = connector.helper.listen_stream.call_args.args[0]

    assert callback.__self__ is connector
    assert callback.__func__ is connector._process_message.__func__


@pytest.mark.parametrize(
    ("pattern", "expected"),
    [
        ("[ipv4-addr:value = '1.2.3.4']", "1.2.3.4"),
        ("[ipv6-addr:value = '2001:db8::1']", "2001:db8::1"),
        ("[ipv4-addr:value = '999.999.999.999']", None),
        ("[domain-name:value = 'example.com']", None),
        ("invalid-pattern", None),
    ],
)
def test_extract_ip_from_pattern(connector, pattern, expected):
    assert connector._extract_ip_from_pattern(pattern) == expected


@pytest.mark.parametrize(
    ("pattern", "expected"),
    [
        ("[autonomous-system:number = 64512]", "64512"),
        ("[autonomous-system:number = '64512']", "64512"),
        ("[autonomous-system:number = 'AS200651']", "200651"),
        ("[autonomous-system:number = 'as200651']", "200651"),
        ("[autonomous-system:number = 4294967295]", "4294967295"),
        ("[autonomous-system:number = 4294967296]", None),
        ("[autonomous-system:name = 'Example']", None),
        ("invalid-pattern", None),
    ],
)
def test_extract_asn_from_pattern(connector, pattern, expected):
    assert connector._extract_asn_from_pattern(pattern) == expected


@pytest.mark.parametrize(
    ("event", "method_name"),
    [
        ("create", "_add_ip"),
        ("delete", "_remove_ip"),
    ],
)
def test_process_ip_message(connector, event, method_name):
    connector._add_ip = MagicMock()
    connector._remove_ip = MagicMock()
    connector._add_asn = MagicMock()
    connector._remove_asn = MagicMock()

    msg = SimpleNamespace(
        data={
            "data": {
                "type": "indicator",
                "pattern_type": "stix",
                "pattern": "[ipv4-addr:value = '1.2.3.4']",
            }
        },
        event=event,
    )

    connector._process_message(msg)

    expected_method = getattr(connector, method_name)
    expected_method.assert_called_once_with("1.2.3.4")

    connector._add_asn.assert_not_called()
    connector._remove_asn.assert_not_called()


@pytest.mark.parametrize(
    ("event", "method_name"),
    [
        ("create", "_add_asn"),
        ("delete", "_remove_asn"),
    ],
)
def test_process_asn_message(connector, event, method_name):
    connector._add_ip = MagicMock()
    connector._remove_ip = MagicMock()
    connector._add_asn = MagicMock()
    connector._remove_asn = MagicMock()

    msg = SimpleNamespace(
        data={
            "data": {
                "type": "indicator",
                "pattern_type": "stix",
                "pattern": "[autonomous-system:number = 'AS200651']",
            }
        },
        event=event,
    )

    connector._process_message(msg)

    expected_method = getattr(connector, method_name)
    expected_method.assert_called_once_with("200651")

    connector._add_ip.assert_not_called()
    connector._remove_ip.assert_not_called()


def test_process_string_payload(connector):
    connector._add_asn = MagicMock()

    payload = {
        "data": {
            "type": "indicator",
            "pattern_type": "stix",
            "pattern": "[autonomous-system:number = 64512]",
        }
    }

    msg = SimpleNamespace(
        data=json.dumps(payload),
        event="create",
    )

    connector._process_message(msg)

    connector._add_asn.assert_called_once_with("64512")


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {
            "data": {
                "type": "malware",
                "pattern_type": "stix",
                "pattern": "[ipv4-addr:value = '1.2.3.4']",
            }
        },
        {
            "data": {
                "type": "indicator",
                "pattern_type": "yara",
                "pattern": "rule test {}",
            }
        },
        {
            "data": {
                "type": "indicator",
                "pattern_type": "stix",
            }
        },
    ],
)
def test_process_ignored_messages(connector, payload):
    connector._add_ip = MagicMock()
    connector._remove_ip = MagicMock()
    connector._add_asn = MagicMock()
    connector._remove_asn = MagicMock()

    msg = SimpleNamespace(
        data=payload,
        event="create",
    )

    connector._process_message(msg)

    connector._add_ip.assert_not_called()
    connector._remove_ip.assert_not_called()
    connector._add_asn.assert_not_called()
    connector._remove_asn.assert_not_called()


def test_process_unsupported_event(connector):
    connector._add_ip = MagicMock()
    connector._remove_ip = MagicMock()
    connector._add_asn = MagicMock()
    connector._remove_asn = MagicMock()

    msg = SimpleNamespace(
        data={
            "data": {
                "type": "indicator",
                "pattern_type": "stix",
                "pattern": "[autonomous-system:number = 64512]",
            }
        },
        event="update",
    )

    connector._process_message(msg)

    connector._add_ip.assert_not_called()
    connector._remove_ip.assert_not_called()
    connector._add_asn.assert_not_called()
    connector._remove_asn.assert_not_called()


def test_process_message_exception(connector):
    msg = SimpleNamespace(
        data="{invalid-json",
        event="create",
    )

    connector._process_message(msg)

    connector.helper.connector_logger.error.assert_called_once()


def test_add_ip(connector):
    response = MagicMock()
    response.status_code = 200
    connector.session.post.return_value = response

    connector._add_ip("1.2.3.4")

    connector.session.post.assert_called_once_with(
        "https://example.akamaiapis.net/client-list/v1/lists/" "12345_IP_LIST/items",
        json={"append": [{"value": "1.2.3.4"}]},
    )

    response.raise_for_status.assert_called_once()
    connector.helper.connector_logger.info.assert_called_once_with("Add IP success")


def test_remove_ip(connector):
    response = MagicMock()
    response.status_code = 200
    connector.session.post.return_value = response

    connector._remove_ip("1.2.3.4")

    connector.session.post.assert_called_once_with(
        "https://example.akamaiapis.net/client-list/v1/lists/" "12345_IP_LIST/items",
        json={"delete": [{"value": "1.2.3.4"}]},
    )

    response.raise_for_status.assert_called_once()
    connector.helper.connector_logger.info.assert_called_once_with("Remove IP success")


def test_remove_ip_not_present(connector):
    response = MagicMock()
    response.status_code = 400
    connector.session.post.return_value = response

    connector._remove_ip("1.2.3.4")

    connector.session.post.assert_called_once_with(
        "https://example.akamaiapis.net/client-list/v1/lists/" "12345_IP_LIST/items",
        json={"delete": [{"value": "1.2.3.4"}]},
    )

    response.raise_for_status.assert_not_called()

    connector.helper.connector_logger.info.assert_called_once_with(
        "IP 1.2.3.4 not present in Akamai list. Ignoring."
    )


def test_add_asn(connector):
    response = MagicMock()
    response.status_code = 200
    connector.session.post.return_value = response

    connector._add_asn("200651")

    connector.session.post.assert_called_once_with(
        "https://example.akamaiapis.net/client-list/v1/lists/" "12345_ASN_LIST/items",
        json={"append": [{"value": "200651"}]},
    )

    response.raise_for_status.assert_called_once()
    connector.helper.connector_logger.info.assert_called_once_with("Add ASN success")


def test_remove_asn(connector):
    response = MagicMock()
    response.status_code = 200
    connector.session.post.return_value = response

    connector._remove_asn("200651")

    connector.session.post.assert_called_once_with(
        "https://example.akamaiapis.net/client-list/v1/lists/" "12345_ASN_LIST/items",
        json={"delete": [{"value": "200651"}]},
    )

    response.raise_for_status.assert_called_once()
    connector.helper.connector_logger.info.assert_called_once_with("Remove ASN success")


def test_remove_asn_not_present(connector):
    response = MagicMock()
    response.status_code = 400
    connector.session.post.return_value = response

    connector._remove_asn("200651")

    connector.session.post.assert_called_once_with(
        "https://example.akamaiapis.net/client-list/v1/lists/" "12345_ASN_LIST/items",
        json={"delete": [{"value": "200651"}]},
    )

    response.raise_for_status.assert_not_called()

    connector.helper.connector_logger.info.assert_called_once_with(
        "ASN 200651 not present in Akamai list. Ignoring."
    )

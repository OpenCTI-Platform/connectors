# -*- coding: utf-8 -*-
"""Unit tests for the connector orchestration.

The OpenCTI helper, config resolution, API client and converter are mocked, so
these exercise the connector's own logic (premium parsing, value extraction and
message handling) without any SDK network access.
"""

import importlib.util
import os
import sys
from unittest.mock import MagicMock, patch

import pytest

SRC = os.path.join(os.path.dirname(__file__), "..", "src")
sys.path.insert(0, SRC)

SDK_AVAILABLE = (
    importlib.util.find_spec("connectors_sdk") is not None
    and importlib.util.find_spec("pycti") is not None
)

if SDK_AVAILABLE:
    from osint_industries.connector import OsintIndustriesConnector

sdk_required = pytest.mark.skipif(
    not SDK_AVAILABLE,
    reason="connectors_sdk / pycti not installed in this environment",
)


def build_connector(premium="false"):
    """Instantiate the connector with the SDK helper and config mocked out."""
    cfg = {
        "OSINT_INDUSTRIES_API_KEY": "key",
        "OSINT_INDUSTRIES_BASE_URL": "https://api.example",
        "OSINT_INDUSTRIES_TLP_LEVEL": "amber+strict",
        "OSINT_INDUSTRIES_PREMIUM": premium,
    }

    def fake_gcv(env_var, yaml_path, config, required=False, default=None):
        return cfg.get(env_var)

    with patch("osint_industries.connector.OpenCTIConnectorHelper"), patch(
        "osint_industries.connector.get_config_variable", side_effect=fake_gcv
    ):
        conn = OsintIndustriesConnector()

    conn.helper = MagicMock()
    conn.client = MagicMock()
    conn.converter = MagicMock()
    return conn


@sdk_required
@pytest.mark.parametrize(
    "value,expected",
    [
        ("true", True),
        ("True", True),
        ("1", True),
        ("false", False),
        ("no", False),
        (None, False),
    ],
)
def test_premium_parsing(value, expected):
    assert build_connector(premium=value).premium is expected


@sdk_required
def test_extract_value_variants():
    conn = build_connector()
    assert (
        conn._extract_value({"entity_type": "Email-Addr", "value": "a@b.com"})
        == "a@b.com"
    )
    assert (
        conn._extract_value({"entity_type": "User-Account", "account_login": "bob"})
        == "bob"
    )
    assert conn._extract_value({"entity_type": "Other", "observable_value": "x"}) == "x"
    assert conn._extract_value({"entity_type": "Email-Addr"}) is None


@sdk_required
def test_process_message_unsupported_type():
    conn = build_connector()
    conn.client.selector_type_for.return_value = None
    msg = conn._process_message({"enrichment_entity": {"entity_type": "Domain-Name"}})
    assert "Unsupported type" in msg


@sdk_required
def test_process_message_no_value():
    conn = build_connector()
    conn.client.selector_type_for.return_value = "email"
    msg = conn._process_message({"enrichment_entity": {"entity_type": "Email-Addr"}})
    assert "No usable value" in msg


@sdk_required
@pytest.mark.parametrize(
    "payload,expected",
    [
        (None, "request failed"),
        ([], "No OSINT Industries result"),
        ({}, "No OSINT Industries result"),
    ],
)
def test_process_message_empty_payloads(payload, expected):
    conn = build_connector()
    conn.client.selector_type_for.return_value = "email"
    conn.client.query.return_value = payload
    obs = {"entity_type": "Email-Addr", "value": "a@b.com"}
    assert expected in conn._process_message({"enrichment_entity": obs})


@sdk_required
def test_process_message_no_stix_objects():
    conn = build_connector()
    conn.client.selector_type_for.return_value = "email"
    conn.client.query.return_value = [{"module": "x"}]
    conn.converter.process.return_value = []
    obs = {"entity_type": "Email-Addr", "value": "a@b.com"}
    assert "No STIX object" in conn._process_message({"enrichment_entity": obs})


@sdk_required
def test_process_message_success():
    conn = build_connector()
    conn.client.selector_type_for.return_value = "email"
    conn.client.query.return_value = [{"module": "x"}]
    conn.converter.process.return_value = [object(), object()]
    conn.helper.stix2_create_bundle.return_value = "BUNDLE"
    obs = {"entity_type": "Email-Addr", "value": "a@b.com"}
    msg = conn._process_message({"enrichment_entity": obs})
    assert "Bundle sent: 2" in msg
    conn.helper.send_stix2_bundle.assert_called_once()


@sdk_required
def test_process_callback_success():
    conn = build_connector()
    conn.client.selector_type_for.return_value = None
    msg = conn._process_callback({"enrichment_entity": {"entity_type": "X"}})
    assert "Unsupported type" in msg


@sdk_required
def test_process_callback_handles_exception():
    conn = build_connector()
    # missing 'enrichment_entity' -> KeyError inside _process_message
    msg = conn._process_callback({})
    assert "Internal error" in msg
    conn.helper.connector_logger.error.assert_called()


@sdk_required
def test_run_starts_listener():
    conn = build_connector()
    conn.run()
    conn.helper.listen.assert_called_once()

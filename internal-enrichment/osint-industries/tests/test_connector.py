# -*- coding: utf-8 -*-
"""Unit tests for the connector orchestration.

The OpenCTI helper, config resolution, API client and converter are mocked, so
these exercise the connector's own logic (premium parsing, value extraction and
message handling) without any SDK network access.
"""

import importlib.util
import os
import sys
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

SRC = os.path.join(os.path.dirname(__file__), "..", "src")
sys.path.insert(0, SRC)

SDK_AVAILABLE = (
    importlib.util.find_spec("connectors_sdk") is not None
    and importlib.util.find_spec("pycti") is not None
)

if SDK_AVAILABLE:
    from osint_industries.connector import (
        MaxTlpExceededError,
        OsintIndustriesConnector,
    )
    from osint_industries.settings import ConnectorSettings

sdk_required = pytest.mark.skipif(
    not SDK_AVAILABLE,
    reason="connectors_sdk / pycti not installed in this environment",
)


def build_settings(premium="false", max_tlp=None):
    """Build a `ConnectorSettings` instance from a fake but valid config dict."""
    settings_dict = {
        "opencti": {"url": "http://localhost:8080", "token": "test-token"},
        "connector": {},
        "osint_industries": {
            "api_key": "key",
            "base_url": "https://api.example",
            "tlp_level": "amber+strict",
        },
    }
    if premium is not None:
        settings_dict["osint_industries"]["premium"] = premium
    if max_tlp is not None:
        settings_dict["osint_industries"]["max_tlp"] = max_tlp

    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(settings_dict)

    return FakeConnectorSettings()


def build_connector(premium="false", max_tlp=None):
    """Instantiate the connector with the SDK helper mocked out."""
    with patch("osint_industries.connector.OpenCTIConnectorHelper"):
        conn = OsintIndustriesConnector(
            config=build_settings(premium=premium, max_tlp=max_tlp)
        )

    conn.helper = MagicMock()
    conn.client = MagicMock()
    conn.converter = MagicMock()
    return conn


def tlp_marking(definition):
    return {"definition_type": "TLP", "definition": definition}


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
def test_send_bundle_uses_cleanup_inconsistent_bundle():
    """VC312 — every bundle MUST be sent with cleanup_inconsistent_bundle=True."""
    conn = build_connector()
    conn.helper.stix2_create_bundle.return_value = "BUNDLE"

    conn._send_bundle([{"type": "identity"}])

    _, kwargs = conn.helper.send_stix2_bundle.call_args
    assert kwargs["cleanup_inconsistent_bundle"] is True
    assert kwargs["update"] is True


@sdk_required
def test_send_bundle_does_not_mutate_caller_list():
    """`stix2_create_bundle` mutates its argument, so it MUST receive a copy."""
    conn = build_connector()
    conn.helper.stix2_create_bundle.return_value = "BUNDLE"
    original = [{"type": "identity"}]

    conn._send_bundle(original)

    passed = conn.helper.stix2_create_bundle.call_args[0][0]
    assert passed is not original
    assert passed == original


@sdk_required
@pytest.mark.parametrize(
    "data,expected",
    [
        # Playbook trigger: the platform omits event_type.
        ({}, True),
        ({"event_type": None}, True),
        ({"event_type": ""}, True),
        # Manual / automatic enrichment carries an event_type.
        ({"event_type": "create"}, False),
        ({"event_type": "update"}, False),
    ],
)
def test_is_playbook_context(data, expected):
    assert OsintIndustriesConnector._is_playbook_context(data) is expected


@sdk_required
def test_former_bundle_is_read_from_data():
    """VC322 — the original bundle MUST be read from data['stix_objects']."""
    former = [{"type": "email-addr", "value": "a@b.com"}]
    assert OsintIndustriesConnector._former_bundle({"stix_objects": former}) == former
    assert OsintIndustriesConnector._former_bundle({}) == []


@sdk_required
@pytest.mark.parametrize(
    "observable,selector,payload,converted,expected",
    [
        pytest.param(
            {"entity_type": "Domain-Name"},
            None,
            None,
            None,
            "Unsupported type",
            id="unsupported_entity_type",
        ),
        pytest.param(
            {"entity_type": "Email-Addr"},
            "email",
            None,
            None,
            "No usable value",
            id="no_usable_value",
        ),
        pytest.param(
            {"entity_type": "Email-Addr", "value": "a@b.com"},
            "email",
            None,
            None,
            "request failed",
            id="api_failure",
        ),
        pytest.param(
            {"entity_type": "Email-Addr", "value": "a@b.com"},
            "email",
            [],
            None,
            "No OSINT Industries result",
            id="empty_payload",
        ),
        pytest.param(
            {"entity_type": "Email-Addr", "value": "a@b.com"},
            "email",
            [{"module": "x"}],
            [],
            "No STIX object",
            id="nothing_converted",
        ),
    ],
)
def test_playbook_receives_untouched_bundle_when_no_enrichment(
    observable, selector, payload, converted, expected
):
    """Every no-enrichment path MUST hand the original bundle back to the playbook."""
    conn = build_connector(max_tlp="TLP:AMBER")
    conn.client.selector_type_for.return_value = selector
    conn.client.query.return_value = payload
    conn.converter.process.return_value = converted
    conn.helper.stix2_create_bundle.return_value = "BUNDLE"
    former = [{"type": "email-addr", "value": "a@b.com"}]
    # No event_type -> playbook context.
    data = {"enrichment_entity": observable, "stix_objects": former}

    msg = conn._process_message(data)

    assert expected in msg
    conn.helper.stix2_create_bundle.assert_called_once_with(former)
    conn.helper.send_stix2_bundle.assert_called_once()


@sdk_required
def test_playbook_receives_untouched_bundle_when_tlp_above_max():
    """A TLP-blocked observable MUST still let the playbook continue."""
    conn = build_connector(max_tlp="TLP:AMBER")
    conn.client.selector_type_for.return_value = "email"
    conn.helper.stix2_create_bundle.return_value = "BUNDLE"
    former = [{"type": "email-addr", "value": "a@b.com"}]
    data = {
        "enrichment_entity": {
            "entity_type": "Email-Addr",
            "value": "a@b.com",
            "objectMarking": [tlp_marking("TLP:RED")],
        },
        "stix_objects": former,
    }

    msg = conn._process_callback(data)

    assert "greater than OSINT_INDUSTRIES_MAX_TLP" in msg
    conn.client.query.assert_not_called()
    conn.helper.stix2_create_bundle.assert_called_once_with(former)
    conn.helper.send_stix2_bundle.assert_called_once()


@sdk_required
def test_manual_enrichment_does_not_resend_untouched_bundle():
    """Outside a playbook there is no pipeline to feed, so nothing is sent back."""
    conn = build_connector()
    conn.client.selector_type_for.return_value = None
    data = {
        "enrichment_entity": {"entity_type": "Domain-Name"},
        "stix_objects": [{"type": "domain-name", "value": "example.com"}],
        "event_type": "create",
    }

    msg = conn._process_message(data)

    assert "Unsupported type" in msg
    conn.helper.send_stix2_bundle.assert_not_called()


@sdk_required
def test_playbook_success_appends_enrichment_to_former_bundle():
    """On success the enriched objects MUST be appended to the original bundle."""
    conn = build_connector()
    conn.client.selector_type_for.return_value = "email"
    conn.client.query.return_value = [{"module": "x"}]
    enriched = [object(), object()]
    conn.converter.process.return_value = enriched
    conn.helper.stix2_create_bundle.return_value = "BUNDLE"
    former = [{"type": "email-addr", "value": "a@b.com"}]
    data = {
        "enrichment_entity": {"entity_type": "Email-Addr", "value": "a@b.com"},
        "stix_objects": former,
    }

    msg = conn._process_message(data)

    assert "Bundle sent: 2" in msg
    conn.helper.stix2_create_bundle.assert_called_once_with(former + enriched)


@sdk_required
def test_playbook_receives_untouched_bundle_on_error():
    """An unexpected failure MUST NOT break the playbook pipeline."""
    conn = build_connector()
    conn.client.selector_type_for.side_effect = RuntimeError("boom")
    conn.helper.stix2_create_bundle.return_value = "BUNDLE"
    former = [{"type": "email-addr", "value": "a@b.com"}]
    data = {
        "enrichment_entity": {"entity_type": "Email-Addr", "value": "a@b.com"},
        "stix_objects": former,
    }

    msg = conn._process_callback(data)

    assert "Internal error" in msg
    conn.helper.connector_logger.error.assert_called()
    conn.helper.stix2_create_bundle.assert_called_once_with(former)


@sdk_required
def test_process_callback_survives_a_failing_bundle_forward():
    """Forwarding is best effort: the callback MUST still return a message."""
    conn = build_connector()
    conn.client.selector_type_for.side_effect = RuntimeError("boom")
    conn.helper.send_stix2_bundle.side_effect = RuntimeError("platform down")
    data = {
        "enrichment_entity": {"entity_type": "Email-Addr", "value": "a@b.com"},
        "stix_objects": [{"type": "email-addr", "value": "a@b.com"}],
    }

    assert "Internal error" in conn._process_callback(data)


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
@pytest.mark.parametrize(
    "max_tlp,markings,allowed",
    [
        # No marking at all: the observable is enrichable.
        ("TLP:AMBER", [], True),
        ("TLP:AMBER", None, True),
        # Non-TLP markings must be ignored.
        ("TLP:AMBER", [{"definition_type": "PAP", "definition": "PAP:RED"}], True),
        # At or below the maximum.
        ("TLP:AMBER", [tlp_marking("TLP:CLEAR")], True),
        ("TLP:AMBER", [tlp_marking("TLP:GREEN")], True),
        ("TLP:AMBER", [tlp_marking("TLP:AMBER")], True),
        # Above the maximum.
        ("TLP:AMBER", [tlp_marking("TLP:AMBER+STRICT")], False),
        ("TLP:AMBER", [tlp_marking("TLP:RED")], False),
        ("TLP:CLEAR", [tlp_marking("TLP:GREEN")], False),
        ("TLP:RED", [tlp_marking("TLP:RED")], True),
        # The most restrictive marking wins when several are present.
        ("TLP:AMBER", [tlp_marking("TLP:GREEN"), tlp_marking("TLP:RED")], False),
        ("TLP:AMBER", [tlp_marking("TLP:RED"), tlp_marking("TLP:GREEN")], False),
        # pycti compares case-insensitively.
        ("TLP:AMBER", [tlp_marking("tlp:red")], False),
    ],
)
def test_check_tlp_allowed(max_tlp, markings, allowed):
    conn = build_connector(max_tlp=max_tlp)
    observable = {"objectMarking": markings}

    if allowed:
        assert conn._check_tlp_allowed(observable) is None
    else:
        with pytest.raises(MaxTlpExceededError):
            conn._check_tlp_allowed(observable)


@sdk_required
def test_process_message_blocks_observable_above_max_tlp():
    """An observable above the max TLP MUST never reach the third-party API."""
    conn = build_connector(max_tlp="TLP:AMBER")
    conn.client.selector_type_for.return_value = "email"
    obs = {
        "entity_type": "Email-Addr",
        "value": "a@b.com",
        "objectMarking": [tlp_marking("TLP:RED")],
    }

    msg = conn._process_callback({"enrichment_entity": obs})

    assert "greater than OSINT_INDUSTRIES_MAX_TLP" in msg
    conn.client.query.assert_not_called()
    conn.helper.send_stix2_bundle.assert_not_called()


@sdk_required
def test_process_message_allows_observable_within_max_tlp():
    conn = build_connector(max_tlp="TLP:RED")
    conn.client.selector_type_for.return_value = "email"
    conn.client.query.return_value = [{"module": "x"}]
    conn.converter.process.return_value = [object()]
    conn.helper.stix2_create_bundle.return_value = "BUNDLE"
    obs = {
        "entity_type": "Email-Addr",
        "value": "a@b.com",
        "objectMarking": [tlp_marking("TLP:RED")],
    }

    msg = conn._process_message({"enrichment_entity": obs})

    assert "Bundle sent: 1" in msg
    conn.client.query.assert_called_once()


@sdk_required
def test_connector_is_playbook_compatible():
    """VC321 — the helper MUST be built with playbook_compatible=True."""
    with patch("osint_industries.connector.OpenCTIConnectorHelper") as helper_cls:
        OsintIndustriesConnector(config=build_settings())

    _, kwargs = helper_cls.call_args
    assert kwargs["playbook_compatible"] is True


@sdk_required
def test_run_starts_listener():
    conn = build_connector()
    conn.run()
    conn.helper.listen.assert_called_once()

# -*- coding: utf-8 -*-
"""Unit tests for the connector: settings, init, and the enrichment flow.

Skipped when connectors_sdk / pycti are not installed, mirroring the sibling
connectors' test convention.
"""

import importlib.util
import os
import sys
from typing import Any
from unittest.mock import MagicMock

import pytest

SRC = os.path.join(os.path.dirname(__file__), "..", "src")
sys.path.insert(0, SRC)

SDK_AVAILABLE = (
    importlib.util.find_spec("connectors_sdk") is not None
    and importlib.util.find_spec("pycti") is not None
)

sdk_required = pytest.mark.skipif(
    not SDK_AVAILABLE,
    reason="connectors_sdk / pycti not installed in this environment",
)

if SDK_AVAILABLE:
    from xposedornot.connector import (
        XposedOrNotConnector,
        is_valid_email,
        observable_tlp,
    )
    from xposedornot.settings import ConnectorSettings

    class StubConnectorSettings(ConnectorSettings):
        """ConnectorSettings with a fake but valid config dict for tests."""

        _api_key: Any = None

        @classmethod
        def _load_config_dict(cls, _, handler) -> dict:
            xon = {
                "api_base_url": "https://api.xposedornot.com",
                "max_tlp": "TLP:AMBER",
                "tlp_level": "amber",
            }
            if cls._api_key:
                xon["api_key"] = cls._api_key
            return handler(
                {
                    "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                    "connector": {
                        "id": "connector-id",
                        "name": "XposedOrNot",
                        "scope": "Email-Addr",
                        "log_level": "error",
                        "auto": False,
                    },
                    "xposedornot": xon,
                }
            )


BREACHED = {
    "breaches": [
        {
            "name": "Sysco",
            "date": "2026",
            "records": 2699339,
            "domain": "sysco.com",
            "industry": "Food",
            "password_risk": "plaintextpassword",
            "verified": "Yes",
            "data_classes": ["Email addresses", "Names"],
        }
    ],
    "risk_label": "Critical",
    "risk_score": 100,
}

OBSERVABLE_ID = "email-addr--11111111-1111-4111-8111-111111111111"


def _make_connector(api_key=None):
    StubConnectorSettings._api_key = api_key
    settings = StubConnectorSettings()
    helper = MagicMock()
    helper.stix2_create_bundle.return_value = "BUNDLE"
    return XposedOrNotConnector(config=settings, helper=helper), helper


def _enrichment_data(email="test@example.com", tlp="TLP:AMBER"):
    marking = [{"definition_type": "TLP", "definition": tlp}] if tlp else []
    entity = {"id": OBSERVABLE_ID, "labels": []}
    observable = {
        "entity_type": "Email-Addr",
        "observable_value": email,
        "objectMarking": marking,
    }
    return {
        "enrichment_entity": observable,
        "stix_entity": entity,
        "stix_objects": [entity],
    }


# ---------------------------------------------------------------------------
# pure helpers
# ---------------------------------------------------------------------------
def test_email_validation():
    if not SDK_AVAILABLE:
        pytest.skip("sdk not installed")
    assert is_valid_email("user@example.com")
    assert is_valid_email("user+tag@sub.example.co.uk")
    assert not is_valid_email("not-an-email")
    assert not is_valid_email("")
    assert not is_valid_email("a@b")
    assert not is_valid_email("a" * 250 + "@example.com")


def test_observable_tlp_extraction():
    if not SDK_AVAILABLE:
        pytest.skip("sdk not installed")
    observable = {
        "objectMarking": [
            {"definition_type": "statement", "definition": "custom"},
            {"definition_type": "TLP", "definition": "TLP:AMBER"},
        ]
    }
    assert observable_tlp(observable) == "TLP:AMBER"
    assert observable_tlp({"objectMarking": []}) is None
    assert observable_tlp({}) is None


# ---------------------------------------------------------------------------
# settings + init
# ---------------------------------------------------------------------------
@sdk_required
def test_settings_instantiate_and_helper_config():
    StubConnectorSettings._api_key = None
    settings = StubConnectorSettings()
    assert isinstance(settings, ConnectorSettings)
    assert isinstance(settings.to_helper_config(), dict)
    assert settings.xposedornot.max_tlp == "TLP:AMBER"
    assert settings.xposedornot.api_key is None


@sdk_required
def test_connector_init_keyless_and_keyed():
    connector, _ = _make_connector()
    assert connector.max_tlp == "TLP:AMBER"
    assert connector.client.api_key is None
    keyed, _ = _make_connector(api_key="SECRET")
    assert keyed.client.api_key == "SECRET"


# ---------------------------------------------------------------------------
# enrichment flow
# ---------------------------------------------------------------------------
@sdk_required
def test_process_message_breached_updates_observable_and_sends_bundle():
    connector, helper = _make_connector()
    connector.client.lookup = MagicMock(return_value=BREACHED)
    result = connector._process_message(_enrichment_data())
    assert "Found 1 breach" in result
    # the enriched observable was included in the sent bundle
    sent_objects = helper.stix2_create_bundle.call_args[0][0]
    enriched = next(o for o in sent_objects if o.get("id") == OBSERVABLE_ID)
    assert enriched["x_opencti_score"] == 100
    assert "data-breach" in enriched["labels"]
    assert "plaintext-password-exposure" in enriched["labels"]
    assert any(
        ref["source_name"] == "XposedOrNot" for ref in enriched["external_references"]
    )
    assert isinstance(enriched["external_references"][0], dict)
    helper.send_stix2_bundle.assert_called_once()


@sdk_required
def test_process_message_clean_email_modifies_nothing():
    connector, helper = _make_connector()
    connector.client.lookup = MagicMock(return_value={})
    result = connector._process_message(_enrichment_data())
    assert "No known breach exposure" in result
    helper.send_stix2_bundle.assert_not_called()


@sdk_required
def test_process_message_tlp_exceeded_skips_before_lookup():
    connector, _ = _make_connector()
    connector.client.lookup = MagicMock()
    result = connector._process_message(_enrichment_data(tlp="TLP:RED"))
    assert "higher than" in result
    connector.client.lookup.assert_not_called()


@sdk_required
def test_process_message_unsupported_type_and_invalid_email():
    connector, _ = _make_connector()
    data = _enrichment_data()
    data["enrichment_entity"]["entity_type"] = "IPv4-Addr"
    assert "Unsupported type" in connector._process_message(data)

    connector.client.lookup = MagicMock()
    bad = _enrichment_data(email="not-an-email")
    assert "not a valid email" in connector._process_message(bad)
    connector.client.lookup.assert_not_called()


@sdk_required
def test_process_message_api_failure_and_callback_guard():
    connector, helper = _make_connector()
    connector.client.lookup = MagicMock(return_value=None)
    assert "request failed" in connector._process_message(_enrichment_data())
    # the callback wrapper converts exceptions into a safe message
    connector._process_message = MagicMock(side_effect=RuntimeError("boom"))
    assert "Internal error" in connector._process_callback(_enrichment_data())

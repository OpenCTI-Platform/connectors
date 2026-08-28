"""Orchestration tests for the connector (helper + API client mocked)."""

from types import SimpleNamespace
from unittest.mock import MagicMock

from connector.connector import MacadressConnector
from pycti import STIX_EXT_OCTI_SCO
from pydantic import SecretStr

MAC_ID = "mac-addr--11111111-2222-4333-8444-555555555555"
TLP_RED = "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed"

APPLE = {
    "mac": "F0:18:98:11:22:33",
    "valid": True,
    "organization": "Apple, Inc.",
    "country": "US",
    "block_type": "MA-L",
    "matched_prefix": "F0:18:98",
    "locally_administered": False,
    "potentially_randomized": False,
    "vendor_lookup_reliable": True,
    "explanation": "Registered to Apple, Inc.",
    "device": {"category": "smartphone", "confidence": "medium"},
    "virtualization": {"detected": False},
    "special_use": {"detected": False},
    "vendor": {"lookup_url": "https://macadress.com/vendor/apple-inc"},
}

RANDOM = {
    "mac": "F2:11:22:33:44:55",
    "valid": True,
    "organization": None,
    "locally_administered": True,
    "potentially_randomized": True,
    "randomization_confidence": "likely",
    "vendor_lookup_reliable": False,
    "device": {"category": "unknown"},
    "virtualization": {"detected": False},
    "special_use": {"detected": False},
    "vendor": None,
}


def _connector(max_tlp="TLP:AMBER", create_vendor_identity=True):
    config = SimpleNamespace(
        macadress=SimpleNamespace(
            api_base_url="http://x",
            api_key=SecretStr("mk_k"),
            max_tlp=max_tlp,
            default_score=30,
            create_note=True,
            create_vendor_identity=create_vendor_identity,
        ),
        connector=SimpleNamespace(scope=["Mac-Addr"]),
    )
    helper = MagicMock()
    helper.stix2_create_bundle.return_value = "{}"
    helper.send_stix2_bundle.return_value = [1]
    conn = MacadressConnector(config, helper)
    conn.client = MagicMock()
    return conn, helper


def _message(mac, marking=None, entity_type="Mac-Addr", stix_type="mac-addr"):
    return {
        "enrichment_entity": {
            "entity_type": entity_type,
            "objectMarking": (
                [{"definition_type": "TLP", "definition": marking}] if marking else []
            ),
        },
        "stix_entity": {"id": MAC_ID, "type": stix_type, "value": mac},
        "stix_objects": [{"id": MAC_ID, "type": stix_type, "value": mac}],
    }


def _ext(stix_entity):
    return stix_entity.get("extensions", {}).get(STIX_EXT_OCTI_SCO, {})


def test_registered_mac_updates_observable_and_adds_vendor():
    conn, helper = _connector()
    conn.client.lookup.return_value = APPLE
    msg = _message("F0:18:98:11:22:33")

    result = conn.process_message(msg)
    ext = _ext(msg["stix_entity"])

    assert "Sending" in result
    assert "**Vendor:** Apple, Inc. (US)" in ext.get("x_opencti_description", "")
    assert ext.get("score") == 30
    assert "smartphone" in ext.get("labels", [])
    assert "universally-administered" in ext.get("labels", [])
    urls = [ref["url"] for ref in ext.get("external_references", [])]
    assert "https://macadress.com/lookup/F0:18:98:11:22:33" in urls

    objects = helper.stix2_create_bundle.call_args[0][0]
    names = [o.get("name") for o in objects if o.get("type") == "identity"]
    types = [o.get("type") for o in objects]
    assert "macadress.com" in names
    assert "Apple, Inc." in names
    assert "relationship" in types
    assert "note" in types


def test_unreliable_lookup_adds_no_vendor_identity():
    conn, helper = _connector()
    conn.client.lookup.return_value = RANDOM
    msg = _message("F2:11:22:33:44:55")

    conn.process_message(msg)

    objects = helper.stix2_create_bundle.call_args[0][0]
    names = [o.get("name") for o in objects if o.get("type") == "identity"]
    assert names == ["macadress.com"]
    assert "mac-randomized" in _ext(msg["stix_entity"]).get("labels", [])


def test_vendor_identity_can_be_disabled():
    conn, helper = _connector(create_vendor_identity=False)
    conn.client.lookup.return_value = APPLE
    msg = _message("F0:18:98:11:22:33")

    conn.process_message(msg)

    objects = helper.stix2_create_bundle.call_args[0][0]
    names = [o.get("name") for o in objects if o.get("type") == "identity"]
    assert names == ["macadress.com"]


def test_tlp_above_max_raises_and_writes_nothing():
    conn, _ = _connector(max_tlp="TLP:GREEN")
    msg = _message("F0:18:98:11:22:33", marking="TLP:RED")

    try:
        conn.process_message(msg)
        raised = False
    except ValueError:
        raised = True

    assert raised
    assert "x_opencti_description" not in _ext(msg["stix_entity"])


def test_out_of_scope_returns_original_bundle():
    conn, helper = _connector()
    msg = _message("example.com", entity_type="Domain-Name", stix_type="domain-name")

    result = conn.process_message(msg)

    assert "Sending" in result
    conn.client.lookup.assert_not_called()
    assert helper.stix2_create_bundle.call_args[0][0] == msg["stix_objects"]


def test_invalid_mac_from_api_returns_original_bundle():
    conn, helper = _connector()
    conn.client.lookup.return_value = {"valid": False}
    msg = _message("00:00:00:00:00:00")

    result = conn.process_message(msg)

    assert "Sending" in result
    assert "x_opencti_description" not in _ext(msg["stix_entity"])

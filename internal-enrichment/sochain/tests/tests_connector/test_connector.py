"""Orchestration tests for the connector (helper and API client mocked)."""

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from connector.connector import POISONING_LABEL, SochainConnector
from connectors_sdk.models.enums import TLPLevel
from pycti import STIX_EXT_OCTI_SCO
from pydantic import SecretStr
from sochain_client import SochainAPIError

WALLET_ID = "cryptocurrency-wallet--11111111-2222-4333-8444-555555555555"
ADDRESS = "bc1qxhmdufsvnuaaaer4ynz88fspdsxq2h9e9cetdj"

SUMMARY = {
    "txs_sent": 1796,
    "txs_received": 32014,
    "txs_total": 32014,
    "confirmed_balance": "0.12771030",
    "unconfirmed_balance": "0.00000000",
    "confirmed_received": "285785.38685032",
    "first_active": {"height": 687848, "time": 1623874601},
    "last_active": {"height": 972455, "time": 1792576976},
}

FINDING = {
    "dust_txid": "b" * 64,
    "amount": "0.00000546",
    "sender": "bc1qxhmdufsvnuaaaer4ynz88fspdsxq2h9e9ceaaaa",
    "imitates": "bc1qxhmdufsvnuaaaer4ynz88fspdsxq2h9e9cebbbb",
    "real_txid": "c" * 64,
    "real_height": 972000,
    "real_amount": "0.50000000",
    "receiver_paid": True,
    "shared_prefix": 4,
    "shared_suffix": 4,
    "sender_kind": "new",
    "sender_txs": 1,
    "height": 972400,
    "confirmed": True,
}


def _connector(max_tlp=TLPLevel.AMBER, check_poisoning=True, api_key=None):
    config = SimpleNamespace(
        sochain=SimpleNamespace(
            api_base_url="https://sochain.com/api/v3",
            api_key=SecretStr(api_key) if api_key else None,
            check_poisoning=check_poisoning,
        ),
        connector=SimpleNamespace(max_tlp=max_tlp),
    )
    helper = MagicMock()
    helper.connect_scope = "cryptocurrency-wallet"
    helper.stix2_create_bundle.return_value = "{}"
    helper.send_stix2_bundle.return_value = [1]
    conn = SochainConnector(config, helper)
    conn.client = MagicMock()
    return conn, helper


def _message(value=ADDRESS, marking=None, event_type="manual", entity_id=WALLET_ID):
    # pycti hands the connector `stix_entity` as the same dict that is already
    # inside `stix_objects`; mirror that so tests exercise the real bundle.
    observable = {"id": entity_id, "type": entity_id.split("--")[0], "value": value}
    message = {
        "entity_id": entity_id,
        "enrichment_entity": {
            "entity_type": "Cryptocurrency-Wallet",
            "objectMarking": (
                [{"definition_type": "TLP", "definition": marking}] if marking else []
            ),
        },
        "stix_entity": observable,
        "stix_objects": [observable],
    }
    if event_type:
        message["event_type"] = event_type
    return message


def _ext(stix_entity):
    return stix_entity.get("extensions", {}).get(STIX_EXT_OCTI_SCO, {})


def test_wallet_is_enriched_with_summary_and_reference():
    conn, helper = _connector()
    conn.client.address_summary.return_value = SUMMARY
    conn.client.address_poisoning.return_value = {
        "address": ADDRESS,
        "building": False,
        "findings": [],
    }
    msg = _message()

    result = conn.process_message(msg)
    ext = _ext(msg["stix_entity"])

    assert "Sending" in result
    conn.client.address_summary.assert_called_once_with("BTC", ADDRESS)
    conn.client.address_poisoning.assert_called_once_with("BTC", ADDRESS)
    assert "- Balance: 0.12771030 BTC" in ext["x_opencti_description"]
    urls = [ref["url"] for ref in ext["external_references"]]
    assert urls == [f"https://sochain.com/btc/address/{ADDRESS}"]
    assert POISONING_LABEL not in ext.get("labels", [])

    objects = helper.stix2_create_bundle.call_args[0][0]
    types = [o.get("type") for o in objects]
    assert "identity" in types
    assert "note" not in types
    bundle_observable = next(o for o in objects if o.get("id") == WALLET_ID)
    assert bundle_observable is msg["stix_entity"]
    assert helper.send_stix2_bundle.call_args.kwargs == {
        "cleanup_inconsistent_bundle": True
    }


def test_poisoning_findings_add_a_note_and_a_label():
    conn, helper = _connector()
    conn.client.address_summary.return_value = SUMMARY
    conn.client.address_poisoning.return_value = {
        "address": ADDRESS,
        "building": False,
        "findings": [FINDING],
    }
    msg = _message(marking="TLP:GREEN")
    msg["stix_entity"]["object_marking_refs"] = [
        "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da"
    ]

    conn.process_message(msg)

    assert POISONING_LABEL in _ext(msg["stix_entity"])["labels"]
    objects = helper.stix2_create_bundle.call_args[0][0]
    note = next(o for o in objects if o.get("type") == "note")
    assert note["object_refs"] == [WALLET_ID]
    assert note["object_marking_refs"] == [
        "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da"
    ]
    assert FINDING["sender"] in note["content"]
    assert note["abstract"].startswith("Address poisoning: 1 look-alike address")


def test_poisoning_note_id_is_stable_across_runs():
    ids = []
    for findings in ([FINDING], [FINDING, dict(FINDING, dust_txid="d" * 64)]):
        conn, helper = _connector()
        conn.client.address_summary.return_value = SUMMARY
        conn.client.address_poisoning.return_value = {"findings": findings}
        conn.process_message(_message())
        objects = helper.stix2_create_bundle.call_args[0][0]
        ids.append(next(o["id"] for o in objects if o.get("type") == "note"))

    assert ids[0] == ids[1]


def test_poisoning_check_can_be_disabled():
    conn, helper = _connector(check_poisoning=False)
    conn.client.address_summary.return_value = SUMMARY

    conn.process_message(_message())

    conn.client.address_poisoning.assert_not_called()


def test_poisoning_failure_still_sends_the_summary():
    conn, helper = _connector()
    conn.client.address_summary.return_value = SUMMARY
    conn.client.address_poisoning.side_effect = SochainAPIError("busy", 503)
    msg = _message()

    result = conn.process_message(msg)

    assert "Sending" in result
    assert "x_opencti_description" in _ext(msg["stix_entity"])


def test_network_is_detected_from_the_address():
    conn, _ = _connector()
    conn.client.address_summary.return_value = SUMMARY
    conn.client.address_poisoning.return_value = {"findings": []}

    conn.process_message(_message("DH5yaieqoZN36fDVciNyRueRGvGLR3mr7L"))

    conn.client.address_summary.assert_called_once_with(
        "DOGE", "DH5yaieqoZN36fDVciNyRueRGvGLR3mr7L"
    )


def test_unsupported_address_is_skipped_without_a_lookup():
    conn, helper = _connector()

    result = conn.process_message(
        _message("0x52908400098527886E0F7030069857D2E4169EE7")
    )

    conn.client.address_summary.assert_not_called()
    helper.send_stix2_bundle.assert_not_called()
    assert "Not a Bitcoin" in result


def test_unsupported_address_in_playbook_returns_the_bundle_unchanged():
    conn, helper = _connector()
    msg = _message("0x52908400098527886E0F7030069857D2E4169EE7", event_type=None)

    conn.process_message(msg)

    objects = helper.stix2_create_bundle.call_args[0][0]
    assert objects == [msg["stix_entity"]]
    assert "extensions" not in msg["stix_entity"]


def test_tlp_above_max_raises_without_a_lookup():
    conn, helper = _connector(max_tlp=TLPLevel.GREEN)

    with pytest.raises(ValueError, match="MAX TLP"):
        conn.process_message(_message(marking="TLP:RED"))

    conn.client.address_summary.assert_not_called()
    helper.send_stix2_bundle.assert_not_called()


def test_tlp_above_max_in_playbook_returns_the_bundle_unchanged():
    conn, helper = _connector(max_tlp=TLPLevel.GREEN)
    msg = _message(marking="TLP:RED", event_type=None)

    conn.process_message(msg)

    conn.client.address_summary.assert_not_called()
    assert helper.stix2_create_bundle.call_args[0][0] == [msg["stix_entity"]]


def test_out_of_scope_entity_is_skipped():
    conn, helper = _connector()

    conn.process_message(_message(entity_id="ipv4-addr--" + WALLET_ID.split("--")[1]))

    conn.client.address_summary.assert_not_called()


def test_unknown_address_is_skipped():
    conn, helper = _connector()
    conn.client.address_summary.side_effect = SochainAPIError("Invalid address?", 404)

    result = conn.process_message(_message())

    helper.send_stix2_bundle.assert_not_called()
    assert "does not know" in result


def test_rate_limit_raises_outside_a_playbook():
    conn, _ = _connector()
    conn.client.address_summary.side_effect = SochainAPIError("rate limit", 429)

    with pytest.raises(SochainAPIError):
        conn.process_message(_message())


def test_rate_limit_in_playbook_returns_the_bundle_unchanged():
    conn, helper = _connector()
    conn.client.address_summary.side_effect = SochainAPIError("rate limit", 429)
    msg = _message(event_type=None)

    conn.process_message(msg)

    objects = helper.stix2_create_bundle.call_args[0][0]
    assert objects == [msg["stix_entity"]]


def test_api_key_is_passed_to_the_client():
    config = SimpleNamespace(
        sochain=SimpleNamespace(
            api_base_url="https://sochain.com/api/v3",
            api_key=SecretStr("k"),
            check_poisoning=True,
        ),
        connector=SimpleNamespace(max_tlp=TLPLevel.AMBER),
    )
    conn = SochainConnector(config, MagicMock())

    assert conn.client._auth_header == {"API-KEY": "k"}


def test_no_api_key_means_no_header():
    config = SimpleNamespace(
        sochain=SimpleNamespace(
            api_base_url="https://sochain.com/api/v3",
            api_key=None,
            check_poisoning=True,
        ),
        connector=SimpleNamespace(max_tlp=TLPLevel.AMBER),
    )
    conn = SochainConnector(config, MagicMock())

    assert conn.client._auth_header == {}


def test_empty_api_key_means_no_header():
    config = SimpleNamespace(
        sochain=SimpleNamespace(
            api_base_url="https://sochain.com/api/v3",
            api_key=SecretStr(""),
            check_poisoning=True,
        ),
        connector=SimpleNamespace(max_tlp=TLPLevel.AMBER),
    )
    conn = SochainConnector(config, MagicMock())

    assert conn.client._auth_header == {}

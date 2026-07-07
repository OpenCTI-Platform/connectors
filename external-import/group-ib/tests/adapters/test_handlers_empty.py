from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from adapters.adapter import DataToSTIXAdapter
from connector.settings import ConfigConnector


def _adapter(collection: str, *, is_ioc: bool = False) -> DataToSTIXAdapter:
    helper = SimpleNamespace(connector_logger=MagicMock())
    return DataToSTIXAdapter(
        mitre_mapper={},
        collection=collection,
        tlp_color="amber",
        helper=helper,
        is_ioc=is_ioc,
        threat_actor_name=None,
        config=ConfigConnector(),
    )


# (collection, handler-attribute, expected-empty-return)
HANDLERS = [
    ("compromised/account_group", "generate_compromised_account_group", []),
    ("compromised/bank_card_group", "generate_compromised_bank_card_group", []),
    ("compromised/access", "generate_compromised_access", []),
    ("compromised/spd", "generate_compromised_spd", []),
    ("osi/public_leak", "generate_osi_public_leak", []),
    ("osi/vulnerability", "generate_osi_vulnerability", []),
    ("osi/git_repository", "generate_osi_git_repository", []),
    ("hi/open_threats", "generate_hi_open_threats", []),
    ("ioc/primary", "generate_ioc_primary", []),
    ("malware/cnc", "generate_malware_cnc", []),
    ("malware/config", "generate_malware_config", []),
    ("darkweb/forums", "generate_darkweb_forums", []),
    ("attacks/deface", "generate_attacks_deface", []),
    ("attacks/ddos", "generate_attacks_ddos", []),
    ("attacks/phishing_group", "generate_attacks_phishing_group", []),
    ("attacks/phishing_kit", "generate_attacks_phishing_kit", []),
]


@pytest.mark.parametrize(("collection", "method_name", "expected"), HANDLERS)
def test_empty_event_returns_empty_list(collection, method_name, expected):
    a = _adapter(collection)
    method = getattr(a, method_name)
    out = method(event={}, json_date_obj={}, json_eval_obj={})
    assert out == expected


@pytest.mark.parametrize(("collection", "method_name", "_"), HANDLERS)
def test_empty_event_logs_warning(collection, method_name, _):
    a = _adapter(collection)
    method = getattr(a, method_name)
    method(event={}, json_date_obj={}, json_eval_obj={})
    # Every handler emits a `"No <key> object provided ..."` warning when
    # the payload is missing.
    warn_calls = a.helper.connector_logger.warning.call_args_list
    assert any(
        "No " in str(c) for c in warn_calls
    ), f"{collection} did not log a warning for empty event"


# --- Chat-collection handlers (different shape: call _build_chat_*) ---------


class TestChatHandlersEmpty:
    def test_discord_empty(self):
        a = _adapter("compromised/discord")
        out = a.generate_compromised_discord(
            event={}, json_date_obj={}, json_eval_obj={}
        )
        # The chat-bundle builder is tolerant of empty inputs — it may
        # still emit author Identity + marking even with no message body.
        assert isinstance(out, list)

    def test_messenger_empty(self):
        a = _adapter("compromised/messenger")
        out = a.generate_compromised_messenger(
            event={}, json_date_obj={}, json_eval_obj={}
        )
        assert isinstance(out, list)


# --- Default-flow generate_stix_* with empty obj ----------------------------


class TestDefaultFlowEmptyObj:
    """``generate_stix_*`` methods in ``SdoMixin`` and ``SpecialMixin`` are
    called from the default flow with potentially-empty objects. Each one
    should accept ``obj={}`` without crashing."""

    def test_generate_stix_yara_empty(self):
        a = _adapter("malware/yara", is_ioc=True)
        out = a.generate_stix_yara(
            obj={}, related_objects=[], json_date_obj={}, yara_is_ioc=True
        )
        # Returns None when there's no yara content.
        assert out is None or out == []

    def test_generate_stix_suricata_empty(self):
        a = _adapter("malware/signature", is_ioc=True)
        out = a.generate_stix_suricata(
            obj={}, related_objects=[], json_date_obj={}, suricata_is_ioc=True
        )
        assert out is None or out == []

    def test_generate_stix_ungrouped_empty(self):
        a = _adapter("apt/threat", is_ioc=True)
        out = a.generate_stix_ungrouped(
            obj={}, related_objects=[], json_date_obj={}, email_is_ioc=False
        )
        # Empty obj → handler returns None (early exit), not an empty list.
        assert out is None

    def test_generate_stix_targeted_entities_empty_when_flag_default(self):
        a = _adapter("apt/threat")
        # Flag defaults to true → empty obj → empty list.
        out = a.generate_stix_targeted_entities(obj={}, related_objects=[])
        assert isinstance(out, list)

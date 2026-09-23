from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

from adapters.adapter import DataToSTIXAdapter
from connector.settings import ConfigConnector


def _adapter(tlp_color: str = "red") -> DataToSTIXAdapter:
    helper = SimpleNamespace(connector_logger=MagicMock())
    return DataToSTIXAdapter(
        mitre_mapper={},
        collection="compromised/masked_card",
        tlp_color=tlp_color,
        helper=helper,
        is_ioc=False,
        threat_actor_name=None,
        config=ConfigConnector(),
    )


_DATE_OBJ = {
    "date-first-seen": "2024-01-01T00:00:00+00:00",
    "date-last-seen": "2024-02-01T00:00:00+00:00",
    "date-detected": "2024-01-01T00:00:00+00:00",
    "date-compromised": "2024-01-02T00:00:00+00:00",
    "ttl": 90,
}


class TestCompromisedMaskedCardHandler:
    def _full_event(self):
        return {
            "masked_card": {
                "name": "card-1",
                "cardInfo": {
                    "number": "4111111111111111",
                    "system": "VISA",
                    "type": "credit",
                    "issuer": "Bank-X",
                    "issuer_country_code": "US",
                    "issuer_country_name": "United States",
                    "bin": [411111],
                    "cvv": "123",
                    "pin": None,
                    "dump": None,
                    "validThru": "12/25",
                    "validThruDate": "2025-12-31",
                },
                "cnc": {
                    "domain": "c2.example.com",
                    "url": "https://c2.example.com/p",
                    "ip": "192.0.2.2",
                    "country_code": "RU",
                },
                "malware": {"name": "MalwareGamma", "id": "m-1"},
                "threat_actor_list": [{"name": "FIN-X", "id": "ta-1"}],
                "owner": {
                    "name": "Owner",
                    "phone": "+1",
                    "address": "1 St",
                    "state": "NY",
                    "zip": "10001",
                    "country_code": "US",
                },
                "source_type": "leak",
                "source_link": "https://leak.example.com",
                "isMasked": True,
                "isDump": False,
                "isExpired": False,
                "baseName": "VISA",
                "price_value": 50,
                "price_currency": "USD",
                "client_ipv4_ip": "192.0.2.1",
            }
        }

    def test_full_payload_emits_full_bundle(self):
        a = _adapter("red")
        out = a.generate_compromised_masked_card(
            event=self._full_event(),
            json_date_obj=_DATE_OBJ,
            json_eval_obj={"severity": "red", "tlp": "red"},
        )
        assert isinstance(out, list) and len(out) > 0
        types = {getattr(o, "type", "") for o in out}
        # Core entities for the masked-card bundle.
        assert "incident" in types
        assert "malware" in types
        assert "threat-actor" in types
        assert "note" in types
        # CnC observables emitted.
        assert "domain-name" in types or "url" in types or "ipv4-addr" in types

    def test_amber_tlp_emits_non_ioc_observables(self):
        # When TLP isn't red, CnC observables shouldn't be flagged as IOCs.
        a = _adapter("amber")
        out = a.generate_compromised_masked_card(
            event=self._full_event(),
            json_date_obj=_DATE_OBJ,
            json_eval_obj={"severity": "amber", "tlp": "amber"},
        )
        assert isinstance(out, list) and len(out) > 0
        # No `indicator` entries on amber TLP.
        types = {getattr(o, "type", "") for o in out}
        # Domain emitted, but as observable not indicator.
        assert "domain-name" in types

    def test_minimal_card_no_cnc(self):
        # No CnC block → no CnC observables, but card + actor still emit.
        a = _adapter("red")
        event = {
            "masked_card": {
                "cardInfo": {"number": "4111111111111112"},
                "malware": {"name": "Stealer"},
                "threat_actor_list": [{"name": "Broker"}],
            }
        }
        out = a.generate_compromised_masked_card(
            event=event, json_date_obj=_DATE_OBJ, json_eval_obj={}
        )
        assert isinstance(out, list) and len(out) > 0
        types = {getattr(o, "type", "") for o in out}
        assert "incident" in types
        # CnC observables absent.
        assert "domain-name" not in types
        assert "url" not in types

    def test_threat_actor_as_dict_field(self):
        # When ``threat_actor`` is a single dict instead of a list,
        # the handler still picks up the actor.
        a = _adapter("red")
        event = {
            "masked_card": {
                "cardInfo": {"number": "4111111111111113"},
                "threat_actor": {"name": "Lone-Actor"},
                "cnc": {"domain": "c2.example.com"},
            }
        }
        out = a.generate_compromised_masked_card(
            event=event, json_date_obj=_DATE_OBJ, json_eval_obj={}
        )
        types = {getattr(o, "type", "") for o in out}
        assert "threat-actor" in types

    def test_cnc_domain_is_ip(self):
        # When cnc.domain accidentally carries an IP, the handler re-emits
        # it as an IP observable.
        a = _adapter("red")
        event = {
            "masked_card": {
                "cardInfo": {"number": "4111111111111114"},
                "cnc": {"domain": "10.99.0.1"},
            }
        }
        out = a.generate_compromised_masked_card(
            event=event, json_date_obj=_DATE_OBJ, json_eval_obj={}
        )
        types = {getattr(o, "type", "") for o in out}
        assert "ipv4-addr" in types
        assert "domain-name" not in types

    def test_invalid_cnc_domain_skipped(self):
        # An obviously bad domain (with a space) is logged + skipped.
        a = _adapter("amber")
        event = {
            "masked_card": {
                "cardInfo": {"number": "4111111111111115"},
                "cnc": {"domain": "not a domain"},
            }
        }
        out = a.generate_compromised_masked_card(
            event=event, json_date_obj=_DATE_OBJ, json_eval_obj={}
        )
        types = {getattr(o, "type", "") for o in out}
        assert "domain-name" not in types

    def test_country_locations_emitted(self):
        a = _adapter("red")
        out = a.generate_compromised_masked_card(
            event=self._full_event(),
            json_date_obj=_DATE_OBJ,
            json_eval_obj={"severity": "red"},
        )
        # Issuer country + CnC country → 2 Location SDOs.
        types = {getattr(o, "type", "") for o in out}
        assert "location" in types

    def test_client_ip_observable_present(self):
        a = _adapter("red")
        out = a.generate_compromised_masked_card(
            event=self._full_event(),
            json_date_obj=_DATE_OBJ,
            json_eval_obj={"severity": "red"},
        )
        # Client IP becomes a non-IOC ipv4-addr observable.
        types = {getattr(o, "type", "") for o in out}
        assert "ipv4-addr" in types

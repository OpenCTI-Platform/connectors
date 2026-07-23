from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

from connector.connector import ExternalImportConnector


def _bare_connector() -> ExternalImportConnector:
    inst = ExternalImportConnector.__new__(ExternalImportConnector)
    inst.helper = SimpleNamespace(
        connector_logger=MagicMock(),
        connect_name="Group-IB Connector",
    )
    inst.cfg = SimpleNamespace(get_extra_settings_by_name=MagicMock(return_value=None))
    inst.IGNORE_NON_MALWARE_DDOS = False
    inst.IGNORE_NON_INDICATOR_THREAT_REPORTS = False
    inst.IGNORE_NON_INDICATOR_THREATS = False
    inst.INTRUSION_SET_INSTEAD_OF_THREAT_ACTOR = False
    return inst


def _portion(parsed_value):
    """Build a mock portion that records calls and returns ``parsed_value``."""
    p = MagicMock()
    p.parse_portion = MagicMock(return_value=parsed_value)
    return p


# --- extra_pre_processing branches -------------------------------------------


class TestExtraPreProcessing:
    def test_default_branch(self):
        """No special flag → parse_portion(use_alternative_parser=True)."""
        c = _bare_connector()
        p = _portion(["evt-1", "evt-2"])
        out = c.extra_pre_processing("compromised/access", p)
        assert out == ["evt-1", "evt-2"]
        # parse_portion called with use_alternative_parser=True only.
        kwargs = p.parse_portion.call_args.kwargs
        assert kwargs.get("use_alternative_parser") is True

    def test_ddos_with_malware_filter(self):
        c = _bare_connector()
        c.IGNORE_NON_MALWARE_DDOS = True
        p = _portion(["filtered"])
        out = c.extra_pre_processing("attacks/ddos", p)
        assert out == ["filtered"]
        kwargs = p.parse_portion.call_args.kwargs
        assert kwargs["filter_map"] == [("malware", [])]
        assert kwargs["check_existence"] is True
        assert kwargs["use_alternative_parser"] is True

    def test_ddos_flag_off_uses_default_branch(self):
        c = _bare_connector()
        # Flag off → falls through to the default branch.
        p = _portion(["all-ddos"])
        c.extra_pre_processing("attacks/ddos", p)
        kwargs = p.parse_portion.call_args.kwargs
        assert "filter_map" not in kwargs

    def test_threat_reports_filter_to_with_indicators(self):
        c = _bare_connector()
        c.IGNORE_NON_INDICATOR_THREAT_REPORTS = True
        p = _portion(
            [
                {"id": "1", "indicators": [{"value": "192.0.2.1"}]},
                {"id": "2", "indicators": []},
                {"id": "3"},  # no key at all
                "not-a-dict",
            ]
        )
        out = c.extra_pre_processing("apt/threat", p)
        # Only the event with non-empty ``indicators`` list survives.
        assert len(out) == 1
        assert out[0]["id"] == "1"

    def test_threat_reports_filter_non_list_parsed_passthrough(self):
        # If parse_portion returns non-list, the function returns it as-is.
        c = _bare_connector()
        c.IGNORE_NON_INDICATOR_THREAT_REPORTS = True
        p = _portion({"unexpected": "scalar-instead-of-list"})
        out = c.extra_pre_processing("hi/threat", p)
        assert out == {"unexpected": "scalar-instead-of-list"}

    def test_threat_reports_indicator_strict_filter(self):
        # Third branch: IGNORE_NON_INDICATOR_THREATS → parse_portion with
        # filter_map on indicators key.
        c = _bare_connector()
        c.IGNORE_NON_INDICATOR_THREATS = True
        p = _portion([])
        c.extra_pre_processing("hi/threat", p)
        kwargs = p.parse_portion.call_args.kwargs
        assert kwargs["filter_map"] == [("indicators", [])]
        assert kwargs["check_existence"] is True

    def test_ddos_flag_priority_over_indicator_flag(self):
        # ddos branch is checked FIRST — turning on indicator flags must
        # not affect attacks/ddos events.
        c = _bare_connector()
        c.IGNORE_NON_MALWARE_DDOS = True
        c.IGNORE_NON_INDICATOR_THREATS = True
        p = _portion(["x"])
        c.extra_pre_processing("attacks/ddos", p)
        kwargs = p.parse_portion.call_args.kwargs
        # DDoS-malware filter wins → filter_map carries ("malware", []).
        assert kwargs["filter_map"] == [("malware", [])]

    def test_non_threat_collection_with_threat_flags(self):
        # Flag is on but collection is unrelated → default branch.
        c = _bare_connector()
        c.IGNORE_NON_INDICATOR_THREAT_REPORTS = True
        c.IGNORE_NON_INDICATOR_THREATS = True
        p = _portion(["x"])
        c.extra_pre_processing("malware/cnc", p)
        kwargs = p.parse_portion.call_args.kwargs
        # No filter_map — fell through to default.
        assert "filter_map" not in kwargs

    def test_threat_reports_drops_non_dict_items(self):
        c = _bare_connector()
        c.IGNORE_NON_INDICATOR_THREAT_REPORTS = True
        p = _portion(
            [
                42,
                None,
                "scalar",
                {"id": "1", "indicators": [{"v": "x"}]},
            ]
        )
        out = c.extra_pre_processing("apt/threat", p)
        # Non-dicts dropped, dict with non-empty indicators kept.
        assert len(out) == 1
        assert out[0]["id"] == "1"


# --- support: _is_transient_network_error edge cases ------------------------


class TestTransientChainBudgetEdgeCases:
    def test_none_input(self):
        # Defensive: passing None doesn't blow up.
        assert ExternalImportConnector._is_transient_network_error(None) is False

    def test_deeply_chained(self):
        class A(Exception):
            pass

        class B(Exception):
            pass

        class C(Exception):
            pass

        class Timeout(Exception):
            pass

        Timeout.__name__ = "Timeout"

        c, b, a = C("inner-c"), B("middle-b"), A("outer-a")
        t = Timeout("real-cause")
        c.__cause__ = t
        b.__cause__ = c
        a.__cause__ = b
        # Walker descends three links to find the Timeout.
        assert ExternalImportConnector._is_transient_network_error(a) is True

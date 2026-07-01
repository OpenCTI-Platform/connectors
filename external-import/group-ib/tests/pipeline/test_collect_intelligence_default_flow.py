from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

from pipeline.collect_intelligence import (
    _extend_from_lists,
    _run_default_flow,
    collect_intelligence,
)

# --- Helpers ----------------------------------------------------------------


def _helper():
    return SimpleNamespace(
        connector_logger=MagicMock(),
        connect_name="Group-IB Connector",
    )


def _wrapper(*ids):
    return SimpleNamespace(stix_objects=[SimpleNamespace(id=i) for i in ids])


def _config(statement_marking=False):
    return SimpleNamespace(
        get_extra_settings_by_name=MagicMock(return_value=statement_marking),
        get_extra_settings_bool=MagicMock(return_value=False),
    )


def _empty_adapter():
    """Adapter whose generate_stix_* methods return empty / None outputs."""
    adapter = MagicMock()
    adapter.generate_stix_malware.return_value = []
    adapter.generate_stix_attack_pattern.return_value = []
    adapter.generate_stix_vulnerability.return_value = []
    adapter.generate_stix_threat_actor.return_value = (None, None)
    adapter.generate_stix_intrusion_set.return_value = (None, None)
    adapter.generate_stix_targeted_entities.return_value = []
    adapter.generate_stix_network.return_value = ([], [], [], None)
    adapter.generate_stix_file.return_value = []
    adapter.generate_stix_yara.return_value = None
    adapter.generate_stix_suricata.return_value = None
    adapter.generate_stix_ungrouped.return_value = []
    adapter.generate_stix_report.return_value = None
    adapter.author = SimpleNamespace(id="identity--auth")
    adapter.tlp_fallback = SimpleNamespace(id="marking-definition--tlp")
    adapter.statement_marking = SimpleNamespace(id="marking-definition--stmt")
    return adapter


def _default_flow_kwargs(adapter, *, collection="apt/threat", config=None):
    """Common kwargs bundle for direct calls to _run_default_flow."""
    return dict(
        helper=_helper(),
        adapter=adapter,
        collection=collection,
        config=config or _config(),
        flag_intrusion_set_instead_of_threat_actor=False,
        json_threat_report_obj={},
        json_file_obj={},
        json_network_obj={},
        json_yara_obj={},
        json_suricata_obj={},
        json_cvss_obj={},
        json_malware_report_obj={},
        json_threat_actor_obj={},
        json_vulnerability_obj={},
        json_ungrouped_obj={},
        json_evaluation_obj={"tlp": "amber"},
        json_mitre_matrix_obj={},
        json_date_obj={},
    )


# --- _run_default_flow ------------------------------------------------------


class TestRunDefaultFlowEmpty:
    def test_empty_adapter_returns_empty_bundle(self):
        adapter = _empty_adapter()
        out = _run_default_flow(**_default_flow_kwargs(adapter))
        assert out == []
        # Confirm every generate_stix_* method was visited (orchestration).
        adapter.generate_stix_malware.assert_called_once()
        adapter.generate_stix_attack_pattern.assert_called_once()
        adapter.generate_stix_vulnerability.assert_called_once()
        adapter.generate_stix_threat_actor.assert_called_once()
        adapter.generate_stix_targeted_entities.assert_called_once()
        adapter.generate_stix_network.assert_called_once()
        adapter.generate_stix_file.assert_called_once()
        adapter.generate_stix_yara.assert_called_once()
        adapter.generate_stix_suricata.assert_called_once()
        adapter.generate_stix_ungrouped.assert_called_once()
        adapter.generate_stix_report.assert_called_once()


class TestRunDefaultFlowReport:
    def test_report_with_author_and_tlp(self):
        adapter = _empty_adapter()
        report = SimpleNamespace(
            stix_objects=[SimpleNamespace(id="report--1")],
            author=SimpleNamespace(id="identity--auth"),
            tlp=SimpleNamespace(id="marking-definition--tlp"),
            statement_marking=SimpleNamespace(id="marking-definition--stmt"),
        )
        adapter.generate_stix_report.return_value = report
        out = _run_default_flow(**_default_flow_kwargs(adapter))
        ids = {getattr(o, "id", None) for o in out}
        assert "report--1" in ids
        assert "identity--auth" in ids
        assert "marking-definition--tlp" in ids

    def test_report_with_statement_marking_flag_on(self):
        adapter = _empty_adapter()
        report = SimpleNamespace(
            stix_objects=[SimpleNamespace(id="report--1")],
            author=SimpleNamespace(id="identity--auth"),
            tlp=SimpleNamespace(id="marking-definition--tlp"),
            statement_marking=SimpleNamespace(id="marking-definition--stmt"),
        )
        adapter.generate_stix_report.return_value = report
        out = _run_default_flow(
            **_default_flow_kwargs(adapter, config=_config(statement_marking=True))
        )
        ids = {getattr(o, "id", None) for o in out}
        assert "marking-definition--stmt" in ids


class TestRunDefaultFlowNoReport:
    def test_threat_actor_only_uses_actor_tlp(self):
        adapter = _empty_adapter()
        ta_wrapper = SimpleNamespace(
            stix_objects=[SimpleNamespace(id="threat-actor--1")],
            tlp=SimpleNamespace(id="marking-definition--amber-strict"),
        )
        adapter.generate_stix_threat_actor.return_value = (ta_wrapper, [])
        out = _run_default_flow(**_default_flow_kwargs(adapter))
        ids = {getattr(o, "id", None) for o in out}
        assert "threat-actor--1" in ids
        assert "marking-definition--amber-strict" in ids
        # Author identity also appended after the threat-actor objects.
        assert "identity--auth" in ids

    def test_intrusion_set_branch(self):
        adapter = _empty_adapter()
        is_wrapper = SimpleNamespace(
            stix_objects=[SimpleNamespace(id="intrusion-set--1")],
            tlp=SimpleNamespace(id="marking-definition--is-tlp"),
        )
        adapter.generate_stix_intrusion_set.return_value = (is_wrapper, [])
        kwargs = _default_flow_kwargs(adapter)
        kwargs["flag_intrusion_set_instead_of_threat_actor"] = True
        out = _run_default_flow(**kwargs)
        ids = {getattr(o, "id", None) for o in out}
        assert "intrusion-set--1" in ids
        # Threat-actor handler NOT called when the flag is on.
        adapter.generate_stix_threat_actor.assert_not_called()
        adapter.generate_stix_intrusion_set.assert_called_once()

    def test_falls_back_to_adapter_tlp_when_no_actor(self):
        adapter = _empty_adapter()
        # No report, no threat-actor, but a malware wrapper exists so bundle
        # is non-empty.
        adapter.generate_stix_malware.return_value = [_wrapper("malware--1")]
        out = _run_default_flow(**_default_flow_kwargs(adapter))
        ids = {getattr(o, "id", None) for o in out}
        assert "malware--1" in ids
        # Adapter's fallback TLP appended at the end of the bundle.
        assert "marking-definition--tlp" in ids


class TestRunDefaultFlowMixedLists:
    def test_malware_and_attack_pattern_flattened(self):
        adapter = _empty_adapter()
        adapter.generate_stix_malware.return_value = [
            _wrapper("malware--1"),
            _wrapper("malware--2"),
        ]
        adapter.generate_stix_attack_pattern.return_value = [
            _wrapper("attack-pattern--1")
        ]
        out = _run_default_flow(
            **_default_flow_kwargs(adapter, collection="malware/malware")
        )
        ids = {getattr(o, "id", None) for o in out}
        assert "malware--1" in ids
        assert "malware--2" in ids
        assert "attack-pattern--1" in ids

    def test_yara_and_suricata_appended(self):
        adapter = _empty_adapter()
        adapter.generate_stix_yara.return_value = SimpleNamespace(
            stix_objects=[SimpleNamespace(id="indicator--yara-1")]
        )
        adapter.generate_stix_suricata.return_value = SimpleNamespace(
            stix_objects=[SimpleNamespace(id="indicator--suricata-1")]
        )
        # Need at least one wrapper to make the bundle non-empty.
        adapter.generate_stix_malware.return_value = [_wrapper("malware--1")]
        out = _run_default_flow(
            **_default_flow_kwargs(adapter, collection="malware/yara")
        )
        ids = {getattr(o, "id", None) for o in out}
        assert "indicator--yara-1" in ids
        assert "indicator--suricata-1" in ids

    def test_network_lists_extended_into_bundle(self):
        adapter = _empty_adapter()
        adapter.generate_stix_network.return_value = (
            [_wrapper("domain-name--1")],
            [_wrapper("url--1")],
            [_wrapper("ipv4-addr--1")],
            [_wrapper("location--target")],
        )
        # Force a non-empty bundle.
        adapter.generate_stix_malware.return_value = [_wrapper("malware--1")]
        out = _run_default_flow(**_default_flow_kwargs(adapter))
        ids = {getattr(o, "id", None) for o in out}
        for wanted in (
            "domain-name--1",
            "url--1",
            "ipv4-addr--1",
            "location--target",
            "malware--1",
        ):
            assert wanted in ids


# --- _extend_from_lists ------------------------------------------------------


class TestExtendFromListsTolerance:
    def test_skips_none_iterables(self):
        target = []
        _extend_from_lists(target, None, [], None)
        assert target == []

    def test_concatenates_in_order(self):
        target = []
        _extend_from_lists(
            target,
            [_wrapper("a")],
            [_wrapper("b"), _wrapper("c")],
        )
        assert [o.id for o in target] == ["a", "b", "c"]


# --- collect_intelligence dispatch (direct call, no monkeypatch) ------------


class TestCollectIntelligenceDispatch:
    """Verifies the public ``collect_intelligence`` entrypoint actually
    dispatches between special and default flows. Uses ``unittest.mock.patch``
    inline so the monkeypatch fixture isn't required."""

    def test_special_slug_routes_to_special_handler(self):
        from unittest.mock import patch

        adapter_instance = MagicMock()
        adapter_instance.generate_compromised_account_group.return_value = [
            SimpleNamespace(id="x")
        ]
        # ``pipeline/__init__.py`` shadows the submodule with the function;
        # patch through ``sys.modules`` to land on the real submodule.
        import sys as _sys

        import pipeline.collect_intelligence  # noqa: ensure submodule loaded

        ci_mod = _sys.modules["pipeline.collect_intelligence"]
        with patch.object(
            ci_mod,
            "DataToSTIXAdapter",
            return_value=adapter_instance,
        ):
            out = collect_intelligence(
                helper=_helper(),
                collection="compromised/account_group",
                ttl=30,
                event={
                    "evaluation": {"tlp": "red"},
                    "account_group": {},
                },
                mitre_mapper={},
                config=_config(),
            )
        assert len(out) == 1
        adapter_instance.generate_compromised_account_group.assert_called_once()
        adapter_instance.generate_stix_malware.assert_not_called()

    def test_non_special_slug_routes_to_default_flow(self):
        from unittest.mock import patch

        adapter_instance = _empty_adapter()
        # ``pipeline/__init__.py`` shadows the submodule with the function;
        # patch through ``sys.modules`` to land on the real submodule.
        import sys as _sys

        import pipeline.collect_intelligence  # noqa: ensure submodule loaded

        ci_mod = _sys.modules["pipeline.collect_intelligence"]
        with patch.object(
            ci_mod,
            "DataToSTIXAdapter",
            return_value=adapter_instance,
        ):
            out = collect_intelligence(
                helper=_helper(),
                collection="apt/threat",
                ttl=1460,
                event={
                    "evaluation": {"tlp": "amber"},
                    "threat_report": {},
                    "threat_actor": {"name": "FIN-X"},
                },
                mitre_mapper={"T1059": "Command Execution"},
                config=_config(),
            )
        assert out == []
        adapter_instance.generate_stix_threat_actor.assert_called_once()
        adapter_instance.generate_compromised_account_group.assert_not_called()

    def test_ttl_propagated_into_date_obj(self):
        from unittest.mock import patch

        adapter_instance = MagicMock()
        adapter_instance.generate_compromised_account_group.return_value = []
        # ``pipeline/__init__.py`` shadows the submodule with the function;
        # patch through ``sys.modules`` to land on the real submodule.
        import sys as _sys

        import pipeline.collect_intelligence  # noqa: ensure submodule loaded

        ci_mod = _sys.modules["pipeline.collect_intelligence"]
        with patch.object(
            ci_mod,
            "DataToSTIXAdapter",
            return_value=adapter_instance,
        ):
            collect_intelligence(
                helper=_helper(),
                collection="compromised/account_group",
                ttl=42,
                event={
                    "evaluation": {},
                    "date": {"date-first-seen": "x"},
                },
                mitre_mapper={},
                config=_config(),
            )
        call_kwargs = (
            adapter_instance.generate_compromised_account_group.call_args.kwargs
        )
        assert call_kwargs["json_date_obj"]["ttl"] == 42


class TestStatementMarkingBranchWithoutReport:
    def test_statement_marking_appended_when_no_report(self):
        # No Report but a non-empty bundle AND ``enable_statement_marking``
        # is on — statement marking is appended after the author + TLP
        # fallback.
        adapter = MagicMock()
        malware = SimpleNamespace(stix_objects=[SimpleNamespace(id="malware--1")])
        adapter.generate_stix_malware.return_value = [malware]
        adapter.generate_stix_attack_pattern.return_value = []
        adapter.generate_stix_vulnerability.return_value = []
        adapter.generate_stix_threat_actor.return_value = (None, None)
        adapter.generate_stix_intrusion_set.return_value = (None, None)
        adapter.generate_stix_targeted_entities.return_value = []
        adapter.generate_stix_network.return_value = ([], [], [], None)
        adapter.generate_stix_file.return_value = []
        adapter.generate_stix_yara.return_value = None
        adapter.generate_stix_suricata.return_value = None
        adapter.generate_stix_ungrouped.return_value = []
        adapter.generate_stix_report.return_value = None
        adapter.author = SimpleNamespace(id="identity--auth")
        adapter.tlp_fallback = SimpleNamespace(id="marking-definition--tlp")
        adapter.statement_marking = SimpleNamespace(id="marking-definition--stmt")
        config = SimpleNamespace(
            get_extra_settings_by_name=MagicMock(return_value=True),
            get_extra_settings_bool=MagicMock(return_value=False),
        )
        out = _run_default_flow(
            helper=SimpleNamespace(
                connector_logger=MagicMock(),
                connect_name="Group-IB Connector",
            ),
            adapter=adapter,
            collection="apt/threat",
            config=config,
            flag_intrusion_set_instead_of_threat_actor=False,
            json_threat_report_obj={},
            json_file_obj={},
            json_network_obj={},
            json_yara_obj={},
            json_suricata_obj={},
            json_cvss_obj={},
            json_malware_report_obj={},
            json_threat_actor_obj={},
            json_vulnerability_obj={},
            json_ungrouped_obj={},
            json_evaluation_obj={},
            json_mitre_matrix_obj={},
            json_date_obj={},
        )
        ids = {getattr(o, "id", None) for o in out}
        assert "marking-definition--tlp" in ids
        assert "marking-definition--stmt" in ids

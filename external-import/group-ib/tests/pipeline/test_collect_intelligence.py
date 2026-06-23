from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

from pipeline.collect_intelligence import (
    _extend_from_lists,
    _run_special,
    collect_intelligence,
)
from pipeline.collection_dispatch import SpecialCollection

# --- Helpers ------------------------------------------------------------------


def _helper() -> SimpleNamespace:
    """Minimal stand-in for ``OpenCTIConnectorHelper``."""
    return SimpleNamespace(
        connector_logger=MagicMock(),
        connect_name="Group-IB Connector",
    )


def _wrapper(*ids: str) -> SimpleNamespace:
    """A ``BaseEntity``-shaped object: ``.stix_objects`` is what the
    bundle-builder concatenates."""
    return SimpleNamespace(stix_objects=[SimpleNamespace(id=i) for i in ids])


# --- _extend_from_lists -------------------------------------------------------


class TestExtendFromLists:
    def test_empty(self):
        bundle: list = []
        _extend_from_lists(bundle)
        assert bundle == []

    def test_none_iterables_skipped(self):
        bundle: list = []
        _extend_from_lists(bundle, None, [], None)
        assert bundle == []

    def test_single_wrapper_list(self):
        bundle: list = []
        _extend_from_lists(bundle, [_wrapper("a", "b")])
        assert [o.id for o in bundle] == ["a", "b"]

    def test_multiple_iterables_concatenated_in_order(self):
        bundle: list = []
        _extend_from_lists(
            bundle,
            [_wrapper("a")],
            [_wrapper("b"), _wrapper("c", "d")],
            [_wrapper("e")],
        )
        assert [o.id for o in bundle] == ["a", "b", "c", "d", "e"]

    def test_preserves_existing_bundle_contents(self):
        bundle: list = [SimpleNamespace(id="pre")]
        _extend_from_lists(bundle, [_wrapper("a")])
        assert [o.id for o in bundle] == ["pre", "a"]


# --- _run_special -------------------------------------------------------------


class TestRunSpecial:
    def test_invokes_named_method_and_returns_list(self):
        helper = _helper()
        adapter = MagicMock()
        adapter.generate_compromised_account_group.return_value = [
            SimpleNamespace(id="sdo-1"),
            SimpleNamespace(id="sdo-2"),
        ]
        spec = SpecialCollection("generate_compromised_account_group", is_ioc=False)
        out = _run_special(
            helper=helper,
            adapter=adapter,
            spec=spec,
            collection="compromised/account_group",
            event={"account_group": {}},
            json_date_obj={},
            json_eval_obj={},
        )
        assert len(out) == 2
        adapter.generate_compromised_account_group.assert_called_once()
        # The method receives the named kwargs the docstring promises.
        call_kwargs = adapter.generate_compromised_account_group.call_args.kwargs
        assert "event" in call_kwargs
        assert "json_date_obj" in call_kwargs
        assert "json_eval_obj" in call_kwargs

    def test_none_result_yields_empty_list(self):
        helper = _helper()
        adapter = MagicMock()
        adapter.generate_x.return_value = None
        spec = SpecialCollection("generate_x", is_ioc=False)
        out = _run_special(
            helper=helper,
            adapter=adapter,
            spec=spec,
            collection="x/y",
            event={},
            json_date_obj={},
            json_eval_obj={},
        )
        assert out == []

    def test_iterable_result_materialised_to_list(self):
        # Spec lets the adapter return any iterable — confirm we always
        # materialise it (callers expect ``list[Any]``).
        helper = _helper()
        adapter = MagicMock()
        adapter.generate_x.return_value = iter(
            [SimpleNamespace(id="a"), SimpleNamespace(id="b")]
        )
        spec = SpecialCollection("generate_x", is_ioc=False)
        out = _run_special(
            helper=helper,
            adapter=adapter,
            spec=spec,
            collection="x/y",
            event={},
            json_date_obj={},
            json_eval_obj={},
        )
        assert isinstance(out, list)
        assert len(out) == 2

    def test_sets_adapter_is_ioc_from_spec(self):
        helper = _helper()
        adapter = MagicMock()
        adapter.generate_ioc_primary.return_value = []
        spec = SpecialCollection(
            "generate_ioc_primary", is_ioc=True, tlp_strict="amber"
        )
        _run_special(
            helper=helper,
            adapter=adapter,
            spec=spec,
            collection="ioc/primary",
            event={},
            json_date_obj={},
            json_eval_obj={"tlp": "green"},
        )
        # Adapter should be reconfigured before calling the handler.
        assert adapter.is_ioc is True
        # Strict TLP overrides the event TLP.
        assert adapter.tlp_color == "amber"

    def test_tlp_fallback_used_when_event_lacks_tlp(self):
        helper = _helper()
        adapter = MagicMock()
        adapter.generate_x.return_value = []
        spec = SpecialCollection("generate_x", is_ioc=False, tlp_fallback="amber")
        _run_special(
            helper=helper,
            adapter=adapter,
            spec=spec,
            collection="x/y",
            event={},
            json_date_obj={},
            json_eval_obj={},
        )
        assert adapter.tlp_color == "amber"

    def test_event_tlp_preferred_over_fallback(self):
        helper = _helper()
        adapter = MagicMock()
        adapter.generate_x.return_value = []
        spec = SpecialCollection("generate_x", is_ioc=False, tlp_fallback="amber")
        _run_special(
            helper=helper,
            adapter=adapter,
            spec=spec,
            collection="x/y",
            event={},
            json_date_obj={},
            json_eval_obj={"tlp": "green"},
        )
        assert adapter.tlp_color == "green"

    def test_logs_object_count(self):
        helper = _helper()
        adapter = MagicMock()
        adapter.generate_x.return_value = [
            SimpleNamespace(id="a"),
            SimpleNamespace(id="b"),
            SimpleNamespace(id="c"),
        ]
        spec = SpecialCollection("generate_x", is_ioc=False)
        _run_special(
            helper=helper,
            adapter=adapter,
            spec=spec,
            collection="x/y",
            event={},
            json_date_obj={},
            json_eval_obj={},
        )
        helper.connector_logger.info.assert_called_once()
        msg = str(helper.connector_logger.info.call_args)
        assert "3" in msg
        assert "x/y" in msg


# --- collect_intelligence dispatch -------------------------------------------


class TestCollectIntelligenceDispatch:
    def test_special_slug_routes_to_special_handler(self, monkeypatch):
        # Patch the adapter constructor in the collect_intelligence module
        # namespace so we don't drag in pycti / stix2 / mapping.json.
        adapter_instance = MagicMock()
        adapter_instance.generate_compromised_account_group.return_value = [
            SimpleNamespace(id="x")
        ]
        ctor = MagicMock(return_value=adapter_instance)
        # ``pipeline/__init__.py`` re-exports ``collect_intelligence`` as
        # the function — so ``pipeline.collect_intelligence`` resolves to
        # the function via attribute lookup, not the submodule. Patch
        # through ``sys.modules`` to reach the actual submodule object.
        import sys as _sys

        import pipeline.collect_intelligence  # noqa: ensure submodule loaded

        ci_mod = _sys.modules["pipeline.collect_intelligence"]
        monkeypatch.setattr(ci_mod, "DataToSTIXAdapter", ctor)

        helper = _helper()
        config = SimpleNamespace(
            get_extra_settings_by_name=MagicMock(return_value=False)
        )
        out = collect_intelligence(
            helper=helper,
            collection="compromised/account_group",
            ttl=30,
            event={"evaluation": {"tlp": "red"}, "account_group": {}},
            mitre_mapper={},
            config=config,
        )
        assert len(out) == 1
        # Adapter constructed with correct kwargs (collection + tlp from event).
        ctor.assert_called_once()
        ctor_kwargs = ctor.call_args.kwargs
        assert ctor_kwargs["collection"] == "compromised/account_group"
        assert ctor_kwargs["tlp_color"] == "red"
        # Default flow's generate_stix_malware MUST NOT be called.
        adapter_instance.generate_stix_malware.assert_not_called()

    def test_non_special_slug_routes_to_default_flow(self, monkeypatch):
        adapter_instance = MagicMock()
        # The default flow calls many ``generate_stix_*`` methods. Wire up
        # the minimum so the function returns without exploding.
        adapter_instance.generate_stix_malware.return_value = []
        adapter_instance.generate_stix_attack_pattern.return_value = []
        adapter_instance.generate_stix_vulnerability.return_value = []
        adapter_instance.generate_stix_threat_actor.return_value = (
            None,
            None,
        )
        adapter_instance.generate_stix_intrusion_set.return_value = (
            None,
            None,
        )
        adapter_instance.generate_stix_targeted_entities.return_value = []
        adapter_instance.generate_stix_network.return_value = (
            [],
            [],
            [],
            None,
        )
        adapter_instance.generate_stix_file.return_value = []
        adapter_instance.generate_stix_yara.return_value = None
        adapter_instance.generate_stix_suricata.return_value = None
        adapter_instance.generate_stix_ungrouped.return_value = []
        adapter_instance.generate_stix_report.return_value = None
        ctor = MagicMock(return_value=adapter_instance)
        # ``pipeline/__init__.py`` re-exports ``collect_intelligence`` as
        # the function — so ``pipeline.collect_intelligence`` resolves to
        # the function via attribute lookup, not the submodule. Patch
        # through ``sys.modules`` to reach the actual submodule object.
        import sys as _sys

        import pipeline.collect_intelligence  # noqa: ensure submodule loaded

        ci_mod = _sys.modules["pipeline.collect_intelligence"]
        monkeypatch.setattr(ci_mod, "DataToSTIXAdapter", ctor)

        helper = _helper()
        config = SimpleNamespace(
            get_extra_settings_by_name=MagicMock(return_value=False)
        )
        out = collect_intelligence(
            helper=helper,
            collection="apt/threat",
            ttl=1460,
            event={
                "evaluation": {"tlp": "amber"},
                "threat_report": {},
                "threat_actor": {"name": "FIN-X"},
            },
            mitre_mapper={"T1059": "Command Execution"},
            config=config,
        )
        # No SDOs produced from empty event — bundle stays empty list.
        assert out == []
        # Confirm we used the DEFAULT flow (threat-actor was called).
        adapter_instance.generate_stix_threat_actor.assert_called_once()
        # And NOT the special flow.
        adapter_instance.generate_compromised_account_group.assert_not_called()

    def test_intrusion_set_flag_swaps_actor_handler(self, monkeypatch):
        adapter_instance = MagicMock()
        adapter_instance.generate_stix_malware.return_value = []
        adapter_instance.generate_stix_attack_pattern.return_value = []
        adapter_instance.generate_stix_vulnerability.return_value = []
        adapter_instance.generate_stix_intrusion_set.return_value = (
            None,
            None,
        )
        adapter_instance.generate_stix_targeted_entities.return_value = []
        adapter_instance.generate_stix_network.return_value = (
            [],
            [],
            [],
            None,
        )
        adapter_instance.generate_stix_file.return_value = []
        adapter_instance.generate_stix_yara.return_value = None
        adapter_instance.generate_stix_suricata.return_value = None
        adapter_instance.generate_stix_ungrouped.return_value = []
        adapter_instance.generate_stix_report.return_value = None
        import sys as _sys

        import pipeline.collect_intelligence  # noqa

        ci_mod = _sys.modules["pipeline.collect_intelligence"]
        monkeypatch.setattr(
            ci_mod,
            "DataToSTIXAdapter",
            MagicMock(return_value=adapter_instance),
        )

        helper = _helper()
        config = SimpleNamespace(
            get_extra_settings_by_name=MagicMock(return_value=False)
        )
        collect_intelligence(
            helper=helper,
            collection="apt/threat",
            ttl=1460,
            event={"evaluation": {}},
            mitre_mapper={},
            config=config,
            flag_intrusion_set_instead_of_threat_actor=True,
        )
        # Flag flip: intrusion_set handler called, threat_actor NOT called.
        adapter_instance.generate_stix_intrusion_set.assert_called_once()
        adapter_instance.generate_stix_threat_actor.assert_not_called()

    def test_ttl_propagated_into_date_obj(self, monkeypatch):
        adapter_instance = MagicMock()
        adapter_instance.generate_compromised_account_group.return_value = []
        import sys as _sys

        import pipeline.collect_intelligence  # noqa

        ci_mod = _sys.modules["pipeline.collect_intelligence"]
        monkeypatch.setattr(
            ci_mod,
            "DataToSTIXAdapter",
            MagicMock(return_value=adapter_instance),
        )

        helper = _helper()
        config = SimpleNamespace(
            get_extra_settings_by_name=MagicMock(return_value=False)
        )
        collect_intelligence(
            helper=helper,
            collection="compromised/account_group",
            ttl=42,
            event={"evaluation": {}, "date": {"date-first-seen": "x"}},
            mitre_mapper={},
            config=config,
        )
        # The special handler must have received ``ttl`` stuffed into
        # the date dict — that's how downstream mappers learn the TTL.
        call_kwargs = (
            adapter_instance.generate_compromised_account_group.call_args.kwargs
        )
        assert call_kwargs["json_date_obj"]["ttl"] == 42

"""Unit tests for the TLP helpers exposed by ``ipqs.ipqs``.

The connector emits STIX objects from two API families (the legacy
fraud-and-risk-scoring branches and the new Artifact / failure-note
branch). The TLP plumbing is shared between them, so a regression in
``_TLP_MAP`` / ``_resolve_tlp`` / ``_make_tlp_marking`` would either
silently downgrade a marking on ingested data or let an operator
typo (``IPQS_DEFAULT_TLP=ANBER``) silently fall back to ``TLP:WHITE``.
"""

from typing import Any, Dict

import pytest
import stix2
from pycti import MarkingDefinition as PyctiMarkingDefinition

from ipqs.ipqs import (
    _TLP_MAP,
    IPQSConnector,
    _make_tlp_marking,
    _normalize_tlp,
    _resolve_tlp,
)


class TestNormalizeTLP:
    """``_normalize_tlp`` is forgiving about case / prefix."""

    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("clear", "TLP:CLEAR"),
            ("CLEAR", "TLP:CLEAR"),
            ("TLP:CLEAR", "TLP:CLEAR"),
            ("tlp:clear", "TLP:CLEAR"),
            ("  amber+strict  ", "TLP:AMBER+STRICT"),
            ("red", "TLP:RED"),
        ],
    )
    def test_normalises_known_aliases(self, raw, expected):
        assert _normalize_tlp(raw) == expected

    @pytest.mark.parametrize("blank", [None, "", "   "])
    def test_blank_falls_back_to_default(self, blank):
        assert _normalize_tlp(blank) == "TLP:CLEAR"
        assert _normalize_tlp(blank, fallback="TLP:AMBER") == "TLP:AMBER"


class TestTLPMap:
    """``_TLP_MAP`` exposes real ``MarkingDefinition`` objects."""

    @pytest.mark.parametrize("alias", list(_TLP_MAP))
    def test_every_alias_returns_a_marking_definition(self, alias):
        marking = _TLP_MAP[alias]
        assert isinstance(marking, stix2.MarkingDefinition)
        assert marking.id.startswith("marking-definition--")

    def test_clear_is_a_custom_marking_distinct_from_stix2_tlp_white(self):
        # ``TLP:CLEAR`` is OpenCTI's modern replacement for the legacy
        # ``TLP:WHITE`` and gets its own ``x_opencti_definition`` so
        # the UI shows the modern label. The marking-definition object
        # is therefore distinct from ``stix2.TLP_WHITE`` even though
        # ``pycti.MarkingDefinition.generate_id`` happens to derive the
        # same canonical id.
        assert _TLP_MAP["TLP:CLEAR"] is not stix2.TLP_WHITE
        assert _TLP_MAP["TLP:CLEAR"].x_opencti_definition == "TLP:CLEAR"

    def test_amber_strict_uses_pycti_canonical_id(self):
        canonical_id = PyctiMarkingDefinition.generate_id("TLP", "TLP:AMBER+STRICT")
        assert _TLP_MAP["TLP:AMBER+STRICT"].id == canonical_id
        assert _TLP_MAP["TLP:AMBER+STRICT"].x_opencti_definition == "TLP:AMBER+STRICT"

    @pytest.mark.parametrize(
        ("alias", "stix2_constant"),
        [
            ("TLP:WHITE", stix2.TLP_WHITE),
            ("TLP:GREEN", stix2.TLP_GREEN),
            ("TLP:AMBER", stix2.TLP_AMBER),
            ("TLP:RED", stix2.TLP_RED),
        ],
    )
    def test_built_in_aliases_match_stix2_constants(self, alias, stix2_constant):
        assert _TLP_MAP[alias] is stix2_constant


class TestResolveTLP:
    """``_resolve_tlp`` raises on unknown values instead of downgrading."""

    def test_known_value_returns_marking_definition(self):
        marking = _resolve_tlp("IPQS_DEFAULT_TLP", "TLP:AMBER")
        assert marking is stix2.TLP_AMBER

    def test_unknown_value_raises_listing_every_alias(self):
        with pytest.raises(ValueError) as exc:
            _resolve_tlp("IPQS_DEFAULT_TLP", "TLP:ANBER")
        message = str(exc.value)
        # Operator typo must surface with both the offending value and
        # every supported alias so they can self-correct from the log.
        assert "TLP:ANBER" in message
        for alias in _TLP_MAP:
            assert alias in message

    def test_unknown_value_does_not_silently_downgrade_to_white(self):
        with pytest.raises(ValueError):
            _resolve_tlp("IPQS_MAX_TLP", "WAT")


class TestMakeTLPMarking:
    """``_make_tlp_marking`` produces canonical OpenCTI markings."""

    def test_id_matches_pycti_canonical_id(self):
        marking = _make_tlp_marking("TLP:CLEAR")
        canonical_id = PyctiMarkingDefinition.generate_id("TLP", "TLP:CLEAR")
        assert marking.id == canonical_id

    def test_marking_carries_opencti_metadata(self):
        marking = _make_tlp_marking("TLP:CLEAR")
        assert marking.x_opencti_definition_type == "TLP"
        assert marking.x_opencti_definition == "TLP:CLEAR"


class TestObservableMarkingRefs:
    """``_observable_marking_refs`` extracts source markings safely."""

    def test_extracts_from_object_marking_with_standard_id(self):
        observable: Dict[str, Any] = {
            "objectMarking": [
                {"standard_id": stix2.TLP_AMBER.id, "definition": "TLP:AMBER"},
            ]
        }
        refs = IPQSConnector._observable_marking_refs(observable)
        assert refs == [stix2.TLP_AMBER.id]

    def test_extracts_from_object_marking_refs_list_of_strings(self):
        observable = {"object_marking_refs": [stix2.TLP_AMBER.id]}
        assert IPQSConnector._observable_marking_refs(observable) == [
            stix2.TLP_AMBER.id
        ]

    def test_deduplicates_preserving_order(self):
        observable = {
            "objectMarking": [
                {"standard_id": "marking-definition--a"},
                {"standard_id": "marking-definition--b"},
                {"standard_id": "marking-definition--a"},
            ]
        }
        refs = IPQSConnector._observable_marking_refs(observable)
        assert refs == ["marking-definition--a", "marking-definition--b"]

    @pytest.mark.parametrize(
        "observable",
        [
            {},
            {"objectMarking": []},
            {"objectMarking": None},
            {"objectMarking": "not-a-list"},
            {"objectMarking": [{"definition": "TLP:AMBER"}]},  # no standard_id
        ],
    )
    def test_missing_or_malformed_returns_empty_list(self, observable):
        assert IPQSConnector._observable_marking_refs(observable) == []

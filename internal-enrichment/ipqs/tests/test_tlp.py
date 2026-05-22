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
from ipqs.ipqs import (
    _MARKING_ID_TO_TLP,
    _TLP_MAP,
    IPQSConnector,
    _make_tlp_marking,
    _normalize_tlp,
    _resolve_tlp,
)
from pycti import MarkingDefinition as PyctiMarkingDefinition


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

    @pytest.mark.parametrize(
        "observable",
        [
            # ``standard_id`` is set but not a string — the previous shape
            # let it through into the refs list and later poisoned
            # ``stix2.Note(..., object_marking_refs=...)`` with an
            # unhashable / invalid value. Filter must drop it.
            pytest.param(
                {"objectMarking": [{"standard_id": None}]},
                id="standard_id_is_None",
            ),
            pytest.param(
                {"objectMarking": [{"standard_id": ""}]},
                id="standard_id_is_empty_string",
            ),
            pytest.param(
                {"objectMarking": [{"standard_id": 42}]},
                id="standard_id_is_int",
            ),
            pytest.param(
                {"objectMarking": [{"standard_id": ["marking-definition--a"]}]},
                id="standard_id_is_list",
            ),
            # Same shape on the flat ``object_marking_refs`` list — an
            # empty string is filtered out by the ``and marking`` guard.
            pytest.param(
                {"object_marking_refs": [""]},
                id="flat_ref_is_empty_string",
            ),
            # Non-string flat refs are skipped too.
            pytest.param(
                {"object_marking_refs": [None, 42]},
                id="flat_refs_are_None_and_int",
            ),
        ],
    )
    def test_filters_falsy_and_non_string_refs(self, observable):
        """Mirror ``IPQSBuilder._get_object_marking_refs`` filter contract.

        Pins the regression — a non-string ``standard_id`` (or a non-string
        flat ref) used to be appended verbatim and broke
        ``stix2.Note(..., object_marking_refs=...)`` at serialisation
        time. The filter now drops every shape that is not a non-empty
        ``str``.
        """
        assert IPQSConnector._observable_marking_refs(observable) == []


class TestMarkingIdToTLP:
    """Reverse lookup ``marking.id -> canonical TLP string``.

    The lookup powers the ``_check_max_tlp`` fallback path for the
    alternate ``object_marking_refs`` shape (a flat list of marking
    ids). Every distinct TLP id in ``_TLP_MAP`` must resolve back to
    a TLP string at the SAME level — otherwise the max-TLP gate
    would silently fall back to ``IPQS_DEFAULT_TLP`` for observables
    carrying their TLP in the flat-id shape, slipping observables
    above ``IPQS_MAX_TLP`` past the gate.
    """

    # ``pycti.MarkingDefinition.generate_id("TLP", "TLP:CLEAR")``
    # collides with the legacy ``stix2.TLP_WHITE`` id by design — both
    # represent the least-restrictive level. We accept either string
    # as a valid resolution for that shared id; both resolve to the
    # same ``check_max_tlp`` level so the gate behaviour is identical.
    _SHARED_LEVELS = {
        # least-restrictive: CLEAR and WHITE collapse onto the same id
        # in pycti's namespace UUID generation.
        ("TLP:CLEAR", "TLP:WHITE"),
    }

    @pytest.mark.parametrize("tlp_string", sorted(_TLP_MAP))
    def test_every_tlp_id_resolves_to_same_level(self, tlp_string):
        marking = _TLP_MAP[tlp_string]
        resolved = _MARKING_ID_TO_TLP[marking.id]
        # Either the same string, or another string from the
        # documented shared-level alias set.
        if resolved == tlp_string:
            return
        for alias_group in self._SHARED_LEVELS:
            if tlp_string in alias_group and resolved in alias_group:
                return
        pytest.fail(
            f"{tlp_string!r} resolved to unexpected {resolved!r} "
            f"(not in any shared-level alias group)"
        )

    def test_reverse_lookup_covers_every_marking_id(self):
        # Every marking-definition id in ``_TLP_MAP`` (deduplicated
        # for the CLEAR/WHITE collision) must be present in the
        # reverse lookup so the alternate ``object_marking_refs``
        # shape never falls through silently.
        for marking in _TLP_MAP.values():
            assert marking.id in _MARKING_ID_TO_TLP


class TestCheckMaxTLPAlternateShape:
    """``_check_max_tlp`` accepts both marking-shape variants.

    The connector resolves marking refs from EITHER the GraphQL
    ``objectMarking`` list of dicts (primary) OR the alternate
    ``object_marking_refs`` flat list of ids (fallback). The
    max-TLP gate must check both — otherwise an observable carrying
    a ``TLP:RED`` marking in the alternate shape would silently fall
    back to ``IPQS_DEFAULT_TLP`` (defaults to ``TLP:CLEAR``) and slip
    past a ``IPQS_MAX_TLP=TLP:AMBER`` gate it should fail.
    """

    @staticmethod
    def _make_connector(
        max_tlp: str = "TLP:AMBER", default_tlp: str = "TLP:CLEAR"
    ) -> IPQSConnector:
        # Build a bare connector instance with just the attributes
        # ``_check_max_tlp`` actually reads — sidesteps the full
        # ``__init__`` config / network surface.
        connector = IPQSConnector.__new__(IPQSConnector)
        connector.max_tlp = max_tlp
        connector.default_tlp_string = default_tlp
        return connector

    def test_object_marking_dicts_blocks_when_above_max(self):
        connector = self._make_connector(max_tlp="TLP:AMBER")
        observable = {
            "objectMarking": [
                {"definition_type": "TLP", "definition": "TLP:RED"},
            ]
        }
        assert connector._check_max_tlp(observable) is False

    def test_object_marking_refs_blocks_when_above_max(self):
        """Plain ``object_marking_refs`` (list of ids) must be honoured."""
        connector = self._make_connector(max_tlp="TLP:AMBER")
        observable = {"object_marking_refs": [stix2.TLP_RED.id]}
        assert connector._check_max_tlp(observable) is False

    def test_object_marking_refs_allows_when_at_or_below_max(self):
        connector = self._make_connector(max_tlp="TLP:AMBER")
        observable = {"object_marking_refs": [stix2.TLP_GREEN.id]}
        assert connector._check_max_tlp(observable) is True

    def test_unknown_marking_id_falls_back_to_default(self):
        # An unknown id (e.g. a PAP marking) must not match the TLP
        # lookup; the gate falls back to ``IPQS_DEFAULT_TLP``.
        connector = self._make_connector(max_tlp="TLP:AMBER", default_tlp="TLP:CLEAR")
        observable = {"object_marking_refs": ["marking-definition--unknown"]}
        assert connector._check_max_tlp(observable) is True

    def test_no_marking_uses_default_tlp(self):
        connector = self._make_connector(max_tlp="TLP:AMBER", default_tlp="TLP:CLEAR")
        assert connector._check_max_tlp({}) is True

    def test_object_marking_dicts_take_precedence_over_refs(self):
        """When both shapes are present, the dict form is used first."""
        connector = self._make_connector(max_tlp="TLP:AMBER")
        observable = {
            "objectMarking": [
                {"definition_type": "TLP", "definition": "TLP:GREEN"},
            ],
            "object_marking_refs": [stix2.TLP_RED.id],
        }
        assert connector._check_max_tlp(observable) is True

    @pytest.mark.parametrize(
        "observable, expected",
        [
            # Malformed ``objectMarking`` payloads must not crash the
            # gate — the previous shape called
            # ``marking_definition.get(...)`` unconditionally and would
            # raise ``AttributeError`` on a non-dict entry, aborting
            # enrichment for every entity type. With the
            # ``isinstance`` guard the malformed entries are skipped
            # and the gate falls through to the alternate shape /
            # default TLP.
            pytest.param(
                {"objectMarking": "not-a-list"},
                True,
                id="object_marking_not_a_list",
            ),
            pytest.param(
                {"objectMarking": [None, 42, "string-entry"]},
                True,
                id="object_marking_non_dict_entries",
            ),
            pytest.param(
                {"objectMarking": [{"definition_type": "PAP"}]},
                True,
                id="object_marking_no_tlp_dict",
            ),
            # Non-list ``object_marking_refs`` must also fall back to
            # the default rather than raising.
            pytest.param(
                {"object_marking_refs": "not-a-list"},
                True,
                id="flat_refs_not_a_list",
            ),
            # Mixed malformed primary + valid fallback: gate uses the
            # fallback (TLP:RED) to block above the AMBER max.
            pytest.param(
                {
                    "objectMarking": [None, 42],
                    "object_marking_refs": [stix2.TLP_RED.id],
                },
                False,
                id="malformed_primary_valid_fallback",
            ),
        ],
    )
    def test_malformed_payload_does_not_crash(self, observable, expected):
        """Defensive ``isinstance`` guards prevent enrichment-wide aborts.

        Mirrors what ``_observable_marking_refs`` does for the
        failure-Note path — the gate and the failure-note marking
        extractor must agree on the shape contract so a malformed
        payload from one observable type cannot crash enrichment for
        every other entity type the connector handles.
        """
        connector = self._make_connector(max_tlp="TLP:AMBER", default_tlp="TLP:CLEAR")
        assert connector._check_max_tlp(observable) is expected

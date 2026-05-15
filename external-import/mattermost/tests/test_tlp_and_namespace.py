"""Unit tests for the TLP map, channel-name namespacing and the
deterministic media-content id helper.

These three helpers are part of the connector's public contract:

* a misconfigured ``MATTERMOST_TLP`` value must raise a clear error
  listing every accepted alias;
* known aliases must resolve to the canonical OpenCTI marking-definition
  id (in particular ``CLEAR`` / ``WHITE`` share the canonical
  ``TLP:WHITE`` id, and ``AMBER_STRICT`` / ``AMBER+STRICT`` share the
  canonical ``TLP:AMBER+STRICT`` id);
* the OpenCTI Channel name must be namespaced by team so two distinct
  Mattermost channels with the same local name (e.g. ``town-square`` in
  two different teams) do not collide on the same OpenCTI Channel SDO;
* the deterministic media-content id derived from a post URL must match
  the id ``CustomObservableMediaContent`` would auto-generate, so thread
  replies can be linked even when their root was ingested in a previous
  run.
"""

import pytest
import stix2
from main import (
    _TLP_MAP,
    MattermostConnector,
    _make_tlp_marking,
)
from pycti import CustomObservableMediaContent
from pycti import MarkingDefinition as PyctiMarkingDefinition


class TestTLPMap:
    """Every alias in ``_TLP_MAP`` resolves to a real marking definition."""

    @pytest.mark.parametrize("alias", list(_TLP_MAP))
    def test_every_alias_returns_a_marking_definition(self, alias):
        marking = _TLP_MAP[alias]
        assert isinstance(marking, stix2.MarkingDefinition)
        assert marking.id.startswith("marking-definition--")

    def test_clear_and_white_share_the_canonical_tlp_white_id(self):
        # In OpenCTI ``TLP:CLEAR`` is the modern alias of ``TLP:WHITE`` —
        # they resolve to the same canonical marking-definition id (the
        # STIX 2.1 ``TLP:WHITE`` id).
        assert _TLP_MAP["CLEAR"].id == stix2.TLP_WHITE.id
        assert _TLP_MAP["WHITE"].id == stix2.TLP_WHITE.id

    def test_clear_carries_the_clear_label_for_the_ui(self):
        # Even though CLEAR and WHITE share the same id, the connector
        # ships the CLEAR-flavoured marking-definition object (carrying
        # ``x_opencti_definition='TLP:CLEAR'``) so the OpenCTI UI shows
        # the modern ``TLP:CLEAR`` label.
        assert _TLP_MAP["CLEAR"].x_opencti_definition == "TLP:CLEAR"

    def test_amber_strict_aliases_share_the_canonical_id(self):
        canonical_id = PyctiMarkingDefinition.generate_id("TLP", "TLP:AMBER+STRICT")
        assert _TLP_MAP["AMBER_STRICT"].id == canonical_id
        assert _TLP_MAP["AMBER+STRICT"].id == canonical_id

    @pytest.mark.parametrize(
        ("alias", "stix2_constant"),
        [
            ("WHITE", stix2.TLP_WHITE),
            ("GREEN", stix2.TLP_GREEN),
            ("AMBER", stix2.TLP_AMBER),
            ("RED", stix2.TLP_RED),
        ],
    )
    def test_built_in_aliases_match_stix2_constants(self, alias, stix2_constant):
        assert _TLP_MAP[alias] is stix2_constant


class TestResolveTLP:
    """``_resolve_tlp`` is forgiving about case and whitespace."""

    @pytest.mark.parametrize(
        ("raw", "expected_alias"),
        [
            ("clear", "CLEAR"),
            ("CLEAR", "CLEAR"),
            ("  amber+strict  ", "AMBER+STRICT"),
            ("amber strict", "AMBER_STRICT"),  # space → underscore
            ("RED", "RED"),
        ],
    )
    def test_aliases_are_normalised(self, raw, expected_alias):
        assert MattermostConnector._resolve_tlp(raw) is _TLP_MAP[expected_alias]

    def test_unknown_value_lists_every_supported_alias(self):
        with pytest.raises(ValueError) as exc:
            MattermostConnector._resolve_tlp("nonsense")
        message = str(exc.value)
        for alias in _TLP_MAP:
            assert alias in message

    @pytest.mark.parametrize("blank", [None, "", "   "])
    def test_blank_value_raises(self, blank):
        with pytest.raises(ValueError):
            MattermostConnector._resolve_tlp(blank)


class TestNamespacedChannelName:
    """The OpenCTI Channel name is namespaced by Mattermost team."""

    def test_team_and_channel_are_joined_with_a_slash(self):
        assert (
            MattermostConnector._namespaced_channel_name("team-a", "town-square")
            == "team-a/town-square"
        )

    def test_two_teams_with_the_same_channel_name_do_not_collide(self):
        # Same Mattermost local name in two different teams must produce
        # two distinct OpenCTI Channel names so the SDOs cannot merge.
        assert MattermostConnector._namespaced_channel_name(
            "team-a", "town-square"
        ) != MattermostConnector._namespaced_channel_name("team-b", "town-square")


class TestMediaContentId:
    """The locally computed media-content id matches stix2 / pycti's."""

    def test_id_matches_custom_observable_auto_generated_id(self):
        url = "https://mm.example.org:8065/team-a/pl/abc123"
        local_id = MattermostConnector._media_content_id(url)
        reference = CustomObservableMediaContent(url=url, allow_custom=True)["id"]
        assert local_id == reference

    def test_two_different_urls_produce_two_different_ids(self):
        a = MattermostConnector._media_content_id(
            "https://mm.example.org:8065/team-a/pl/abc123"
        )
        b = MattermostConnector._media_content_id(
            "https://mm.example.org:8065/team-a/pl/def456"
        )
        assert a != b


class TestMakeTLPMarking:
    """``_make_tlp_marking`` is the helper used to materialise CLEAR / AMBER+STRICT."""

    def test_id_matches_pycti_canonical_id(self):
        marking = _make_tlp_marking("TLP:AMBER+STRICT")
        assert marking.id == PyctiMarkingDefinition.generate_id(
            "TLP", "TLP:AMBER+STRICT"
        )

    def test_marking_carries_opencti_metadata(self):
        marking = _make_tlp_marking("TLP:CLEAR")
        assert marking.x_opencti_definition_type == "TLP"
        assert marking.x_opencti_definition == "TLP:CLEAR"
        assert marking.definition_type == "statement"

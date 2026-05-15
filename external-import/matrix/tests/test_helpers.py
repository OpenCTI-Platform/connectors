"""Unit tests for ``lib.helpers``.

The helpers exposed here are part of the connector's public contract:

* ``resolve_tlp`` must accept every documented alias (with any
  combination of case, whitespace, ``-`` / ``_`` / ``+`` separators on
  the strict variant), and must raise a clear ``ValueError`` listing
  every supported alias on unknown input;
* ``TLP_MAP`` must keep ``CLEAR`` and ``WHITE`` pointing at the same
  canonical id (the OpenCTI ``TLP:WHITE`` id) and ``AMBER_STRICT`` /
  ``AMBER+STRICT`` pointing at the same canonical
  ``TLP:AMBER+STRICT`` id;
* ``media_content_id`` must produce the same id as
  ``pycti.CustomObservableMediaContent`` would auto-generate from the
  same URL, so thread-reply relationships can be linked deterministically
  without a round-trip through OpenCTI.
"""

import pytest
import stix2
from lib.helpers import TLP_MAP, media_content_id, resolve_tlp
from pycti import CustomObservableMediaContent


class TestTLPMap:
    """Every alias in ``TLP_MAP`` resolves to the right canonical id."""

    @pytest.mark.parametrize("alias", list(TLP_MAP))
    def test_every_alias_returns_a_marking_id(self, alias):
        assert TLP_MAP[alias].startswith("marking-definition--")

    def test_clear_and_white_share_the_canonical_tlp_white_id(self):
        # In OpenCTI ``TLP:CLEAR`` is the modern alias of ``TLP:WHITE`` —
        # both resolve to the same canonical marking-definition id (the
        # STIX 2.1 ``TLP:WHITE`` id).
        assert TLP_MAP["CLEAR"] == stix2.TLP_WHITE.id
        assert TLP_MAP["WHITE"] == stix2.TLP_WHITE.id

    def test_amber_strict_aliases_share_the_canonical_id(self):
        assert TLP_MAP["AMBER_STRICT"] == TLP_MAP["AMBER+STRICT"]

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
        assert TLP_MAP[alias] == stix2_constant.id


class TestResolveTLP:
    """``resolve_tlp`` is forgiving about case, whitespace and separators."""

    @pytest.mark.parametrize(
        ("raw", "expected_alias"),
        [
            ("clear", "CLEAR"),
            ("CLEAR", "CLEAR"),
            ("white", "WHITE"),
            ("  amber+strict  ", "AMBER+STRICT"),
            ("amber strict", "AMBER_STRICT"),
            ("amber-strict", "AMBER_STRICT"),
            ("AMBER-Strict", "AMBER_STRICT"),
            ("RED", "RED"),
        ],
    )
    def test_aliases_are_normalised(self, raw, expected_alias):
        assert resolve_tlp(raw) == TLP_MAP[expected_alias]

    def test_unknown_value_lists_every_supported_alias(self):
        with pytest.raises(ValueError) as exc:
            resolve_tlp("nonsense")
        message = str(exc.value)
        for alias in TLP_MAP:
            assert alias in message

    @pytest.mark.parametrize("blank", [None, "", "   "])
    def test_blank_value_raises(self, blank):
        with pytest.raises(ValueError):
            resolve_tlp(blank)


class TestMediaContentId:
    """The locally computed media-content id matches stix2 / pycti's."""

    def test_id_matches_custom_observable_auto_generated_id(self):
        url = "$abcdef:matrix.example.org"
        local_id = media_content_id(url)
        reference = CustomObservableMediaContent(url=url, allow_custom=True)["id"]
        assert local_id == reference

    def test_two_different_urls_produce_two_different_ids(self):
        a = media_content_id("$root:matrix.example.org")
        b = media_content_id("$reply:matrix.example.org")
        assert a != b

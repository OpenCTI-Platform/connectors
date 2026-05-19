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

from datetime import datetime, timezone
from types import SimpleNamespace
from typing import List

import pytest
import stix2
from lib.helpers import (
    TLP_MAP,
    channel_display_name,
    media_content_id,
    publication_date_from_event,
    resolve_tlp,
)
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


class TestChannelDisplayName:
    """``channel_display_name`` prefers the human-friendly room name.

    The Matrix ``room_id`` is opaque (``!abcdef:matrix.example.org``);
    analysts in the OpenCTI *Channels* list expect to see the room
    display name (``#general``) instead. The helper falls back to the
    raw ``room_id`` whenever the display name is missing / blank so
    the Channel SDO is always queryable. The deterministic
    ``standard_id`` is computed from ``room_id`` upstream, so dedup is
    unaffected.
    """

    def test_returns_room_name_when_present(self):
        assert channel_display_name("!abc:matrix.example.org", "#general") == "#general"

    @pytest.mark.parametrize("blank", [None, "", "   "])
    def test_falls_back_to_room_id_when_name_is_blank(self, blank):
        assert (
            channel_display_name("!abc:matrix.example.org", blank)
            == "!abc:matrix.example.org"
        )

    def test_strips_whitespace(self):
        assert (
            channel_display_name("!abc:matrix.example.org", "  #general  ")
            == "#general"
        )


class TestPublicationDateFromEvent:
    """``publication_date_from_event`` validates ``server_timestamp``.

    A malformed / synthetic Matrix event with a missing or non-numeric
    ``server_timestamp`` must fall back to the current UTC time and emit
    a warning via the injected ``log_warning`` callable, instead of
    letting the resulting ``TypeError`` bubble up through the outer
    ``except`` block (which would silently drop the event).
    """

    @staticmethod
    def _recorder() -> tuple:
        warnings: List[str] = []
        return warnings, warnings.append

    def test_valid_millisecond_timestamp_is_parsed_as_utc(self):
        warnings, log_warning = self._recorder()
        ts_ms = 1778834760_000  # arbitrary "well after the epoch" timestamp
        event = SimpleNamespace(
            server_timestamp=ts_ms, event_id="$valid:matrix.example.org"
        )
        result = publication_date_from_event(event, log_warning)
        # Compare against the same conversion we expect ``main.py`` to
        # use (millisecond Unix timestamp -> UTC ``datetime``) instead
        # of a hard-coded calendar string so the test stays independent
        # of the runner's local timezone.
        assert result == datetime.fromtimestamp(ts_ms / 1000, tz=timezone.utc)
        assert result.tzinfo == timezone.utc
        assert warnings == []

    @pytest.mark.parametrize(
        "bad_ts",
        [None, "not-a-number", 0, -1, [1234], True, False],
    )
    def test_invalid_timestamp_falls_back_to_now_with_warning(self, bad_ts):
        warnings, log_warning = self._recorder()
        event = SimpleNamespace(
            server_timestamp=bad_ts, event_id="$bad:matrix.example.org"
        )
        before = datetime.now(tz=timezone.utc)
        result = publication_date_from_event(event, log_warning)
        after = datetime.now(tz=timezone.utc)
        assert before <= result <= after
        assert len(warnings) == 1
        assert "$bad:matrix.example.org" in warnings[0]
        assert "server_timestamp" in warnings[0]

    def test_missing_server_timestamp_attribute_falls_back(self):
        warnings, log_warning = self._recorder()
        event = SimpleNamespace(event_id="$no-ts:matrix.example.org")
        result = publication_date_from_event(event, log_warning)
        assert result.tzinfo == timezone.utc
        assert len(warnings) == 1
        assert "$no-ts:matrix.example.org" in warnings[0]

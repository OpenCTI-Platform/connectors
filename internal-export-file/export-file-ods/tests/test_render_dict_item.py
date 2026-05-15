"""Unit tests for ``lib.rendering`` (list-of-dict cell rendering).

These tests pin the contract used by ``_row_for`` when an OpenCTI list
attribute contains dicts (``externalReferences``, ``killChainPhases``,
``objectMarking``, ...). They guarantee that:

* well-known shapes render in the form operators expect
  (``MITRE ATT&CK: https://...``, ``mitre-attack:execution``, ...);
* unknown shapes still surface their content (JSON fallback) instead of
  silently producing an empty cell;
* non-dict items are sanitised through ``sanitize_cell`` so formula
  injection cannot bypass the spreadsheet defence.
"""

import pytest
from lib.rendering import (
    DICT_ITEM_STRATEGIES,
    render_dict_item,
    render_dict_list,
)


class TestRenderDictItemKnownShapes:
    """Well-known OpenCTI dict shapes render to the canonical text."""

    def test_external_reference_with_source_and_url(self):
        assert (
            render_dict_item(
                {"source_name": "MITRE ATT&CK", "url": "https://attack.mitre.org/T1059"}
            )
            == "MITRE ATT&CK: https://attack.mitre.org/T1059"
        )

    def test_external_reference_with_url_only(self):
        assert (
            render_dict_item({"url": "https://example.com/ref"})
            == "https://example.com/ref"
        )

    def test_external_reference_with_source_name_only(self):
        assert render_dict_item({"source_name": "internal-vendor"}) == "internal-vendor"

    def test_kill_chain_phase_uses_colon_separator(self):
        assert (
            render_dict_item(
                {"kill_chain_name": "mitre-attack", "phase_name": "execution"}
            )
            == "mitre-attack:execution"
        )

    def test_kill_chain_phase_with_only_phase_name_returns_phase_name(self):
        # When only one half of the composite strategy is present, the
        # renderer returns that single value (matching the single-key
        # branch) instead of dropping it or falling back to JSON.
        assert render_dict_item({"phase_name": "execution"}) == "execution"

    @pytest.mark.parametrize(
        ("item", "expected"),
        [
            ({"name": "APT29"}, "APT29"),
            ({"definition": "TLP:AMBER"}, "TLP:AMBER"),
            ({"value": "1.2.3.4"}, "1.2.3.4"),
            ({"observable_value": "evil.com"}, "evil.com"),
        ],
    )
    def test_single_key_strategies_return_the_value(self, item, expected):
        assert render_dict_item(item) == expected

    def test_more_specific_strategy_wins_over_name(self):
        # ``source_name`` + ``url`` must be preferred over ``name`` so an
        # external reference with both ``name`` and ``url`` does not collapse
        # to the bare name.
        item = {
            "name": "T1059",
            "source_name": "MITRE ATT&CK",
            "url": "https://attack.mitre.org/T1059",
        }
        assert render_dict_item(item) == (
            "MITRE ATT&CK: https://attack.mitre.org/T1059"
        )


class TestRenderDictItemFallback:
    """Unsupported shapes must still surface their content."""

    def test_unknown_shape_falls_back_to_json(self):
        assert render_dict_item({"score": 80, "vendor": "ACME"}) == (
            '{"score": 80, "vendor": "ACME"}'
        )

    def test_empty_dict_falls_back_to_json(self):
        assert render_dict_item({}) == "{}"

    def test_non_dict_input_is_sanitised(self):
        # ``sanitize_cell`` escapes the leading ``=`` so a non-dict value
        # smuggled into the list cannot inject a formula.
        assert render_dict_item("=SUM(A1:A2)") == "[=]SUM(A1:A2)"


class TestRenderDictItemEmptyValues:
    """Empty / ``None`` strategy values must be ignored."""

    def test_empty_url_falls_back_to_source_name_only(self):
        # ``url`` is empty so the (source_name, url) strategy reports a
        # single-key match on ``source_name`` and returns just that.
        assert (
            render_dict_item({"source_name": "MITRE ATT&CK", "url": ""})
            == "MITRE ATT&CK"
        )

    def test_none_values_are_treated_as_missing(self):
        assert render_dict_item({"name": None, "value": "1.2.3.4"}) == "1.2.3.4"


class TestRenderDictList:
    """``render_dict_list`` joins items with ``,`` and skips empties."""

    def test_external_references_list(self):
        items = [
            {"source_name": "MITRE ATT&CK", "url": "https://attack.mitre.org/T1059"},
            {"source_name": "internal-vendor"},
        ]
        assert render_dict_list(items) == (
            "MITRE ATT&CK: https://attack.mitre.org/T1059,internal-vendor"
        )

    def test_empty_list_returns_empty_string(self):
        assert render_dict_list([]) == ""

    def test_non_list_returns_empty_string(self):
        assert render_dict_list({"name": "x"}) == ""


class TestStrategiesContract:
    """The strategy table itself is part of the public contract."""

    def test_strategy_order_starts_with_composites(self):
        assert DICT_ITEM_STRATEGIES[0] == ("source_name", "url")
        assert DICT_ITEM_STRATEGIES[1] == ("kill_chain_name", "phase_name")

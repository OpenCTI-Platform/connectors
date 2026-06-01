"""Tests for Snort parser handling of rules without trailing newline (issue #6427)."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from crowdstrike_feeds_services.utils.snort_parser import SnortParser

SINGLE_RULE = (
    "alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS "
    '(msg: "Malware CrowdStrike MALWARE_NAME Outbound [CSIT-00001]"; '
    'content:"evil"; rev:20250528; sid:1000001;)'
)


class TestSplitSnortRulesTrailingNewline:
    """Test _split_snort_rules with and without trailing newline."""

    def test_rule_with_trailing_newline(self):
        """Rule ending with newline should be parsed (existing behavior)."""
        rules_str = SINGLE_RULE + "\n"
        result = SnortParser._split_snort_rules(rules_str)
        assert len(result) == 1

    def test_rule_without_trailing_newline(self):
        """Rule without trailing newline should still be parsed (bug #6427)."""
        result = SnortParser._split_snort_rules(SINGLE_RULE)
        assert len(result) == 1, "Rule without trailing newline was dropped — bug #6427"

    def test_two_rules_last_without_newline(self):
        """Two rules where the last has no trailing newline."""
        rules_str = SINGLE_RULE + "\n" + SINGLE_RULE
        result = SnortParser._split_snort_rules(rules_str)
        assert (
            len(result) == 2
        ), "Last rule without trailing newline was dropped — bug #6427"

    def test_multiple_rules_all_with_newline(self):
        """Multiple rules all ending with newline."""
        rules_str = (SINGLE_RULE + "\n") * 3
        result = SnortParser._split_snort_rules(rules_str)
        assert len(result) == 3


class TestSnortParserFullParse:
    """Test full parse of Snort rules without trailing newline."""

    def test_parse_single_rule_no_trailing_newline(self):
        """Full parse should work without trailing newline."""
        result = SnortParser.parse(SINGLE_RULE)
        assert (
            len(result) == 1
        ), "Full parse lost rule without trailing newline — bug #6427"
        assert "CSIT-00001" in result[0].name
        assert "MALWARE_NAME" in result[0].description

    def test_parse_single_rule_with_trailing_newline(self):
        """Full parse with trailing newline (baseline)."""
        result = SnortParser.parse(SINGLE_RULE + "\n")
        assert len(result) == 1
        assert "CSIT-00001" in result[0].name

"""Tests for RuleParser (Snort/Suricata rule string -> Rule models)."""

from unittest.mock import MagicMock

from connector.models.rule import Rule, RuleParser

VALID_RULE = 'alert tcp any any -> any any (msg:"VULNCHECK Test Rule"; sid:1000001;)\n'
# An alert rule whose msg has no VULNCHECK token -> no description -> skipped.
NO_MATCH_RULE = 'alert tcp any any -> any any (msg:"unrelated"; sid:42;)\n'


def test_parse_empty_string_returns_empty():
    assert RuleParser.parse("", MagicMock()) == []


def test_parse_no_alert_lines_returns_empty():
    assert RuleParser.parse("this is not a rule\n", MagicMock()) == []


def test_parse_valid_rule():
    rules = RuleParser.parse(VALID_RULE, MagicMock())

    assert len(rules) == 1
    rule = rules[0]
    assert isinstance(rule, Rule)
    assert rule.rule == VALID_RULE
    assert "VULNCHECK Test Rule" in rule.name
    assert "1000001" in rule.name
    assert rule.description


def test_parse_skips_rule_without_vulncheck_msg():
    assert RuleParser.parse(NO_MATCH_RULE, MagicMock()) == []


def test_parse_multiple_rules():
    rules = RuleParser.parse(VALID_RULE + VALID_RULE, MagicMock())
    assert len(rules) == 2

import re

import pytest
from pydantic import ValidationError
from settings import Definition, Rule


def make_rule(**overrides):
    rule = {
        "label": "demo",
        "search": "foo|bar",
        "flags": ["IGNORECASE"],
        "attributes": ["name", "description"],
    }
    rule.update(overrides)
    return rule


class TestRuleValidation:
    def test_valid_rule_compiles_pattern_once(self):
        rule = Rule(**make_rule())

        assert isinstance(rule.pattern, re.Pattern)
        assert rule.pattern.pattern == "foo|bar"
        assert rule.pattern.flags & re.IGNORECASE

    def test_flags_default_to_empty_list(self):
        rule_config = make_rule()
        del rule_config["flags"]

        rule = Rule(**rule_config)

        assert rule.flags == []
        assert isinstance(rule.pattern, re.Pattern)

    def test_pattern_is_excluded_from_serialization(self):
        rule = Rule(**make_rule())

        assert "pattern" not in rule.model_dump()
        assert "pattern" not in Rule.model_json_schema()["properties"]

    def test_invalid_regex_is_rejected_at_load_time(self):
        with pytest.raises(ValidationError) as exc_info:
            Rule(**make_rule(search="foo|?bar"))

        message = str(exc_info.value)
        assert "Invalid regular expression" in message
        assert "'foo|?bar'" in message
        assert "'demo'" in message

    @pytest.mark.parametrize(
        "flag",
        ["ignorecase", "search", "G", "NOTAFLAG"],
    )
    def test_invalid_flag_is_rejected_at_load_time(self, flag):
        with pytest.raises(ValidationError) as exc_info:
            Rule(**make_rule(flags=[flag]))

        message = str(exc_info.value)
        assert "Invalid regex flag" in message
        assert repr(flag) in message
        assert "'demo'" in message

    def test_flags_as_string_is_rejected(self):
        with pytest.raises(ValidationError):
            Rule(**make_rule(flags="IGNORECASE"))


class TestDefinitionValidation:
    def test_definition_validates_nested_rules(self):
        with pytest.raises(ValidationError):
            Definition(
                scopes=["Report"],
                rules=[make_rule(search="foo|?bar")],
            )

    def test_definition_exposes_compiled_rules(self):
        definition = Definition(scopes=["Report"], rules=[make_rule()])

        assert isinstance(definition.rules[0].pattern, re.Pattern)

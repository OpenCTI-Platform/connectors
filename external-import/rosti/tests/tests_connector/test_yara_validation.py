"""Tests for connector.test_yara_rule.valid_rule (human-readable YARA checks)."""

import pytest
from conftest import load_fixture
from connector.test_yara_rule import valid_rule


def test_valid_rule_with_tags_and_modules():
    rule = 'import "pe"\nrule A : tag1 tag2 {\n strings:\n  $a = "x"\n condition:\n  $a and pe.number_of_sections > 1\n}'
    assert valid_rule(rule) == (True, [])


def test_sample_rules_from_rosti_are_valid():
    for item in load_fixture("yara_rules.json")["data"]:
        assert valid_rule(item["rule"]) == (True, [])


def test_missing_opening_brace_like_in_rosti_data():
    # The most common problem in Rösti's data: "{" missing after the rule name.
    rule = 'rule M_APT_Dropper_X_1\n  meta:\n    author = "x"\n  strings:\n    $a = "x"\n  condition:\n    $a\n}'
    ok, errors = valid_rule(rule)
    assert not ok
    assert errors == [
        'Rule "M_APT_Dropper_X_1", line 2 (meta:): the rule body does not start with "{". '
        'Add "{" after "rule M_APT_Dropper_X_1".'
    ]


def test_all_rules_with_a_missing_brace_are_reported():
    rule = 'rule A\n meta:\n  x = 1\n condition:\n  true\n}\nrule B\n strings:\n  $a = "x"\n condition:\n  $a\n}'
    ok, errors = valid_rule(rule)
    assert not ok
    assert [e.split(",")[0] for e in errors] == ['Rule "A"', 'Rule "B"']
    assert "line 8 (strings:)" in errors[1]


def test_every_undefined_string_is_reported_with_its_line():
    rule = 'rule B {\n strings:\n  $a = "x"\n condition:\n  $a and $b and #c > 2\n}'
    ok, errors = valid_rule(rule)
    assert not ok
    assert len(errors) == 2
    assert "line 5" in errors[0] and "uses $b" in errors[0]
    assert "uses $c" in errors[1]


def test_every_unused_string_is_reported_where_it_is_defined():
    rule = (
        'rule C {\n strings:\n  $a = "x"\n  $b = "y"\n  $c = "z"\n condition:\n  $a\n}'
    )
    ok, errors = valid_rule(rule)
    assert not ok
    assert [("line 4" in errors[0]), ("line 5" in errors[1])] == [True, True]
    assert "$b is defined but never used" in errors[0]


def test_wildcards_and_them_count_as_used():
    rule = 'rule W {\n strings:\n  $s1 = "x"\n  $s2 = "y"\n  $t = "z"\n condition:\n  any of ($s*) and $t and $zz\n}'
    ok, errors = valid_rule(rule)
    assert not ok
    assert len(errors) == 1 and "uses $zz" in errors[0]


def test_comments_and_text_inside_strings_are_ignored():
    rule = 'rule T {\n // condition: $zz\n strings:\n  $a = "condition: $q"\n condition:\n  $a and $b\n}'
    ok, errors = valid_rule(rule)
    assert not ok
    assert len(errors) == 1 and "uses $b" in errors[0]


@pytest.mark.parametrize(
    "rule, expected",
    [
        ('rule D { condition: filename == "a" }', '"filename" is an external variable'),
        (
            "rule E { condition: pe.number_of_sections > 1 }",
            'Add the line import "pe" above the rule',
        ),
        ("rule F { condition: Helper }", '"Helper" is not defined'),
        (
            'rule F {\n strings:\n  $a = "x"\n condition:\n  $a and',
            "at the end: the rule ends unexpectedly",
        ),
        ("rule L { condition: true", 'ends before its closing "}"'),
        ('rule I { strings: $a = "abc condition: $a }', "a text string is not closed"),
        (
            'rule G { strings: $a = "x" $a = "y" condition: all of them }',
            "$a is defined more than once",
        ),
        (
            "rule K { condition: true }\nrule K { condition: true }",
            'more than one rule named "K"',
        ),
        (
            "rule J { strings: $a = /ab(c/ condition: $a }",
            "regular expression $a is invalid",
        ),
        (
            'import "foo"\nrule M { condition: true }',
            'Line 1 (import "foo"): imports the module "foo"',
        ),
        ("rule N { condtion: true }", '"condition:" is missing or misspelled'),
    ],
)
def test_compiler_errors_are_explained(rule, expected):
    ok, errors = valid_rule(rule)
    assert not ok
    assert expected in errors[0]


def test_text_without_a_rule_is_invalid():
    assert valid_rule("") == (
        False,
        ['No YARA rule found: the text contains no "rule <name> { ... }" definition.'],
    )
    assert valid_rule("just some text")[0] is False


def test_non_string_input_is_rejected():
    with pytest.raises(TypeError):
        valid_rule(None)

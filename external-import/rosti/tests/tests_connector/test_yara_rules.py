"""Tests for YARA rule preparation (OpenCTI compiles every YARA indicator)."""

from conftest import load_fixture
from connector.test_yara_rule import valid_rule
from connector.yara_rules import prepare_yara_patterns
from rosti_client.models import Yara


def rule(name: str, text: str) -> Yara:
    return Yara(id=name, name=name, filename=f"{name}.yara", rule=text, report="r")


def test_sample_rules_compile():
    rules = [Yara.model_validate(r) for r in load_fixture("yara_rules.json")["data"]]
    accepted, skipped = prepare_yara_patterns(rules)
    assert [a.rule.name for a in accepted] == ["PavokwiLoader_1", "RMMCRAT_1"]
    assert not skipped
    assert accepted[0].pattern == rules[0].rule.strip()


def test_rule_using_private_helper_gets_it_prepended():
    helper = rule("Helper", 'private rule Helper { strings: $a = "x" condition: $a }')
    main = rule("Main", "rule Main { condition: Helper and filesize < 1MB }")
    accepted, skipped = prepare_yara_patterns([helper, main])

    assert not skipped
    by_name = {a.rule.name: a for a in accepted}
    assert by_name["Main"].dependencies == ["Helper"]
    assert by_name["Main"].pattern.index("rule Helper") < by_name["Main"].pattern.index(
        "rule Main"
    )
    assert valid_rule(by_name["Main"].pattern) == (True, [])
    assert by_name["Helper"].dependencies == []


def test_transitive_dependencies():
    a = rule("A", 'private rule A { strings: $a = "a" condition: $a }')
    b = rule("B", "private rule B { condition: A }")
    c = rule("C", "rule C { condition: B }")
    accepted, skipped = prepare_yara_patterns([c, b, a])
    assert not skipped
    by_name = {x.rule.name: x for x in accepted}
    assert by_name["C"].dependencies == ["A", "B"]


def test_external_variables_and_syntax_errors_are_skipped():
    externals = rule("Ext", 'rule Ext { condition: filename == "x.exe" }')
    broken = rule("Broken", "rule Broken { condition: }")
    missing = rule("Missing", "rule Missing { condition: NotInThisReport }")
    accepted, skipped = prepare_yara_patterns([externals, broken, missing])
    assert not accepted
    reasons = {s.rule.name: s.reason for s in skipped}
    assert set(reasons) == {"Ext", "Broken", "Missing"}
    assert "external variable" in reasons["Ext"]


def test_modules_are_allowed():
    pe = rule("Pe", 'import "pe"\nrule Pe { condition: pe.number_of_sections > 2 }')
    accepted, skipped = prepare_yara_patterns([pe])
    assert len(accepted) == 1 and not skipped


def test_string_identifier_named_like_rule_is_not_a_dependency():
    a = rule("abc", 'rule abc { strings: $s = "1" condition: $s }')
    b = rule("B", 'rule B { strings: $abc = "2" condition: $abc }')
    accepted, _ = prepare_yara_patterns([a, b])
    assert {x.rule.name: x.dependencies for x in accepted} == {"abc": [], "B": []}

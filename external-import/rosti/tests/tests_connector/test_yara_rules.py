"""Tests for YARA rule preparation (OpenCTI compiles every YARA indicator)."""

import yara
from conftest import load_fixture
from connector.yara_rules import compile_error, prepare_yara_patterns
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
    assert compile_error(by_name["Main"].pattern) is None
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
    errors = {s.rule.name: s.error for s in skipped}
    assert set(errors) == {"Ext", "Broken", "Missing"}
    # The compiler's own message is kept
    assert errors["Ext"] == 'line 1: undefined identifier "filename"'
    assert errors["Missing"] == 'line 1: undefined identifier "NotInThisReport"'


def test_compile_error():
    assert compile_error('rule A { strings: $a = "x" condition: $a }') is None
    assert compile_error('rule A { strings: $a = "x" condition: $b }') == (
        'line 1: undefined string "$b"'
    )


def test_modules_are_allowed():
    pe = rule("Pe", 'import "pe"\nrule Pe { condition: pe.number_of_sections > 2 }')
    accepted, skipped = prepare_yara_patterns([pe])
    assert len(accepted) == 1 and not skipped


def test_string_identifier_named_like_rule_is_not_a_dependency():
    a = rule("abc", 'rule abc { strings: $s = "1" condition: $s }')
    b = rule("B", 'rule B { strings: $abc = "2" condition: $abc }')
    accepted, _ = prepare_yara_patterns([a, b])
    assert {x.rule.name: x.dependencies for x in accepted} == {"abc": [], "B": []}


def test_includes_are_not_read(tmp_path):
    """An include would read a file on the connector's machine: rejected."""
    local = tmp_path / "local.yar"
    local.write_text("rule Local { condition: true }", encoding="utf-8")
    uses_it = rule(
        "Uses", f'include "{local.as_posix()}"\nrule Uses {{ condition: Local }}'
    )
    only_includes = rule(
        "Only", f'include "{local.as_posix()}"\nrule Only {{ condition: true }}'
    )
    accepted, skipped = prepare_yara_patterns([uses_it, only_includes])
    assert not accepted
    errors = {s.rule.name: s.error for s in skipped}
    # The included file is not read, so its rule stays undefined
    assert errors == {
        "Uses": 'line 2: undefined identifier "Local"',
        "Only": "line 1: includes are disabled",
    }


def test_names_in_strings_and_comments_are_not_dependencies():
    helper = rule("Helper", 'private rule Helper { strings: $a = "x" condition: $a }')
    broken = rule("Broken", 'rule Broken { condition: filename == "a" }')
    main = rule(
        "Main",
        'rule Main {\n meta:\n  note = "not Broken"\n strings:\n  $s = "Broken"\n'
        " condition:\n  Helper and $s // Broken\n}",
    )
    accepted, skipped = prepare_yara_patterns([helper, broken, main])
    by_name = {a.rule.name: a for a in accepted}
    assert by_name["Main"].dependencies == ["Helper"]
    assert "rule Broken" not in by_name["Main"].pattern
    assert [s.rule.name for s in skipped] == ["Broken"]


def test_prepended_public_helper_is_private_and_cannot_match_alone():
    helper = rule(
        "PubHelper", 'import "pe"\nrule PubHelper { strings: $a = "x" condition: $a }'
    )
    main = rule("Main", "rule Main { condition: PubHelper and filesize < 10 }")
    accepted, skipped = prepare_yara_patterns([helper, main])
    assert not skipped
    by_name = {a.rule.name: a for a in accepted}
    combined = by_name["Main"].pattern
    assert "private rule PubHelper" in combined and 'import "pe"' in combined
    # The helper's own indicator is unchanged
    assert by_name["PubHelper"].pattern == helper.rule
    compiled = yara.compile(source=combined)
    assert compiled.match(data=b"x" * 100) == []  # Main is false, nothing matches
    assert [m.rule for m in compiled.match(data=b"x")] == ["Main"]


def test_other_modifiers_are_kept_when_made_private():
    helper = rule("G", 'global rule G { strings: $a = "x" condition: $a }')
    main = rule("Main", "rule Main { condition: G }")
    accepted, _ = prepare_yara_patterns([helper, main])
    combined = {a.rule.name: a for a in accepted}["Main"].pattern
    assert combined.startswith("global private rule G")


def test_dependency_needed_by_two_rules_is_defined_first():
    a = rule("A", 'private rule A { strings: $a = "a" condition: $a }')
    b = rule("B", "private rule B { condition: A }")
    main = rule("Main", "rule Main { condition: A and B }")
    accepted, skipped = prepare_yara_patterns([main, b, a])
    assert not skipped
    assert {x.rule.name: x for x in accepted}["Main"].dependencies == ["A", "B"]


def test_failing_helper_is_named_in_the_error():
    helper = rule("Helper", 'rule Helper { condition: filename == "x" }')
    main = rule("Main", "rule Main { condition: Helper }")
    _, skipped = prepare_yara_patterns([helper, main])
    errors = {s.rule.name: s.error for s in skipped}
    assert errors["Main"] == (
        'line 1: undefined identifier "filename" (with helper rules Helper prepended)'
    )

from unittest.mock import MagicMock, patch

import pytest
from sentinelone_hunt.powerquery import (
    PIPELINES,
    PowerQueryBackend,
    quote_string,
    wildcard_regex,
)
from sigma.collection import SigmaCollection
from sigma.conversion.deferred import DeferredQueryExpression
from sigma.types import SigmaString


def convert(detection: str, category: str = "process_creation") -> str:
    """Translate a Windows rule with the SentinelOne pipeline."""
    rule = f"""
title: Test
logsource:
  category: {category}
  product: windows
detection:
{detection}
"""
    backend = PowerQueryBackend(PIPELINES["sentinelone_pq"]())
    (query,) = backend.convert(SigmaCollection.from_yaml(rule))
    return query


def test_a_rule_keeps_the_log_source_conditions_of_the_pipeline():
    # Given/When a process creation rule is translated
    query = convert("""
  selection:
    Image|endswith: '\\powershell.exe'
    CommandLine|contains: ' -enc '
  condition: selection
""")

    # Then the event type and the operating system of the log source frame the
    # detection, with suffixes as ends_with and substrings as contains
    assert query == (
        'event.type in:anycase ("Process Creation") and '
        '(endpoint.os in:anycase ("windows") and '
        r'(tgt.process.image.path ends_with "\\powershell.exe" and '
        'tgt.process.cmdline contains " -enc "))'
    )


def test_negations_are_parenthesised():
    # Given/When a rule with a filter is translated
    query = convert("""
  selection:
    Image|endswith: '\\cmd.exe'
  filter:
    ParentImage|endswith: '\\explorer.exe'
  condition: selection and not filter
""")

    # Then the filter is negated with !(...), never with a bare not
    assert r'!(src.process.image.path ends_with "\\explorer.exe")' in query
    assert " not " not in query.lower()


def test_whole_values_compare_without_case():
    # Given/When values are matched whole
    query = convert("""
  selection:
    User: ['a', 'B']
  condition: selection
""")

    # Then they are compared with in:anycase (= and in compare with case)
    assert 'tgt.process.user in:anycase ("a","B")' in query


def test_prefixes_and_cased_modifiers():
    # Given/When a prefix and a cased substring are matched
    query = convert("""
  selection:
    User|startswith: 'NT AUTH'
    CommandLine|cased|contains: 'Enc'
  condition: selection
""")

    # Then the prefix uses starts_with and the cased substring keeps its case
    assert 'tgt.process.user starts_with "NT AUTH"' in query
    assert 'tgt.process.cmdline contains:matchcase "Enc"' in query


def test_cased_prefixes_and_suffixes_use_matchcase():
    # Given/When cased prefixes and suffixes are matched
    query = convert("""
  selection:
    User|cased|startswith: 'Adm'
    Image|cased|endswith: '.EXE'
  condition: selection
""")

    # Then they use the matchcase forms of starts_with and ends_with
    assert 'tgt.process.user starts_with:matchcase("Adm")' in query
    assert 'tgt.process.image.path ends_with:matchcase(".EXE")' in query


def test_wildcards_inside_a_value_become_an_anchored_regex():
    # Given/When a value has wildcards in its middle
    query = convert("""
  selection:
    CommandLine: 'run*now?x.y'
  condition: selection
""")

    # Then it is matched with an anchored, escaped regular expression
    assert r'tgt.process.cmdline matches "^run.*now.x\\.y$"' in query


def test_regular_expressions_are_escaped_for_the_string_literal():
    # Given/When a Sigma regular expression is translated
    query = convert("""
  selection:
    CommandLine|re: '\\d+ -x'
  condition: selection
""")

    # Then its backslashes are doubled for the PowerQuery string literal
    assert r'tgt.process.cmdline matches "\\d+ -x"' in query


def test_null_fields_are_negated_existence_checks():
    # Given/When a field must be empty
    query = convert("""
  selection:
    CommandLine: null
  condition: selection
""")

    # Then the field is required not to exist
    assert "!(tgt.process.cmdline = *)" in query


def test_cidr_ranges_become_address_prefixes():
    # Given/When a CIDR range is matched
    query = convert(
        """
  selection:
    DestinationIp|cidr: '10.0.0.0/8'
  condition: selection
""",
        category="network_connection",
    )

    # Then the address prefix is matched
    assert 'dst.ip.address starts_with "10."' in query


def test_rule_fields_add_no_columns():
    # Given/When a rule lists output fields
    query = convert("""
  selection:
    CommandLine|contains: 'x'
  condition: selection
fields: [CommandLine, User]
""")

    # Then no columns command is added (the connector names the columns)
    assert "|" not in query


def test_quotes_and_backslashes_are_escaped():
    # Given/When a value holds a quote and a backslash
    query = convert("""
  selection:
    CommandLine|contains: 'a"b\\c'
  condition: selection
""")

    # Then both are escaped in the string literal
    assert r'tgt.process.cmdline contains "a\"b\\c"' in query


def test_a_deferred_expression_is_negated_by_itself():
    # Given a condition converted into a deferred expression
    backend = PowerQueryBackend()
    deferred = MagicMock(spec=DeferredQueryExpression)
    condition = MagicMock(args=[MagicMock()])

    # When it is negated
    with patch.object(backend, "convert_condition", return_value=deferred):
        result = backend.convert_condition_not(condition, MagicMock())

    # Then the deferred expression negates itself
    assert result is deferred.negate.return_value


@pytest.mark.parametrize(
    "value, expected",
    [
        pytest.param('a"b', '"a\\"b"', id="quote"),
        pytest.param("a\\b", '"a\\\\b"', id="backslash"),
    ],
)
def test_quote_string(value, expected):
    # Given/When/Then quotes and backslashes are escaped
    assert quote_string(value) == expected


def test_wildcard_regex():
    # Given/When/Then wildcards become regex wildcards and the rest is escaped
    assert wildcard_regex(SigmaString("a*b?.c")) == r"^a.*b.\.c$"

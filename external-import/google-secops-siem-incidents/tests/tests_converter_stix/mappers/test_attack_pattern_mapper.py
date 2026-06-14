"""Tests — attack pattern mapper.

Covers extraction of MITRE ATT&CK technique IDs from alert outcomes, including
the ``string_seq.string_vals`` path (a ``StringSeq`` model is not itself an
iterable of technique strings).
"""

from connectors_sdk.models import AttackPattern
from google_secops_siem_incidents.mappers.attack_pattern_mapper import (
    map_attack_patterns,
)
from tests_converter_stix.factories import (
    OutcomeFactory,
    StringSeqFactory,
    make_author,
    make_tlp_marking,
)


def _when_map(outcomes):
    return map_attack_patterns(
        outcomes,
        author=make_author(),
        tlp_marking=make_tlp_marking(),
    )


class TestAttackPatternMapper:
    def test_string_seq_techniques_extracted(self):
        """A ``mitre_attack_technique_id`` string_seq yields one AttackPattern per value."""
        outcomes = [
            OutcomeFactory.build(
                name="mitre_attack_technique_id",
                string_seq=StringSeqFactory.build(string_vals=["T1566", "T1059"]),
            )
        ]
        result = _when_map(outcomes)
        assert len(result) == 2
        assert all(isinstance(ap, AttackPattern) for ap in result)
        assert {ap.name for ap in result} == {"T1566", "T1059"}

    def test_string_val_technique_extracted(self):
        """A scalar ``string_val`` technique yields a single AttackPattern."""
        outcomes = [
            OutcomeFactory.build(name="mitre_attack_technique_id", string_val="T1190")
        ]
        result = _when_map(outcomes)
        assert len(result) == 1
        assert result[0].name == "T1190"

    def test_no_attack_pattern_outcome_returns_empty(self):
        """No matching outcome → []."""
        outcomes = [OutcomeFactory.build(name="principal_hostname", string_val="h")]
        assert _when_map(outcomes) == []

    def test_outcome_without_values_returns_empty(self):
        """Outcome present but with neither string_val nor string_seq → []."""
        outcomes = [OutcomeFactory.build(name="mitre_attack_technique_id")]
        assert _when_map(outcomes) == []

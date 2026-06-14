"""Tests — find_all_outcomes utility.

Validates the multi-outcome lookup function that underlies all mapper changes.

BDD helpers: _given_ / _when_ / _then_ pattern (plain pytest, no pytest-bdd).
"""

from google_secops_siem_incidents.mappers._utils import find_all_outcomes
from tests_converter_stix.factories import OutcomeFactory


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _given_outcomes_with_names(*names: str):
    """Build a list of Outcome objects with the given names."""
    return [OutcomeFactory.build(name=n, string_val=f"val-{n}") for n in names]


def _when_find_all(outcomes, name: str):
    return find_all_outcomes(outcomes, name)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------
class TestFindAllOutcomes:
    def test_then_returns_all_matching_when_multiple_share_same_name(self):
        """Given 3 outcomes named 'alpha' → returns all 3."""
        # _given_
        outcomes = _given_outcomes_with_names("alpha", "alpha", "alpha")

        # _when_
        result = _when_find_all(outcomes, "alpha")

        # _then_
        assert len(result) == 3
        assert all(o.name == "alpha" for o in result)

    def test_then_returns_empty_list_when_no_match(self):
        """Given outcomes with different names → returns []."""
        # _given_
        outcomes = _given_outcomes_with_names("beta", "gamma")

        # _when_
        result = _when_find_all(outcomes, "alpha")

        # _then_
        assert result == []

    def test_then_returns_single_item_list_when_one_match(self):
        """Given exactly one matching outcome → returns list with 1 element."""
        # _given_
        outcomes = _given_outcomes_with_names("alpha", "beta", "gamma")

        # _when_
        result = _when_find_all(outcomes, "alpha")

        # _then_
        assert len(result) == 1
        assert result[0].name == "alpha"

    def test_then_does_not_return_outcomes_with_different_names(self):
        """Given mixed names → only matching ones returned, others excluded."""
        # _given_
        outcomes = _given_outcomes_with_names(
            "alpha", "beta", "alpha", "gamma", "alpha"
        )

        # _when_
        result = _when_find_all(outcomes, "alpha")

        # _then_
        assert len(result) == 3
        assert all(o.name == "alpha" for o in result)
        assert not any(o.name in ("beta", "gamma") for o in result)

    def test_then_returns_empty_for_empty_input(self):
        """Given empty outcomes list → returns []."""
        # _given_
        outcomes = []

        # _when_
        result = _when_find_all(outcomes, "alpha")

        # _then_
        assert result == []

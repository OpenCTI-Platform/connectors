"""RED tests — Hostname mapper.

Tests extraction of Hostname observables from Chronicle alert outcomes.

BDD helpers: _given_ / _when_ / _then_ pattern (plain pytest, no pytest-bdd).
"""

# --- import under test (will cause ImportError → RED) ---
from google_secops_siem_incidents.mappers.hostname_mapper import (  # noqa: E402
    map_hostname,
)
from tests_converter_stix.factories import (
    OutcomeFactory,
    make_author,
    make_hostname_outcomes,
    make_multi_hostname_outcomes,
    make_tlp_marking,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _when_map_hostname(outcomes):
    return map_hostname(
        outcomes,
        author=make_author(),
        tlp_marking=make_tlp_marking(),
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------
class TestHostnameMapper:
    def test_then_hostname_extracted_from_principal(self):
        """Given principal.hostname 'webserver.corp.local' → list with Hostname(value=...)."""
        # _given_
        outcomes = make_hostname_outcomes("webserver.corp.local")

        # _when_
        result = _when_map_hostname(outcomes)

        # _then_
        assert len(result) == 1
        assert result[0].value == "webserver.corp.local"

    def test_then_returns_empty_list_when_no_hostname_in_outcomes(self):
        """Given no hostname in event samples → returns empty list."""
        # _given_
        outcomes = []  # no hostname outcome

        # _when_
        result = _when_map_hostname(outcomes)

        # _then_
        assert result == []

    def test_then_no_exception_on_empty_outcomes(self):
        """Trap guard: Given no event samples → returns empty list, no exception."""
        # _given_
        outcomes = []

        # _when_ / _then_ — no exception raised
        result = _when_map_hostname(outcomes)
        assert result == []


class TestHostnameMapperMultiOutcome:
    def test_then_two_hostnames_from_two_outcomes(self):
        """Given 2 principal_hostname outcomes → 2 Hostname objects."""
        # _given_
        outcomes = make_multi_hostname_outcomes(["host1.local", "host2.local"])

        # _when_
        result = _when_map_hostname(outcomes)

        # _then_
        assert len(result) == 2
        values = {h.value for h in result}
        assert values == {"host1.local", "host2.local"}

    def test_then_three_hostnames_from_three_outcomes(self):
        """Given 3 principal_hostname outcomes → 3 Hostname objects."""
        # _given_
        outcomes = make_multi_hostname_outcomes(["a.local", "b.local", "c.local"])

        # _when_
        result = _when_map_hostname(outcomes)

        # _then_
        assert len(result) == 3
        values = {h.value for h in result}
        assert values == {"a.local", "b.local", "c.local"}

    def test_then_only_matching_outcomes_returned(self):
        """Given mix of principal_hostname and other outcomes → only hostnames returned."""
        # _given_
        outcomes = make_multi_hostname_outcomes(["host1.local", "host2.local"]) + [
            OutcomeFactory.build(name="principal_ip", string_val="10.0.0.1"),
        ]

        # _when_
        result = _when_map_hostname(outcomes)

        # _then_
        assert len(result) == 2
        values = {h.value for h in result}
        assert values == {"host1.local", "host2.local"}

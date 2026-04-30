"""RED tests — Hostname mapper.

Tests extraction of a Hostname observable from Chronicle alert outcomes.

BDD helpers: _given_ / _when_ / _then_ pattern (plain pytest, no pytest-bdd).
"""

from tests_converter_stix.factories import (
    make_author,
    make_hostname_outcomes,
    make_tlp_marking,
)

# --- import under test (will cause ImportError → RED) ---
from google_secops_siem_incidents.mappers.hostname_mapper import (  # noqa: E402
    map_hostname,
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
        """Given principal.hostname 'webserver.corp.local' → Hostname(value=...)."""
        # _given_
        outcomes = make_hostname_outcomes("webserver.corp.local")

        # _when_
        result = _when_map_hostname(outcomes)

        # _then_
        assert result is not None
        assert result.value == "webserver.corp.local"

    def test_then_returns_none_when_no_hostname_in_outcomes(self):
        """Given no hostname in event samples → returns None."""
        # _given_
        outcomes = []  # no hostname outcome

        # _when_
        result = _when_map_hostname(outcomes)

        # _then_
        assert result is None

    def test_then_no_exception_on_empty_outcomes(self):
        """Trap guard: Given no event samples → returns None, no exception."""
        # _given_
        outcomes = []

        # _when_ / _then_ — no exception raised
        result = _when_map_hostname(outcomes)
        assert result is None

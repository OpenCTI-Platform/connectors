"""RED tests — Relationship mapper.

Tests creation of 'related-to' Relationship objects linking an incident
to its extracted observables.

BDD helpers: _given_ / _when_ / _then_ pattern (plain pytest, no pytest-bdd).
"""

from uuid import uuid4

from connectors_sdk.models import Hostname, IPV4Address, Relationship, UserAccount
from connectors_sdk.models.enums import RelationshipType
from connectors_sdk.models.reference import Reference

# --- import under test (will cause ImportError → RED) ---
from google_secops_siem_incidents.mappers.relationship_mapper import (  # noqa: E402
    map_relationships,
)
from tests_converter_stix.factories import make_author, make_tlp_marking


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _make_mock_incident():
    """Create a minimal incident stub as a Reference (valid BaseIdentifiedEntity union member)."""
    return Reference(id=f"incident--{uuid4()}")


def _when_map_relationships(incident, observables):
    return map_relationships(
        incident,
        observables,
        author=make_author(),
        tlp_marking=make_tlp_marking(),
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------
class TestRelationshipMapper:
    def test_then_one_relationship_per_observable(self):
        """Given one incident + 3 observables → 3 Relationship objects."""
        # _given_
        incident = _make_mock_incident()
        observables = [
            Hostname(value="host1.local"),
            IPV4Address(value="10.0.0.1"),
            UserAccount(user_id="alice"),
        ]

        # _when_
        result = _when_map_relationships(incident, observables)

        # _then_
        assert len(result) == 3
        assert all(isinstance(r, Relationship) for r in result)

    def test_then_all_relationships_are_related_to(self):
        """Each relationship has type 'related-to'."""
        # _given_
        incident = _make_mock_incident()
        observables = [
            Hostname(value="host1.local"),
            IPV4Address(value="10.0.0.1"),
            UserAccount(user_id="alice"),
        ]

        # _when_
        result = _when_map_relationships(incident, observables)

        # _then_
        for rel in result:
            assert rel.type == RelationshipType.RELATED_TO

    def test_then_source_is_incident_target_is_observable(self):
        """Each relationship: source = incident, target = observable."""
        # _given_
        incident = _make_mock_incident()
        observables = [Hostname(value="host1.local")]

        # _when_
        result = _when_map_relationships(incident, observables)

        # _then_
        assert len(result) == 1
        assert result[0].source == incident
        assert result[0].target == observables[0]

    def test_then_zero_observables_returns_empty(self):
        """Given one incident + 0 observables → returns []."""
        # _given_
        incident = _make_mock_incident()
        observables = []

        # _when_
        result = _when_map_relationships(incident, observables)

        # _then_
        assert result == []

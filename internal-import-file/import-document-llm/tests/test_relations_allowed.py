"""Unit tests for reportimporter.relations_allowed."""

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from reportimporter.relations_allowed import (
    _normalize_threat_actor_lookup,
    is_relation_allowed,
    load_allowed_relations,
    stix_lookup_type,
)


class _FakeAPI:
    def __init__(self, data):
        self._data = data

    def query(self, _query):
        return {"data": {"schemaRelationsTypesMapping": self._data}}


class _FakeHelper:
    def __init__(self, data):
        self.api = _FakeAPI(data)


class TestNormalizeThreatActorLookup:
    def test_group_aliases(self):
        assert _normalize_threat_actor_lookup("group") == "THREAT-ACTOR-GROUP"
        assert (
            _normalize_threat_actor_lookup("threat_actor_group") == "THREAT-ACTOR-GROUP"
        )

    def test_individual_aliases(self):
        assert _normalize_threat_actor_lookup("individual") == "THREAT-ACTOR-INDIVIDUAL"

    def test_threat_actor_prefix(self):
        assert _normalize_threat_actor_lookup("threat-actor-foo") == "THREAT-ACTOR-FOO"

    def test_empty_and_unknown(self):
        assert _normalize_threat_actor_lookup("") == ""
        assert _normalize_threat_actor_lookup(None) == ""
        assert _normalize_threat_actor_lookup("random") == ""


class TestStixLookupType:
    def test_none_and_empty(self):
        assert stix_lookup_type(None) == ""
        assert stix_lookup_type({}) == ""

    def test_plain_type(self):
        assert stix_lookup_type({"type": "malware"}) == "MALWARE"

    def test_identity(self):
        assert (
            stix_lookup_type({"type": "identity", "identity_class": "organization"})
            == "ORGANIZATION"
        )
        assert (
            stix_lookup_type({"type": "identity", "x_opencti_identity_type": "Sector"})
            == "SECTOR"
        )

    def test_location(self):
        assert (
            stix_lookup_type({"type": "location", "x_opencti_location_type": "Country"})
            == "COUNTRY"
        )

    def test_threat_actor_variants(self):
        assert (
            stix_lookup_type(
                {"type": "threat-actor", "x_opencti_threat_actor_type": "group"}
            )
            == "THREAT-ACTOR-GROUP"
        )
        assert (
            stix_lookup_type(
                {"type": "threat-actor", "threat_actor_types": ["individual"]}
            )
            == "THREAT-ACTOR-INDIVIDUAL"
        )
        assert stix_lookup_type({"type": "threat-actor"}) == "THREAT-ACTOR"


class TestRelationMatrix:
    def test_load_allowed_relations(self):
        helper = _FakeHelper(
            [
                {"key": "Malware_Infrastructure", "values": ["uses"]},
                {"key": "nounderscore", "values": []},
            ]
        )
        mapping = load_allowed_relations(helper)
        assert mapping[("MALWARE", "INFRASTRUCTURE")] == {"USES"}
        # The underscore-less "nounderscore" key is skipped, leaving only the valid pair.
        assert len(mapping) == 1

    def test_is_relation_allowed(self):
        mapping = {("MALWARE", "INFRASTRUCTURE"): {"USES"}}
        assert is_relation_allowed(mapping, "malware", "infrastructure", "uses")
        assert not is_relation_allowed(mapping, "malware", "infrastructure", "targets")
        assert not is_relation_allowed(mapping, "malware", "infrastructure", "")

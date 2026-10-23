from __future__ import annotations

import os
from datetime import datetime, timezone
from unittest.mock import patch

import stix2
from models.indicators import URL, Domain
from models.sdo import Identity

# --- Description + valid_from/until ------------------------------------------


class TestSetDescription:
    def test_plain(self):
        d = Domain(name="example.com", c_type="domain-name")
        d.set_description("Phishing host")
        assert d.description == "Phishing host"

    def test_none_keeps_existing(self):
        d = Domain(name="example.com", c_type="domain-name")
        d.description = "kept"
        d.set_description(None)
        assert d.description == "kept"

    def test_empty_string_clears(self):
        d = Domain(name="example.com", c_type="domain-name")
        d.description = "old"
        d.set_description("")
        assert d.description == ""

    def test_strips_html(self):
        d = Domain(name="example.com", c_type="domain-name")
        d.set_description("<b>Phishing</b> host")
        assert d.description == "Phishing host"

    def test_strips_ctrl_chars(self):
        d = Domain(name="example.com", c_type="domain-name")
        d.set_description("clean\x00body")
        assert d.description == "cleanbody"


class TestSetValid:
    def test_set_valid_from(self):
        d = Domain(name="example.com", c_type="domain-name")
        ts = datetime(2024, 1, 1, tzinfo=timezone.utc)
        d.set_valid_from(ts)
        assert d.valid_from == ts

    def test_set_valid_from_none_keeps_existing(self):
        d = Domain(name="example.com", c_type="domain-name")
        ts = datetime(2024, 1, 1, tzinfo=timezone.utc)
        d.valid_from = ts
        d.set_valid_from(None)
        assert d.valid_from == ts

    def test_set_valid_until(self):
        d = Domain(name="example.com", c_type="domain-name")
        ts = datetime(2025, 1, 1, tzinfo=timezone.utc)
        d.set_valid_until(ts)
        assert d.valid_until == ts

    def test_set_valid_until_none_keeps_existing(self):
        d = Domain(name="example.com", c_type="domain-name")
        original = d.valid_until
        d.set_valid_until(None)
        assert d.valid_until == original


# --- get_markings + _labels_kv ----------------------------------------------


class TestGetMarkings:
    def test_default_tlp_only(self):
        d = Domain(name="example.com", c_type="domain-name", tlp_color="amber")
        markings = d.get_markings()
        assert len(markings) == 1

    def test_with_statement_marking(self):
        env_key = "TI_API__EXTRA_SETTINGS__ENABLE_STATEMENT_MARKING"
        with patch.dict(os.environ, {env_key: "true"}):
            d = Domain(name="example.com", c_type="domain-name")
            markings = d.get_markings()
            assert len(markings) == 2

    def test_white_default_when_unknown(self):
        d = Domain(name="example.com", c_type="domain-name", tlp_color="bogus")
        # Unknown TLP falls back to WHITE — verified earlier in
        # test_stix_payload_utils; here we just confirm the markings
        # list still has exactly one entry.
        assert len(d.get_markings()) == 1


class TestLabelsKv:
    def test_returns_labels_list(self):
        d = Domain(
            name="example.com",
            c_type="domain-name",
            labels=["collection:Test", "extra"],
        )
        kv = d._labels_kv()
        assert kv == {"x_opencti_labels": ["collection:Test", "extra"]}

    def test_returns_none_label_when_labels_is_none(self):
        d = Domain(name="example.com", c_type="domain-name", labels=None)
        kv = d._labels_kv()
        assert kv == {"x_opencti_labels": None}

    def test_preserve_manual_labels_omits_key(self):
        env_key = "TI_API__EXTRA_SETTINGS__PRESERVE_MANUAL_LABELS"
        with patch.dict(os.environ, {env_key: "true"}):
            d = Domain(name="example.com", c_type="domain-name", labels=["x"])
            assert d._labels_kv() == {}


# --- _generate_relationship / generate_relationship --------------------------


class TestGenerateRelationship:
    def test_direct_relationship_factory(self):
        d = Domain(name="example.com", c_type="domain-name")
        src = "domain-name--11111111-1111-4111-8111-111111111111"
        tgt = "indicator--22222222-2222-4222-8222-222222222222"
        rel = d._generate_relationship(src, tgt, relation_type="based-on")
        assert isinstance(rel, stix2.Relationship)
        assert rel.relationship_type == "based-on"
        assert rel.source_ref == src
        assert rel.target_ref == tgt

    def test_generate_relationship_appends_to_list(self):
        d = Domain(name="example.com", c_type="domain-name")
        d.generate_stix_objects()
        other = Domain(name="y.com", c_type="domain-name")
        other.generate_stix_objects()
        # Build a real SDO-on-SDO relationship via the public method.
        d.generate_relationship(
            d.stix_main_object, other.stix_main_object, relation_type="related-to"
        )
        assert len(d.stix_relationships) == 1
        assert d.stix_relationships[0].relationship_type == "related-to"

    def test_default_relation_type_is_based_on(self):
        d = Domain(name="example.com", c_type="domain-name")
        d.generate_stix_objects()
        other = Domain(name="y.com", c_type="domain-name")
        other.generate_stix_objects()
        d.generate_relationship(d.stix_main_object, other.stix_main_object)
        assert d.stix_relationships[0].relationship_type == "based-on"


# --- generate_external_references --------------------------------------------


class TestGenerateExternalReferences:
    def test_empty_input_clears(self):
        d = Domain(name="example.com", c_type="domain-name")
        d.external_references = ["pre-existing"]  # type: ignore[list-item]
        out = d.generate_external_references([])
        assert out == []
        assert d.external_references == []

    def test_portal_link_uses_entity_name(self):
        d = Domain(name="MalwareExample", c_type="domain-name")
        refs = d.generate_external_references(
            [
                (
                    "rec-1",
                    "https://tap.group-ib.com/malware/reports/rec-1",
                    "",
                )
            ]
        )
        assert refs[0].source_name == "Group-IB TI portal: MalwareExample"

    def test_list_name_with_strings(self):
        # FileHash uses a list name; the helper should pick the first string.
        fh = type("FakeListName", (Domain,), {})(
            name=["hash1", "hash2"], c_type="domain-name"
        )
        refs = fh.generate_external_references([("rec", "https://example.com", "")])
        assert refs[0].source_name == "Group-IB TI portal: hash1"

    def test_list_name_falls_back_when_no_string(self):
        fh = type("FakeListName", (Domain,), {})(name=[], c_type="domain-name")
        refs = fh.generate_external_references([("rec", "https://example.com", "")])
        assert refs[0].source_name == "Group-IB TI portal"


# --- generate_stix_objects: IOC paths ----------------------------------------


class TestGenerateStixObjects:
    def test_non_ioc_observable(self):
        # Domain non-IOC: observable, no indicator.
        d = Domain(name="example.com", c_type="domain-name")
        out = d.generate_stix_objects()
        assert out is d  # returns self
        assert d.stix_observable is not None
        assert d.stix_indicator is None
        assert d.stix_objects == [d.stix_observable]

    def test_ioc_path_observable_plus_indicator(self):
        from datetime import datetime, timezone

        d = Domain(name="example.com", c_type="domain-name")
        d.is_ioc = True
        # stix2 requires ``valid_until > valid_from``; BaseEntity defaults
        # ``valid_from=None``, so seed an earlier timestamp.
        d.set_valid_from(datetime(2024, 1, 1, tzinfo=timezone.utc))
        d.generate_stix_objects()
        # Indicator-first (single Indicator path) → indicator + observable.
        assert d.stix_indicator is not None
        assert d.stix_observable is not None
        # Order is [indicator, observable] when stix_indicator is NOT a list.
        assert d.stix_objects[0] is d.stix_indicator
        assert d.stix_observable in d.stix_objects

    def test_ioc_path_list_indicator(self):
        # FileHash returns a list of indicators (one per hash).
        from datetime import datetime, timezone

        from models.indicators import FileHash

        fh = FileHash(
            name=[
                "d41d8cd98f00b204e9800998ecf8427e",
                "da39a3ee5e6b4b0d3255bfef95601890afd80709",
            ],
            c_type="file",
        )
        fh.is_ioc = True
        fh.set_valid_from(datetime(2024, 1, 1, tzinfo=timezone.utc))
        fh.generate_stix_objects()
        # When stix_indicator is a list, observable comes FIRST then
        # indicators are appended.
        assert isinstance(fh.stix_indicator, list)
        assert fh.stix_objects[0] is fh.stix_observable
        # Both indicators appended after the observable.
        for ind in fh.stix_indicator:
            assert ind in fh.stix_objects

    def test_sdo_only_path(self):
        # Identity has no observable; only stix_sdo populates.
        ident = Identity(name="ExampleCorp", c_type="identity")
        ident.generate_stix_objects()
        assert ident.stix_observable is None
        assert ident.stix_sdo is ident.stix_main_object
        assert ident.stix_objects == [ident.stix_main_object]


# --- add_relationships_to_stix_objects --------------------------------------


class TestAddRelationshipsToStixObjects:
    def test_appends_when_present(self):
        d = Domain(name="example.com", c_type="domain-name")
        d.generate_stix_objects()
        other = Domain(name="y.com", c_type="domain-name")
        other.generate_stix_objects()
        d.generate_relationship(
            d.stix_main_object, other.stix_main_object, relation_type="related-to"
        )
        before = len(d.stix_objects)
        d.add_relationships_to_stix_objects()
        # Relationship appended.
        assert len(d.stix_objects) == before + 1
        assert d.stix_objects[-1].type == "relationship"

    def test_noop_when_no_relationships(self):
        d = Domain(name="example.com", c_type="domain-name")
        d.generate_stix_objects()
        before = list(d.stix_objects)
        d.add_relationships_to_stix_objects()
        assert d.stix_objects == before


# --- bundle helper -----------------------------------------------------------


class TestBundle:
    def test_returns_stix2_bundle(self):
        d = Domain(name="example.com", c_type="domain-name")
        d.generate_stix_objects()
        bundle = d.bundle()
        assert isinstance(bundle, stix2.Bundle)
        assert len(bundle.objects) == 1
        # Bundle id always has the v4 UUID shape.
        assert bundle.id.startswith("bundle--")


# --- _generate_author + _generate_statement_marking -------------------------


class TestAuthorAndStatementMarking:
    def test_author_is_group_ib_identity(self):
        d = Domain(name="example.com", c_type="domain-name")
        assert d.author.name == "Group-IB"
        assert d.author.identity_class == "organization"
        assert d.author.id.startswith("identity--")

    def test_statement_marking_off_by_default(self):
        d = Domain(name="example.com", c_type="domain-name")
        assert d.statement_marking is None

    def test_statement_marking_constructed_when_enabled(self):
        env_key = "TI_API__EXTRA_SETTINGS__ENABLE_STATEMENT_MARKING"
        with patch.dict(os.environ, {env_key: "true"}):
            d = Domain(name="example.com", c_type="domain-name")
            assert d.statement_marking is not None
            assert d.statement_marking.definition_type == "statement"
            assert d.statement_marking.definition["statement"] == "Group-IB"


# --- URL pattern + escape integration ---------------------------------------


class TestUrlEscapeIntegration:
    def test_backslash_doubled_in_pattern(self):
        from datetime import datetime, timezone

        u = URL(name="https://example.com/with\\slash", c_type="url")
        u.is_ioc = True
        u.set_valid_from(datetime(2024, 1, 1, tzinfo=timezone.utc))
        u.generate_stix_objects()
        # Backslash must be doubled for STIX pattern syntax.
        assert "\\\\" in u.stix_indicator.pattern

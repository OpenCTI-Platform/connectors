from __future__ import annotations

from models.location import KillChainPhase, Location

# --- Location ----------------------------------------------------------------


class TestLocationCountry:
    def test_default_country_type(self):
        loc = Location(name="US", c_type="location", tlp_color="white")
        loc.generate_stix_objects()
        sdo = loc.stix_main_object
        assert sdo.type == "location"
        # Country name resolved via _generate_country_by_cc lookup.
        assert sdo.name == "United States"
        assert sdo.country == "US"

    def test_unknown_country_code_falls_back_to_name(self):
        loc = Location(name="ZZ", c_type="location", tlp_color="white")
        loc.generate_stix_objects()
        # No ISO 3166 match — name passes through as-is.
        assert loc.stix_main_object.name == "ZZ"

    def test_description_propagates(self):
        loc = Location(name="US", c_type="location", tlp_color="white")
        loc.set_description("Custom location text.")
        loc.generate_stix_objects()
        assert loc.stix_main_object.description == "Custom location text."

    def test_stix_objects_contains_only_common(self):
        loc = Location(name="US", c_type="location")
        loc.generate_stix_objects()
        # ``Location`` is a Common SDO — no separate observable or SDO record.
        assert loc.stix_observable is None
        assert loc.stix_sdo is None
        assert loc.stix_common is loc.stix_main_object
        assert loc.stix_objects == [loc.stix_main_object]

    def test_aliases_carry_original_name(self):
        loc = Location(name="DE", c_type="location")
        loc.generate_stix_objects()
        # Custom property keeps the original alpha-2 code as an alias
        # (analysts can grep by the raw upstream value).
        assert loc.stix_main_object["x_opencti_aliases"] == "DE"

    def test_labels_attached_to_custom_properties(self):
        loc = Location(
            name="US",
            c_type="location",
            labels=["collection:Test", "extra"],
        )
        loc.generate_stix_objects()
        assert loc.stix_main_object["x_opencti_labels"] == [
            "collection:Test",
            "extra",
        ]


class TestLocationRegion:
    def test_region_type_uses_region_field(self):
        loc = Location(
            name="European Union",
            c_type="location",
            location_type="Region",
        )
        loc.generate_stix_objects()
        sdo = loc.stix_main_object
        assert sdo.name == "European Union"
        # Region slug: lowercased, spaces -> hyphens.
        assert sdo.region == "european-union"
        assert sdo["x_opencti_location_type"] == "Region"

    def test_region_value_override(self):
        loc = Location(
            name="EMEA",
            c_type="location",
            location_type="Region",
            region_value="europe:european_union",
        )
        loc.generate_stix_objects()
        sdo = loc.stix_main_object
        # The display name stays "EMEA" but the slug uses the override.
        assert sdo.name == "EMEA"
        assert sdo.region == "europe:european_union"

    def test_region_no_country_field(self):
        loc = Location(
            name="Africa",
            c_type="location",
            location_type="Region",
        )
        loc.generate_stix_objects()
        # Region SDOs intentionally don't carry a country property.
        assert "country" not in loc.stix_main_object


# --- KillChainPhase ----------------------------------------------------------


class TestKillChainPhase:
    def test_emits_kill_chain_phase_sdo(self):
        kcp = KillChainPhase(name="mitre-attack", c_type="reconnaissance")
        kcp.generate_stix_objects()
        sdo = kcp.stix_main_object
        # ``stix2.KillChainPhase`` is a sub-object — no ``type`` field;
        # check the kill-chain identification fields directly.
        assert sdo.kill_chain_name == "mitre-attack"
        assert sdo.phase_name == "reconnaissance"

    def test_kill_chain_phase_with_labels(self):
        kcp = KillChainPhase(
            name="lockheed-martin-cyber-kill-chain",
            c_type="exploitation",
            labels=["mitre"],
        )
        kcp.generate_stix_objects()
        assert kcp.stix_main_object["x_opencti_labels"] == ["mitre"]

    def test_stix_objects_only_common(self):
        kcp = KillChainPhase(name="x", c_type="y")
        kcp.generate_stix_objects()
        assert kcp.stix_objects == [kcp.stix_main_object]

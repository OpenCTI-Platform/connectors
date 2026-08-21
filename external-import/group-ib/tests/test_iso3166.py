from __future__ import annotations

from _data.iso3166 import COUNTRIES


class TestCountriesTable:
    def test_table_is_non_empty(self):
        assert len(COUNTRIES) > 200  # ~249 codes in ISO 3166-1.

    def test_keys_are_two_letter_uppercase(self):
        for code in COUNTRIES.keys():
            assert isinstance(code, str)
            assert len(code) == 2
            assert code.isalpha()
            assert code == code.upper()

    def test_values_are_non_empty_strings(self):
        for code, name in COUNTRIES.items():
            assert isinstance(name, str), code
            assert name.strip() == name, code  # No leading/trailing whitespace.
            assert len(name) > 0, code

    def test_no_duplicate_codes(self):
        keys = list(COUNTRIES.keys())
        assert len(keys) == len(set(keys))

    def test_sample_well_known_codes(self):
        # Spot-check a handful of high-traffic codes that the adapters
        # bump into often (G20-ish + the obvious nation-state APT targets).
        for code in ("US", "GB", "DE", "FR", "CN", "RU", "JP", "IN", "BR"):
            assert code in COUNTRIES, f"missing well-known code: {code}"

    def test_lookup_returns_country_name(self):
        # Direct dict access is the only API surface; verify the canonical
        # title-case form expected by the adapters' country emitters.
        assert COUNTRIES["US"] == "United States"
        assert COUNTRIES["GB"] == "United Kingdom"

    def test_no_self_referencing_code_as_name(self):
        # Cheap guard against a copy-paste bug where the name accidentally
        # equals the two-letter code.
        for code, name in COUNTRIES.items():
            assert name != code

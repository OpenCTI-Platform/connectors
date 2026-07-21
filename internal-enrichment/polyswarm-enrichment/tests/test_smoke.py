"""Smoke tests for the PolySwarm Enrichment connector.

Verifies: all modules import, core classes instantiate, config loads,
and ConverterToStix produces valid output structure.
"""

from conftest import StubHelper

# ── 1. All modules import without error ───────────────────────────────────────


class TestModuleImports:
    def test_import_converter_to_stix(self):
        import polyswarm_enrichment.converter_to_stix  # noqa: F401

    def test_import_client_api(self):
        import polyswarm_enrichment.client_api  # noqa: F401

    def test_import_connector(self):
        import polyswarm_enrichment.connector  # noqa: F401

    def test_import_attack_pattern_handler(self):
        import polyswarm_enrichment.attack_pattern_handler  # noqa: F401

    def test_import_settings(self):
        import polyswarm_enrichment.settings  # noqa: F401

    def test_import_polyswarm_client(self):
        import polyswarm_enrichment.polyswarm_client  # noqa: F401


# ── 2. Core classes instantiate with mocked helper ────────────────────────────


class TestClassInstantiation:
    def test_converter_to_stix_instantiation(self):
        from polyswarm_enrichment.converter_to_stix import ConverterToStix

        helper = StubHelper()
        converter = ConverterToStix(helper)
        assert converter.helper is helper
        assert converter.author is not None
        assert converter.author["type"] == "identity"

    def test_converter_clear_cache(self):
        from polyswarm_enrichment.converter_to_stix import ConverterToStix

        helper = StubHelper()
        converter = ConverterToStix(helper)
        converter._malware_cache["test"] = {"id": "test"}
        converter.clear_cache()
        assert len(converter._malware_cache) == 0

    def test_attack_pattern_handler_instantiation(self):
        from polyswarm_enrichment.attack_pattern_handler import AttackPatternHandler

        helper = StubHelper()
        handler = AttackPatternHandler(helper, "identity--test-author")
        assert handler.helper is helper


# ── 3. Config classes load with minimal env vars ──────────────────────────────


class TestConfigLoading:
    def test_internal_enrichment_config_defaults(self):
        from polyswarm_enrichment.settings import InternalEnrichmentConnectorConfig

        cfg = InternalEnrichmentConnectorConfig(id="test-connector-id")
        assert cfg.name == "PolySwarm Hash Enrichment"
        assert "StixFile" in cfg.scope
        assert "Artifact" in cfg.scope

    def test_polyswarm_config_defaults(self):
        from polyswarm_enrichment.settings import PolySwarmConfig

        # PolySwarmConfig needs api_key — provide a dummy
        cfg = PolySwarmConfig(api_key="test-key")
        assert cfg.community == "default"
        assert cfg.ioc_enabled is True
        assert cfg.max_polling_time == 120


# ── 4. ConverterToStix produces valid output structure ────────────────────────


class TestConverterOutput:
    def test_create_author(self):
        from polyswarm_enrichment.converter_to_stix import ConverterToStix

        helper = StubHelper()
        converter = ConverterToStix(helper)
        author = converter.create_author()
        assert author["type"] == "identity"
        assert "PolySwarm" in author["name"]
        assert author["identity_class"] == "organization"

    def test_create_indicator(self):
        from polyswarm_enrichment.converter_to_stix import ConverterToStix

        helper = StubHelper()
        converter = ConverterToStix(helper)
        sha = "a" * 64
        obs = {"id": "file--test", "hashes": {"SHA-256": sha}}
        data = {
            "x_opencti_score": 80,
            "x_opencti_labels": ["malware_type:trojan"],
            "x_opencti_description": "Test file",
            "first_seen": "2024-01-01T00:00:00Z",
            "permalink": "https://example.com",
            "polyswarm_id": "test-123",
            "confidence": 100,
        }
        indicator = converter.create_indicator_from_polyswarm(obs, data)
        assert indicator is not None
        assert indicator["type"] == "indicator"
        assert "SHA256" in indicator["pattern"]
        assert indicator["x_opencti_score"] == 80

    def test_create_relationship(self):
        from polyswarm_enrichment.converter_to_stix import ConverterToStix

        helper = StubHelper()
        converter = ConverterToStix(helper)
        rel = converter.create_relationship(
            source_id="indicator--12345678-1234-4234-8234-123456789abc",
            relationship_type="indicates",
            target_id="malware--87654321-4321-4321-8321-cba987654321",
            description="test relationship",
        )
        assert rel is not None
        assert rel["type"] == "relationship"
        assert rel["relationship_type"] == "indicates"

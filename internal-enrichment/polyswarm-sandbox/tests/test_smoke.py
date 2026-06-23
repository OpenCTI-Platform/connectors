"""Smoke tests for the PolySwarm Sandbox connector.

Verifies: all modules import, core classes instantiate, config loads,
and StixBuilder produces valid output structure.
"""

from unittest.mock import patch


class StubHelper:
    """Minimal stand-in for OpenCTIConnectorHelper."""

    connect_scope = "Artifact"
    connect_log_level = "info"
    config = {}
    connector_logger = type(
        "_L",
        (),
        {
            "info": lambda s, *a, **k: None,
            "warning": lambda s, *a, **k: None,
            "error": lambda s, *a, **k: None,
            "debug": lambda s, *a, **k: None,
        },
    )()

    class _API:
        class _Observable:
            def add_file(self, **kwargs):
                pass

            def update_field(self, **kwargs):
                pass

        stix_cyber_observable = _Observable()

    api = _API()

    def log_info(self, msg):
        pass

    def log_warning(self, msg):
        pass

    def log_error(self, msg):
        pass

    def log_debug(self, msg):
        pass

    def stix2_create_bundle(self, objects):
        return {"type": "bundle", "spec_version": "2.1", "objects": objects}

    def send_stix2_bundle(self, bundle, **kwargs):
        return ["bundle-1"]

    @staticmethod
    def check_max_tlp(markings, max_tlp):
        return True


# ── 1. All modules import without error ───────────────────────────────────────


class TestModuleImports:
    def test_import_stix_builder(self):
        import connector.stix_builder  # noqa: F401

    def test_import_polyswarm_client(self):
        import connector.polyswarm_client  # noqa: F401

    def test_import_sandbox_processor(self):
        import connector.sandbox_processor  # noqa: F401

    def test_import_scan_processor(self):
        import connector.scan_processor  # noqa: F401

    def test_import_artifact_handler(self):
        import connector.artifact_handler  # noqa: F401

    def test_import_polyswarm(self):
        import connector.polyswarm  # noqa: F401

    def test_import_ttp_mapping(self):
        import connector.ttp_mapping  # noqa: F401


# ── 2. Core classes instantiate with mocked helper ────────────────────────────


class TestClassInstantiation:
    def test_stix_builder_instantiation(self):
        from connector.stix_builder import StixBuilder

        helper = StubHelper()
        builder = StixBuilder(helper)
        assert builder.helper is helper
        assert builder.author is not None
        assert builder.author["type"] == "identity"

    def test_sandbox_processor_instantiation(self):
        from connector.sandbox_processor import SandboxProcessor

        proc = SandboxProcessor()
        assert hasattr(proc, "_safe_num")

    def test_scan_processor_instantiation(self):
        from connector.scan_processor import ScanProcessor

        proc = ScanProcessor()
        assert proc is not None


# ── 3. StixBuilder produces valid output structure ────────────────────────────


class TestStixBuilderOutput:
    @patch(
        "connector.stix_builder.StixBuilder._fetch_polykg_profile", return_value=None
    )
    def test_build_bundle_returns_list(self, _mock):
        from connector.stix_builder import StixBuilder

        helper = StubHelper()
        builder = StixBuilder(helper)
        entity = {
            "id": "file--test",
            "entity_type": "StixFile",
            "hashes": {"SHA-256": "a" * 64},
            "standard_id": "file--test",
        }
        scan_data = {
            "score": 70,
            "family": "TestMal",
            "sha256": "a" * 64,
            "permalink": "https://polyswarm.network/scan/results/file/" + "a" * 64,
            "labels": ["Trojan"],
            "operating_systems": ["Windows"],
            "first_seen": "2024-01-01T00:00:00Z",
            "last_seen": "2024-06-01T00:00:00Z",
            "detections": {"malicious": 30, "total": 60},
            "polyscore": 0.7,
        }
        result = builder.build_bundle(entity=entity, scan_data=scan_data, config={})
        assert isinstance(result, list)
        assert len(result) > 0
        # All objects should be dicts with a "type" key
        for obj in result:
            assert isinstance(obj, dict)
            assert "type" in obj

    @patch(
        "connector.stix_builder.StixBuilder._fetch_polykg_profile", return_value=None
    )
    def test_bundle_contains_author(self, _mock):
        from connector.stix_builder import StixBuilder

        helper = StubHelper()
        builder = StixBuilder(helper)
        entity = {
            "id": "file--test",
            "entity_type": "StixFile",
            "hashes": {"SHA-256": "a" * 64},
            "standard_id": "file--test",
        }
        result = builder.build_bundle(
            entity=entity, scan_data={"score": 50, "sha256": "a" * 64}, config={}
        )
        identities = [o for o in result if o.get("type") == "identity"]
        assert len(identities) >= 1
        assert any("PolySwarm" in i.get("name", "") for i in identities)

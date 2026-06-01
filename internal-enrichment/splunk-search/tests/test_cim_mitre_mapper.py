from pathlib import Path

from internal_enrichment_connector.cim_mitre_mapper import CIMToMITREMapper


def _mapping_path() -> Path:
    return (
        Path(__file__).parents[1]
        / "src"
        / "internal_enrichment_connector"
        / "data"
        / "cim_to_mitre.yaml"
    )


class TestCIMToMITREMapper:
    def test_load_mapping_file(self):
        """Mapping file loads successfully."""
        mapper = CIMToMITREMapper(mapping_path=_mapping_path())
        assert mapper.is_available is True

    def test_resolve_single_model(self):
        """Single CIM model resolves to correct MITRE Data Sources."""
        mapper = CIMToMITREMapper(mapping_path=_mapping_path())
        entry = {"datamodels": ["Network_Traffic"]}
        assert mapper.resolve(entry) == ["Network Traffic"]

    def test_resolve_multiple_models(self):
        """Multiple CIM models resolve and deduplicate."""
        mapper = CIMToMITREMapper(mapping_path=_mapping_path())
        entry = {"datamodels": ["Network_Traffic", "Intrusion_Detection"]}
        assert mapper.resolve(entry) == ["Network Traffic"]

    def test_explicit_override(self):
        """mitre_data_sources in entry takes precedence over datamodels."""
        mapper = CIMToMITREMapper(mapping_path=_mapping_path())
        entry = {
            "mitre_data_sources": ["File", "Process"],
            "datamodels": ["Network_Traffic"],
        }
        assert mapper.resolve(entry) == ["File", "Process"]

    def test_no_datamodels_no_override(self):
        """Entry with neither field returns empty list."""
        mapper = CIMToMITREMapper(mapping_path=_mapping_path())
        assert mapper.resolve({}) == []

    def test_unknown_cim_model(self):
        """Unknown CIM model is silently skipped."""
        mapper = CIMToMITREMapper(mapping_path=_mapping_path())
        entry = {"datamodels": ["DoesNotExist"]}
        assert mapper.resolve(entry) == []

    def test_performance_model_empty(self):
        """Performance CIM model resolves to empty list."""
        mapper = CIMToMITREMapper(mapping_path=_mapping_path())
        entry = {"datamodels": ["Performance"]}
        assert mapper.resolve(entry) == []

    def test_is_available_when_loaded(self):
        """is_available is True after successful load."""
        mapper = CIMToMITREMapper(mapping_path=_mapping_path())
        assert mapper.is_available is True

    def test_graceful_degradation(self, tmp_path):
        """Missing mapping file sets is_available=False, resolve returns empty."""
        mapper = CIMToMITREMapper(mapping_path=tmp_path / "missing.yaml")
        assert mapper.is_available is False
        assert mapper.resolve({"datamodels": ["Network_Traffic"]}) == []

    def test_unmapped_models_property(self):
        """unmapped_models returns models with no MITRE mapping."""
        mapper = CIMToMITREMapper(mapping_path=_mapping_path())
        mapper.resolve({"datamodels": ["UnknownA", "UnknownB", "Network_Traffic"]})
        assert mapper.unmapped_models == ["UnknownA", "UnknownB"]

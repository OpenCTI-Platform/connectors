"""The processor's contract and its conversion of HoneyLabs TAXII objects."""

from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest
from connectors_sdk import BaseDataProcessor

from connector.data_processors.indicators_processor import IndicatorsProcessor
from connector.state import ConnectorState
from honeylabs_client.models import TaxiiIndicator

RAW = {
    "type": "indicator",
    "spec_version": "2.1",
    "id": "indicator--0d0c6a3e-9d2e-5e3b-9a3e-2b3f1c2d3e4f",
    "created": "2026-09-05T14:26:50.000Z",
    "modified": "2026-09-24T04:57:26.000Z",
    "name": "CVE probing source: 192.0.2.10",
    "description": "Probed the exploit path of 2 CVEs against HoneyLabs honeypot sensors.",
    "indicator_types": ["malicious-activity"],
    "pattern": "[ipv4-addr:value = '192.0.2.10']",
    "pattern_type": "stix",
    "valid_from": "2026-09-05T14:26:50.000Z",
    "valid_until": "2026-10-01T04:57:26.000Z",
    "confidence": 60,
    "labels": ["honeylabs", "cve-probing", "cve-2024-4577"],
    "kill_chain_phases": [
        {
            "kill_chain_name": "lockheed-martin-cyber-kill-chain",
            "phase_name": "reconnaissance",
        }
    ],
    "external_references": [
        {"source_name": "HoneyLabs", "url": "https://honeylabs.net/lookup/192.0.2.10"}
    ],
}


def _processor(connector_settings, fake_logger, pages):
    class DummyClient:
        def iter_objects(self, collection, added_after, limit):
            yield from pages

    class Dummy(IndicatorsProcessor):
        def inject_dependencies(self):
            self.settings = connector_settings
            self.state = ConnectorState()
            self.work_manager = MagicMock()
            self.logger = fake_logger

        def post_init(self):
            super().post_init()
            self.client = DummyClient()

    p = Dummy("attackers")
    p.inject_dependencies()
    p.post_init()
    return p


def test_is_a_base_data_processor_and_rejects_unknown_collections():
    assert issubclass(IndicatorsProcessor, BaseDataProcessor)
    IndicatorsProcessor("exploiters")
    with pytest.raises(ValueError):
        IndicatorsProcessor("something-else")


def test_full_pipeline_runs_and_checkpoints(connector_settings, fake_logger):
    p = _processor(
        connector_settings, fake_logger, [[TaxiiIndicator.model_validate(RAW)]]
    )
    p.process()
    assert p.state.attackers_added_after == datetime(
        2026, 9, 24, 4, 57, 26, tzinfo=timezone.utc
    )
    assert (
        p.work_manager.method_calls
    ), "the processor must hand a bundle to the work manager"


def test_conversion_keeps_the_evidence(connector_settings, fake_logger):
    p = _processor(connector_settings, fake_logger, [])
    ind = p._convert(TaxiiIndicator.model_validate(RAW))
    assert ind.main_observable_type == "IPv4-Addr"
    assert ind.score == 60 and "cve-2024-4577" in ind.labels
    assert ind.external_references[0].url == "https://honeylabs.net/lookup/192.0.2.10"
    assert ind.kill_chain_phases[0].phase_name == "reconnaissance"
    assert ind.create_observables is True
    stix = ind.to_stix2_object()
    assert stix.pattern == RAW["pattern"]


def test_url_pattern_maps_to_url_observable(connector_settings, fake_logger):
    p = _processor(connector_settings, fake_logger, [])
    raw = dict(
        RAW,
        pattern="[url:value = 'http://198.51.100.7:8080/bins/x.sh']",
        name="Malware hosting URL",
    )
    assert p._convert(TaxiiIndicator.model_validate(raw)).main_observable_type == "Url"

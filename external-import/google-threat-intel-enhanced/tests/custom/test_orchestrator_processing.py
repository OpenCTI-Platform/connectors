"""Module to test Orchestrator's fetch/convert/batch orchestration methods.

These tests replace client_api, converter and batch_processor with mocks so the
orchestration branches (conversion failures, flush thresholds, per-item error
handling, IOC enrichment gating) can be exercised deterministically without
needing real GTI API response fixtures.
"""

import logging
from types import SimpleNamespace
from typing import Any, AsyncGenerator, List, Optional
from unittest.mock import AsyncMock, MagicMock

import pytest
from connector.src.custom.orchestrators.orchestrator import Orchestrator

# =====================
# Test Fakes
# =====================


class DummyConfig:
    """Dummy configuration for testing purposes."""

    def __init__(self, **overrides: Any) -> None:
        """Initialize the DummyConfig object with sensible defaults."""
        self.api_key = "fake-key"
        self.import_start_date = "P1D"
        self.api_url = "https://fake-gti.api"
        self.import_reports = False
        self.import_campaigns = False
        self.import_threat_actors = False
        self.import_malware_families = False
        self.import_vulnerabilities = False
        self.report_types = ["All"]
        self.origins = ["All"]
        self.tlp_level = "amber+strict"
        self.enrich_iocs_with_threat_actors_and_malware = False
        self.ioc_enrichment_threshold = 250
        for key, value in overrides.items():
            setattr(self, key, value)


class FakeWorkManager:
    """Minimal fake WorkManager, unused directly by these mocked-batch tests."""


async def _async_gen(pages: List[Any]) -> AsyncGenerator[Any, None]:
    """Build an async generator yielding the given pages."""
    for page in pages:
        yield page


def _entity(id: Optional[str] = None, name: Optional[str] = None) -> Any:
    """Build a fake GTI entity exposing id and attributes.name."""
    ns = SimpleNamespace(id=id)
    ns.attributes = SimpleNamespace(name=name)
    return ns


# =====================
# Fixtures
# =====================


@pytest.fixture
def orchestrator() -> Orchestrator:
    """Fixture for an Orchestrator with mocked client_api/converter/batch_processor."""
    logger = logging.getLogger("test_orchestrator_processing")
    orch = Orchestrator(
        work_manager=FakeWorkManager(),  # type: ignore
        logger=logger,
        config=DummyConfig(),  # type: ignore
        tlp_level="amber+strict",
    )
    orch.client_api = MagicMock()
    orch.client_api.real_total_reports = 0
    orch.converter = MagicMock()
    orch.converter.organization.id = "identity--fixture-org"
    orch.converter.tlp_marking.id = "marking-definition--fixture-tlp"
    orch.batch_processor = MagicMock()
    orch.batch_processor.get_current_batch_size.return_value = 0
    orch.batch_processor.config.batch_size = 500
    orch.batch_processor.config.work_name_template = "Importing (~ 0/0 reports)"
    return orch


# =====================
# Test Cases: _process_campaigns
# =====================


@pytest.mark.asyncio
async def test_process_campaigns_success(orchestrator: Orchestrator) -> None:
    """Test that campaigns are converted, enriched with relationships, and batched."""
    campaign = _entity(id="campaign-1", name="Op Fixture")
    orchestrator.client_api.fetch_campaigns = MagicMock(
        return_value=_async_gen([[campaign]])
    )
    orchestrator.client_api.fetch_campaign_subentities = AsyncMock(
        return_value={"threat_actors": ["ta-1"]}
    )
    orchestrator.client_api.fetch_campaign_subentity_details = AsyncMock(
        return_value={"threat_actors": [_entity(id="ta-1", name="APT1")]}
    )
    orchestrator.converter.convert_campaign_to_stix.return_value = [
        SimpleNamespace(type="campaign", id="campaign--1")
    ]
    orchestrator.converter.convert_campaign_subentities_to_stix.return_value = []

    await orchestrator._process_campaigns(initial_state=None)

    orchestrator.batch_processor.add_items.assert_called_once()
    orchestrator.batch_processor.flush.assert_not_called()


@pytest.mark.asyncio
async def test_process_campaigns_conversion_failure_is_skipped(
    orchestrator: Orchestrator,
) -> None:
    """Test that a campaign failing to convert to STIX is skipped without crashing."""
    campaign = _entity(id="campaign-1", name="Op Fixture")
    orchestrator.client_api.fetch_campaigns = MagicMock(
        return_value=_async_gen([[campaign]])
    )
    orchestrator.converter.convert_campaign_to_stix.return_value = []

    await orchestrator._process_campaigns(initial_state=None)

    orchestrator.client_api.fetch_campaign_subentities.assert_not_called()
    orchestrator.batch_processor.add_items.assert_not_called()


@pytest.mark.asyncio
async def test_process_campaigns_flushes_before_threshold(
    orchestrator: Orchestrator,
) -> None:
    """Test that the batch processor is flushed before adding when near the batch size limit."""
    campaign = _entity(id="campaign-1", name="Op Fixture")
    orchestrator.client_api.fetch_campaigns = MagicMock(
        return_value=_async_gen([[campaign]])
    )
    orchestrator.client_api.fetch_campaign_subentities = AsyncMock(return_value={})
    orchestrator.client_api.fetch_campaign_subentity_details = AsyncMock(
        return_value={}
    )
    orchestrator.converter.convert_campaign_to_stix.return_value = [
        SimpleNamespace(type="campaign", id="campaign--1")
    ]
    orchestrator.converter.convert_campaign_subentities_to_stix.return_value = []
    orchestrator.batch_processor.get_current_batch_size.return_value = 499

    await orchestrator._process_campaigns(initial_state=None)

    orchestrator.batch_processor.flush.assert_called_once()


@pytest.mark.asyncio
async def test_process_campaigns_error_is_logged_and_loop_continues(
    orchestrator: Orchestrator,
) -> None:
    """Test that an error processing one campaign does not stop the remaining ones."""
    campaigns = [_entity(id="campaign-1", name="A"), _entity(id="campaign-2", name="B")]
    orchestrator.client_api.fetch_campaigns = MagicMock(
        return_value=_async_gen([campaigns])
    )
    orchestrator.converter.convert_campaign_to_stix.side_effect = [
        RuntimeError("boom"),
        [SimpleNamespace(type="campaign", id="campaign--2")],
    ]
    orchestrator.client_api.fetch_campaign_subentities = AsyncMock(return_value={})
    orchestrator.client_api.fetch_campaign_subentity_details = AsyncMock(
        return_value={}
    )
    orchestrator.converter.convert_campaign_subentities_to_stix.return_value = []

    await orchestrator._process_campaigns(initial_state=None)

    orchestrator.batch_processor.add_items.assert_called_once()


# =====================
# Test Cases: _process_threat_actors
# =====================


@pytest.mark.asyncio
async def test_process_threat_actors_success(orchestrator: Orchestrator) -> None:
    """Test that standalone threat actors are converted and batched."""
    ta = _entity(id="ta-1", name="APT1")
    orchestrator.client_api.fetch_threat_actors = MagicMock(
        return_value=_async_gen([[ta]])
    )
    orchestrator.converter.convert_threat_actor_to_stix.return_value = [
        SimpleNamespace(type="intrusion-set", id="intrusion-set--1")
    ]

    await orchestrator._process_threat_actors(initial_state=None)

    orchestrator.batch_processor.add_items.assert_called_once()


@pytest.mark.asyncio
async def test_process_threat_actors_conversion_failure_is_skipped(
    orchestrator: Orchestrator,
) -> None:
    """Test that a threat actor failing to convert is skipped without crashing."""
    ta = _entity(id="ta-1", name="APT1")
    orchestrator.client_api.fetch_threat_actors = MagicMock(
        return_value=_async_gen([[ta]])
    )
    orchestrator.converter.convert_threat_actor_to_stix.return_value = []

    await orchestrator._process_threat_actors(initial_state=None)

    orchestrator.batch_processor.add_items.assert_not_called()


@pytest.mark.asyncio
async def test_process_threat_actors_flushes_before_threshold(
    orchestrator: Orchestrator,
) -> None:
    """Test that the batch processor is flushed before adding when near the batch size limit."""
    ta = _entity(id="ta-1", name="APT1")
    orchestrator.client_api.fetch_threat_actors = MagicMock(
        return_value=_async_gen([[ta]])
    )
    orchestrator.converter.convert_threat_actor_to_stix.return_value = [
        SimpleNamespace(type="intrusion-set", id="intrusion-set--1")
    ]
    orchestrator.batch_processor.get_current_batch_size.return_value = 499

    await orchestrator._process_threat_actors(initial_state=None)

    orchestrator.batch_processor.flush.assert_called_once()


@pytest.mark.asyncio
async def test_process_threat_actors_error_is_logged_and_loop_continues(
    orchestrator: Orchestrator,
) -> None:
    """Test that an error processing one threat actor does not stop the remaining ones."""
    tas = [_entity(id="ta-1", name="A"), _entity(id="ta-2", name="B")]
    orchestrator.client_api.fetch_threat_actors = MagicMock(
        return_value=_async_gen([tas])
    )
    orchestrator.converter.convert_threat_actor_to_stix.side_effect = [
        RuntimeError("boom"),
        [SimpleNamespace(type="intrusion-set", id="intrusion-set--2")],
    ]

    await orchestrator._process_threat_actors(initial_state=None)

    orchestrator.batch_processor.add_items.assert_called_once()


# =====================
# Test Cases: _process_malware_families
# =====================


@pytest.mark.asyncio
async def test_process_malware_families_success(orchestrator: Orchestrator) -> None:
    """Test that standalone malware families are converted and batched."""
    malware = _entity(id="mw-1", name="Emotet")
    orchestrator.client_api.fetch_malware_families = MagicMock(
        return_value=_async_gen([[malware]])
    )
    orchestrator.converter.convert_malware_to_stix.return_value = [
        SimpleNamespace(type="malware", id="malware--1")
    ]

    await orchestrator._process_malware_families(initial_state=None)

    orchestrator.batch_processor.add_items.assert_called_once()


@pytest.mark.asyncio
async def test_process_malware_families_conversion_failure_is_skipped(
    orchestrator: Orchestrator,
) -> None:
    """Test that a malware family failing to convert is skipped without crashing."""
    malware = _entity(id="mw-1", name="Emotet")
    orchestrator.client_api.fetch_malware_families = MagicMock(
        return_value=_async_gen([[malware]])
    )
    orchestrator.converter.convert_malware_to_stix.return_value = []

    await orchestrator._process_malware_families(initial_state=None)

    orchestrator.batch_processor.add_items.assert_not_called()


@pytest.mark.asyncio
async def test_process_malware_families_flushes_before_threshold(
    orchestrator: Orchestrator,
) -> None:
    """Test that the batch processor is flushed before adding when near the batch size limit."""
    malware = _entity(id="mw-1", name="Emotet")
    orchestrator.client_api.fetch_malware_families = MagicMock(
        return_value=_async_gen([[malware]])
    )
    orchestrator.converter.convert_malware_to_stix.return_value = [
        SimpleNamespace(type="malware", id="malware--1")
    ]
    orchestrator.batch_processor.get_current_batch_size.return_value = 499

    await orchestrator._process_malware_families(initial_state=None)

    orchestrator.batch_processor.flush.assert_called_once()


@pytest.mark.asyncio
async def test_process_malware_families_error_is_logged_and_loop_continues(
    orchestrator: Orchestrator,
) -> None:
    """Test that an error processing one malware family does not stop the remaining ones."""
    malware_items = [_entity(id="mw-1", name="A"), _entity(id="mw-2", name="B")]
    orchestrator.client_api.fetch_malware_families = MagicMock(
        return_value=_async_gen([malware_items])
    )
    orchestrator.converter.convert_malware_to_stix.side_effect = [
        RuntimeError("boom"),
        [SimpleNamespace(type="malware", id="malware--2")],
    ]

    await orchestrator._process_malware_families(initial_state=None)

    orchestrator.batch_processor.add_items.assert_called_once()


# =====================
# Test Cases: _process_vulnerabilities
# =====================


@pytest.mark.asyncio
async def test_process_vulnerabilities_success(orchestrator: Orchestrator) -> None:
    """Test that standalone vulnerabilities are converted and batched."""
    vuln = _entity(id="vuln-1", name="CVE-2024-0001")
    orchestrator.client_api.fetch_vulnerabilities = MagicMock(
        return_value=_async_gen([[vuln]])
    )
    orchestrator.converter.convert_vulnerability_to_stix.return_value = [
        SimpleNamespace(type="vulnerability", id="vulnerability--1")
    ]

    await orchestrator._process_vulnerabilities(initial_state=None)

    orchestrator.batch_processor.add_items.assert_called_once()


@pytest.mark.asyncio
async def test_process_vulnerabilities_conversion_failure_is_skipped(
    orchestrator: Orchestrator,
) -> None:
    """Test that a vulnerability failing to convert is skipped without crashing."""
    vuln = _entity(id="vuln-1", name="CVE-2024-0001")
    orchestrator.client_api.fetch_vulnerabilities = MagicMock(
        return_value=_async_gen([[vuln]])
    )
    orchestrator.converter.convert_vulnerability_to_stix.return_value = []

    await orchestrator._process_vulnerabilities(initial_state=None)

    orchestrator.batch_processor.add_items.assert_not_called()


@pytest.mark.asyncio
async def test_process_vulnerabilities_flushes_before_threshold(
    orchestrator: Orchestrator,
) -> None:
    """Test that the batch processor is flushed before adding when near the batch size limit."""
    vuln = _entity(id="vuln-1", name="CVE-2024-0001")
    orchestrator.client_api.fetch_vulnerabilities = MagicMock(
        return_value=_async_gen([[vuln]])
    )
    orchestrator.converter.convert_vulnerability_to_stix.return_value = [
        SimpleNamespace(type="vulnerability", id="vulnerability--1")
    ]
    orchestrator.batch_processor.get_current_batch_size.return_value = 499

    await orchestrator._process_vulnerabilities(initial_state=None)

    orchestrator.batch_processor.flush.assert_called_once()


@pytest.mark.asyncio
async def test_process_vulnerabilities_error_is_logged_and_loop_continues(
    orchestrator: Orchestrator,
) -> None:
    """Test that an error processing one vulnerability does not stop the remaining ones."""
    vulns = [_entity(id="vuln-1", name="A"), _entity(id="vuln-2", name="B")]
    orchestrator.client_api.fetch_vulnerabilities = MagicMock(
        return_value=_async_gen([vulns])
    )
    orchestrator.converter.convert_vulnerability_to_stix.side_effect = [
        RuntimeError("boom"),
        [SimpleNamespace(type="vulnerability", id="vulnerability--2")],
    ]

    await orchestrator._process_vulnerabilities(initial_state=None)

    orchestrator.batch_processor.add_items.assert_called_once()


# =====================
# Test Cases: _process_reports
# =====================


@pytest.mark.asyncio
async def test_process_reports_success_without_relationships(
    orchestrator: Orchestrator,
) -> None:
    """Test the base report processing path with no subentities to relate."""
    report = _entity(id="report-1", name="Fixture Report")
    orchestrator.client_api.fetch_reports = MagicMock(
        return_value=_async_gen([[report]])
    )
    orchestrator.client_api.fetch_subentities_ids = AsyncMock(return_value={})
    orchestrator.client_api.fetch_subentity_details = AsyncMock(return_value={})
    orchestrator.converter.convert_report_to_stix.return_value = [
        SimpleNamespace(type="report", id="report--1", object_refs=[])
    ]
    orchestrator.converter.convert_subentities_to_stix_with_linking.return_value = []

    await orchestrator._process_reports(initial_state=None)

    orchestrator.batch_processor.add_items.assert_called_once()


@pytest.mark.asyncio
async def test_process_reports_logs_relationship_summary(
    orchestrator: Orchestrator,
) -> None:
    """Test that discovered subentity relationships are logged with a summary."""
    report = _entity(id="report-1", name="Fixture Report")
    orchestrator.client_api.fetch_reports = MagicMock(
        return_value=_async_gen([[report]])
    )
    orchestrator.client_api.fetch_subentities_ids = AsyncMock(
        return_value={"malware_families": ["mw-1"]}
    )
    orchestrator.client_api.fetch_subentity_details = AsyncMock(
        return_value={"malware_families": [_entity(id="mw-1", name="Emotet")]}
    )
    orchestrator.converter.convert_report_to_stix.return_value = [
        SimpleNamespace(type="report", id="report--1", object_refs=[])
    ]
    orchestrator.converter.convert_subentities_to_stix_with_linking.return_value = []

    await orchestrator._process_reports(initial_state=None)

    orchestrator.client_api.fetch_subentity_details.assert_called_once_with(
        {"malware_families": ["mw-1"]}
    )


@pytest.mark.asyncio
async def test_process_reports_skips_ioc_enrichment_over_threshold(
    orchestrator: Orchestrator,
) -> None:
    """Test that IOC subentity types are excluded from detail fetching once over threshold."""
    orchestrator.ioc_enrichment_threshold = 1
    report = _entity(id="report-1", name="Fixture Report")
    orchestrator.client_api.fetch_reports = MagicMock(
        return_value=_async_gen([[report]])
    )
    orchestrator.client_api.fetch_subentities_ids = AsyncMock(
        return_value={"domains": ["d1", "d2"], "malware_families": ["mw-1"]}
    )
    orchestrator.client_api.fetch_subentity_details = AsyncMock(
        return_value={"malware_families": [_entity(id="mw-1", name="Emotet")]}
    )
    orchestrator.converter.convert_report_to_stix.return_value = [
        SimpleNamespace(type="report", id="report--1", object_refs=[])
    ]
    orchestrator.converter.convert_subentities_to_stix_with_linking.return_value = []

    await orchestrator._process_reports(initial_state=None)

    called_with = orchestrator.client_api.fetch_subentity_details.call_args[0][0]
    assert "domains" not in called_with  # noqa: S101
    assert "malware_families" in called_with  # noqa: S101


@pytest.mark.asyncio
async def test_process_reports_enriches_iocs_when_enabled(
    orchestrator: Orchestrator,
) -> None:
    """Test that IOC enrichment maps are built when the config flag is enabled."""
    orchestrator.enrich_iocs_with_threat_actors_and_malware = True
    report = _entity(id="report-1", name="Fixture Report")
    orchestrator.client_api.fetch_reports = MagicMock(
        return_value=_async_gen([[report]])
    )
    orchestrator.client_api.fetch_subentities_ids = AsyncMock(
        return_value={"threat_actors": ["ta-1"], "domains": ["d1"]}
    )
    orchestrator.client_api.fetch_subentity_details = AsyncMock(
        return_value={
            "threat_actors": [_entity(id="ta-1", name="APT1")],
            "domains": [_entity(id="d1")],
        }
    )
    orchestrator.converter.convert_report_to_stix.return_value = [
        SimpleNamespace(type="report", id="report--1", object_refs=[])
    ]
    orchestrator.converter.convert_subentities_to_stix_with_linking.return_value = []

    await orchestrator._process_reports(initial_state=None)

    call_kwargs = (
        orchestrator.converter.convert_subentities_to_stix_with_linking.call_args
    )
    threat_actor_map = call_kwargs[0][2]
    assert threat_actor_map.get("domains", {}).get("d1") == ["APT1"]  # noqa: S101


@pytest.mark.asyncio
async def test_process_reports_flushes_before_threshold(
    orchestrator: Orchestrator,
) -> None:
    """Test that the batch processor is flushed before adding when near the batch size limit."""
    report = _entity(id="report-1", name="Fixture Report")
    orchestrator.client_api.fetch_reports = MagicMock(
        return_value=_async_gen([[report]])
    )
    orchestrator.client_api.fetch_subentities_ids = AsyncMock(return_value={})
    orchestrator.client_api.fetch_subentity_details = AsyncMock(return_value={})
    orchestrator.converter.convert_report_to_stix.return_value = [
        SimpleNamespace(type="report", id="report--1", object_refs=[])
    ]
    orchestrator.converter.convert_subentities_to_stix_with_linking.return_value = []
    orchestrator.batch_processor.get_current_batch_size.return_value = 499

    await orchestrator._process_reports(initial_state=None)

    orchestrator.batch_processor.flush.assert_called_once()


# =====================
# Test Cases: run
# =====================


@pytest.mark.asyncio
async def test_run_processes_only_enabled_import_types(
    orchestrator: Orchestrator,
) -> None:
    """Test that run() only invokes the processing steps enabled in configuration."""
    orchestrator.config.import_reports = True
    orchestrator.config.import_campaigns = True
    orchestrator.config.import_threat_actors = False
    orchestrator.config.import_malware_families = False
    orchestrator.config.import_vulnerabilities = False

    orchestrator._process_reports = AsyncMock()  # type: ignore
    orchestrator._process_campaigns = AsyncMock()  # type: ignore
    orchestrator._process_threat_actors = AsyncMock()  # type: ignore
    orchestrator._process_malware_families = AsyncMock()  # type: ignore
    orchestrator._process_vulnerabilities = AsyncMock()  # type: ignore

    await orchestrator.run(initial_state=None)

    orchestrator._process_reports.assert_called_once()
    orchestrator._process_campaigns.assert_called_once()
    orchestrator._process_threat_actors.assert_not_called()
    orchestrator._process_malware_families.assert_not_called()
    orchestrator._process_vulnerabilities.assert_not_called()
    orchestrator.batch_processor.flush.assert_called_once()


@pytest.mark.asyncio
async def test_run_flushes_batch_processor_even_on_error(
    orchestrator: Orchestrator,
) -> None:
    """Test that run() flushes the batch processor via finally even if processing raises."""
    orchestrator.config.import_reports = True
    orchestrator._process_reports = AsyncMock(side_effect=RuntimeError("boom"))  # type: ignore

    with pytest.raises(RuntimeError, match="boom"):
        await orchestrator.run(initial_state=None)

    orchestrator.batch_processor.flush.assert_called_once()

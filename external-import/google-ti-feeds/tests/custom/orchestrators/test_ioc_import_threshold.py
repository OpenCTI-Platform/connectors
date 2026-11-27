"""Tests for skipping IOC sub-entities of reports and campaigns above a threshold."""

import logging
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from connector.src.custom.orchestrators.collection_orchestrator import (
    CollectionOrchestrator,
)
from connector.src.custom.orchestrators.report.orchestrator_report import (
    OrchestratorReport,
)

ALL_SUBENTITY_TYPES = [
    "malware_families",
    "threat_actors",
    "domains",
    "files",
    "urls",
    "ip_addresses",
]
NON_IOC_SUBENTITY_TYPES = ["malware_families", "threat_actors"]


def _entity(ioc_count: int | None) -> Any:
    counters = None if ioc_count is None else SimpleNamespace(iocs=ioc_count)
    return SimpleNamespace(
        id="report--1", attributes=SimpleNamespace(counters=counters)
    )


def _skip(threshold: int | None, entity: Any) -> tuple[list[str], MagicMock]:
    orchestrator = SimpleNamespace(
        LOG_PREFIX="[Test]",
        config=SimpleNamespace(ioc_import_threshold=threshold),
        logger=MagicMock(),
    )
    result = CollectionOrchestrator._skip_iocs_above_threshold(
        orchestrator,  # type: ignore[arg-type]
        list(ALL_SUBENTITY_TYPES),
        entity,
    )
    return result, orchestrator.logger


# Scenario: the threshold only drops IOC types when it is exceeded
@pytest.mark.parametrize(
    "threshold, ioc_count, expected",
    [
        (None, 10_000, ALL_SUBENTITY_TYPES),
        (250, 250, ALL_SUBENTITY_TYPES),
        (250, 251, NON_IOC_SUBENTITY_TYPES),
        (250, None, ALL_SUBENTITY_TYPES),
    ],
)
def test_skip_iocs_above_threshold(
    threshold: int | None, ioc_count: int | None, expected: list[str]
) -> None:
    """IOC types are dropped only above a set threshold with a known IOC count."""
    # Given an entity with the given IOC count
    entity = _entity(ioc_count)
    # When the sub-entity types are filtered
    result, _ = _skip(threshold, entity)
    # Then only the expected types remain
    assert result == expected  # noqa: S101


def test_skip_iocs_above_threshold_logs_warning() -> None:
    """Skipping IOCs is logged as a warning with the count and the threshold."""
    # Given an entity above the threshold
    entity = _entity(300)
    # When the sub-entity types are filtered
    _, logger = _skip(250, entity)
    # Then a warning reports the skipped IOCs
    logger.warning.assert_called_once()
    meta = logger.warning.call_args.args[1]
    assert meta["ioc_count"] == 300  # noqa: S101
    assert meta["ioc_import_threshold"] == 250  # noqa: S101


@pytest.mark.asyncio
async def test_report_orchestrator_skips_iocs_above_threshold() -> None:
    """The report orchestrator does not fetch IOCs of a report above the threshold."""
    # Given a report referencing more IOCs than the threshold
    config = MagicMock()
    config.ioc_import_threshold = 100
    config.report_subentities = list(ALL_SUBENTITY_TYPES)
    config.report_download_pdf = False
    orchestrator = OrchestratorReport(
        work_manager=MagicMock(),
        logger=logging.getLogger(__name__),
        config=config,
        tlp_level="white",
    )
    report = MagicMock(id="report--1")
    report.attributes.counters.iocs = 500

    async def fetch_reports(_: Any) -> Any:
        yield [report]

    orchestrator.client_api = MagicMock()
    orchestrator.client_api.fetch_reports = fetch_reports
    orchestrator.client_api.fetch_subentities = AsyncMock(return_value={})
    orchestrator.converter = MagicMock()
    orchestrator.converter.convert_report_to_stix.return_value = []
    orchestrator.converter.convert_subentities_to_stix_with_linking.return_value = []

    # When the orchestrator runs
    with (
        patch.object(orchestrator, "_update_index_inplace"),
        patch.object(orchestrator, "_flush_batch_processor"),
        patch.object(orchestrator, "_check_batch_size_and_flush"),
        patch.object(orchestrator, "_add_entities_to_batch"),
    ):
        await orchestrator.run(None)

    # Then only the non-IOC sub-entities are fetched
    fetched_types = orchestrator.client_api.fetch_subentities.call_args.kwargs[
        "subentity_types"
    ]
    assert fetched_types == NON_IOC_SUBENTITY_TYPES  # noqa: S101

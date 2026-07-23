"""Validate the indicator orchestration workflow A-to-Z using IOC delta stubs."""

import logging
from datetime import datetime, timedelta, timezone
from typing import Any
from unittest.mock import MagicMock

import pytest
from connector.src.custom.models.gti.gti_ioc_delta_model import (
    IOCDeltaAttributes,
    IOCDeltaEntry,
    IOCDeltaGTIAssessment,
    IOCDeltaRelationshipData,
    IOCDeltaRelationshipItem,
    IOCDeltaRelationshipItemAttributes,
    IOCDeltaRelationships,
    IOCDeltaSeverity,
    IOCDeltaThreatScore,
    IOCDeltaVerdict,
)
from pydantic import HttpUrl
from pydantic.types import SecretStr

# =====================
# Test Fakes
# =====================


class FakeWorkManager:
    """FakeWorkManager is a fake implementation of WorkManager for testing purposes."""

    def __init__(self) -> None:
        """Initialize the FakeWorkManager."""
        self.updated_state: dict[str, Any] = {}

    def get_state(self) -> dict[str, Any]:
        """Get the current state of the FakeWorkManager."""
        return {}

    def set_current_work_id(self, work_id: str) -> None:
        """Set the current work ID."""
        pass

    def update_state(
        self, state_key: str, date_str: str = "", error_flag: bool = False
    ) -> None:
        """Update the state of the FakeWorkManager."""
        self.updated_state[state_key] = date_str

    def send_bundle(self, work_id: str, bundle: Any) -> None:
        """Send a bundle to the FakeWorkManager."""
        pass

    def publish_report(self, *args: Any, **kwargs: Any) -> None:
        """Publish a report using the FakeWorkManager."""
        pass

    def initiate_work(self, name: str) -> None:
        """Initiate a new work item using the FakeWorkManager."""
        pass

    def work_to_process(self, work_id: str) -> None:
        """Retrieve a work item to process using the FakeWorkManager."""
        pass


class DummyConfig:
    """Dummy configuration for testing indicator orchestration."""

    def __init__(
        self,
        api_key: SecretStr,
        api_url: HttpUrl,
        tlp_level: str,
        indicator_types: list[str],
        indicator_import_start_date: timedelta,
        indicator_min_score: int = 0,
    ):
        """Initialize the DummyConfig object."""
        self.api_key = api_key
        self.api_url = api_url
        self.tlp_level = tlp_level
        self.import_reports = False
        self.import_threat_actors = False
        self.import_malware_families = False
        self.import_vulnerabilities = False
        self.import_campaigns = False
        self.import_indicators = True
        self.indicator_types = indicator_types
        self.indicator_import_start_date = indicator_import_start_date
        self.indicator_min_score = indicator_min_score
        self.indicator_require_malware_family = False
        self.indicator_require_threat_actor = False
        self.report_import_start_date = timedelta(days=1)
        self.threat_actor_import_start_date = timedelta(days=1)
        self.malware_family_import_start_date = timedelta(days=1)
        self.vulnerability_import_start_date = timedelta(days=1)
        self.campaign_import_start_date = timedelta(days=1)
        self.report_types = ["All"]
        self.report_origins = ["All"]
        self.threat_actor_origins = "All"
        self.malware_family_origins = "All"
        self.vulnerability_origins = "All"
        self.vulnerability_get_related_softwares = True
        self.import_software_toolkits = False
        self.software_toolkit_import_start_date = timedelta(days=1)


# Sample IOC delta entries (file IOC with a malware family relationship)
SAMPLE_FILE_ENTRY = IOCDeltaEntry(
    id="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    type="file",
    attributes=IOCDeltaAttributes(
        sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        md5="d41d8cd98f00b204e9800998ecf8427e",
        sha1="da39a3ee5e6b4b0d3255bfef95601890afd80709",
        meaningful_name="malware.exe",
        names=["malware.exe"],
        size=12345,
        gti_assessment=IOCDeltaGTIAssessment(
            verdict=IOCDeltaVerdict(value="VERDICT_MALICIOUS"),
            threat_score=IOCDeltaThreatScore(value=85),
            severity=IOCDeltaSeverity(value="SEVERITY_HIGH"),
        ),
        last_modification_date=1700000000,
    ),
    relationships=IOCDeltaRelationships(
        malware_families=IOCDeltaRelationshipData(
            data=[
                IOCDeltaRelationshipItem(
                    type="collection",
                    id="malware--00000000-0000-0000-0000-000000000001",
                    attributes=IOCDeltaRelationshipItemAttributes(
                        name="TestMalware",
                        collection_type="malware-family",
                    ),
                )
            ]
        )
    ),
)


# =====================
# Fixtures
# =====================


@pytest.fixture(autouse=True)
def patch_fetch_ioc_delta_package(monkeypatch: Any) -> Any:
    """Before any test runs, replace ClientAPIIndicator.fetch_ioc_delta_package so that
    it never does a real HTTP call, but instead returns the sample IOC delta stub.
    """
    from connector.src.custom.client_api.indicator.client_api_indicator import (
        ClientAPIIndicator,
    )

    async def _fake_fetch_ioc_delta_package(
        self: Any, package_id: str, ioc_type: str
    ) -> list[IOCDeltaEntry]:
        """Return the sample IOC delta entries for file type; empty otherwise."""
        if ioc_type == "file":
            return [SAMPLE_FILE_ENTRY]
        return []

    monkeypatch.setattr(
        ClientAPIIndicator,
        "fetch_ioc_delta_package",
        _fake_fetch_ioc_delta_package,
        raising=True,
    )

    yield


@pytest.fixture
def gti_config() -> DummyConfig:
    """Fixture for GTI indicator configuration."""
    return DummyConfig(
        api_key=SecretStr("fake-key"),
        api_url=HttpUrl("https://fake-gti.api"),
        tlp_level="white",
        indicator_types=["file"],
        indicator_import_start_date=timedelta(hours=1),
    )


@pytest.fixture
def expected_indicator_log_messages() -> list[str]:
    """Fixture for expected log messages in indicator orchestration."""
    return [
        "Starting indicator orchestration - {'prefix': '[OrchestratorIndicator]'}",
        "Processing IOC delta packages - {'prefix': '[OrchestratorIndicator]'",
        "Processing IOC delta package - {'prefix': '[OrchestratorIndicator]'",
        "Fetched IOC delta entries - {'prefix': '[OrchestratorIndicator]'",
        "Flushing remaining items - {'prefix': '[GenericBatchProcessor]'",
        "Processing batch - {'prefix': '[GenericBatchProcessor]'",
        "Sent batch to OpenCTI - {'prefix': '[GenericBatchProcessor]'",
        "Successfully processed batch #1",
    ]


# =====================
# Test Cases
# =====================


# Scenario: Full indicator orchestration processes IOC delta packages successfully
@pytest.mark.asyncio
async def test_full_orchestration_indicators(  # type: ignore
    gti_config: DummyConfig,
    expected_indicator_log_messages: list[str],
    caplog: Any,
) -> None:
    """Test full indicator orchestration from IOC delta fetch to OpenCTI submission."""
    # Given an orchestrator configured for indicator import with test setup
    orchestrator = _given_orchestrator_with_test_setup(gti_config, caplog)
    # When the indicator orchestration workflow is executed
    await _when_indicator_orchestration_executed(orchestrator)
    # Then the orchestration should complete successfully with expected log messages
    _then_orchestration_completed_successfully(caplog, expected_indicator_log_messages)


# Scenario: Indicator orchestration updates connector state after processing packages
@pytest.mark.asyncio
async def test_full_orchestration_indicators_updates_state(  # type: ignore
    gti_config: DummyConfig,
    caplog: Any,
) -> None:
    """Test that indicator orchestration persists the last processed package ID."""
    # Given an orchestrator configured for indicator import with test setup
    orchestrator = _given_orchestrator_with_test_setup(gti_config, caplog)
    # When the indicator orchestration workflow is executed
    await _when_indicator_orchestration_executed(orchestrator)
    # Then the connector state should contain the last processed package ID
    _then_state_updated_with_package_id(orchestrator)


# =====================
# GWT Gherkin-style functions
# =====================


# Given an orchestrator with test configuration and logging setup
def _given_orchestrator_with_test_setup(gti_config: DummyConfig, caplog: Any) -> Any:
    """Set up the orchestrator with test configuration and logging."""
    fake_wm = FakeWorkManager()

    logger = logging.getLogger("test_orchestrate_indicators")
    logger.setLevel(logging.INFO)
    caplog.set_level(logging.INFO)

    from connector.src.custom.orchestrators.orchestrator import (
        Orchestrator,
    )

    orchestrator = Orchestrator(
        work_manager=fake_wm,  # type: ignore
        logger=logger,
        config=gti_config,
        tlp_level=gti_config.tlp_level,
    )

    return orchestrator


# When the indicator orchestration workflow is executed
async def _when_indicator_orchestration_executed(orchestrator: Any) -> None:
    """Execute the indicator orchestration workflow."""
    await orchestrator.run_indicators(initial_state=None)


# Then the orchestration should complete successfully with expected results and logs
def _then_orchestration_completed_successfully(
    caplog: Any, expected_log_messages: list[str]
) -> None:
    """Verify that orchestration completed successfully with expected results and logs."""
    all_messages = [rec.getMessage() for rec in caplog.records]
    missing_messages = [
        msg
        for msg in expected_log_messages
        if not any(msg in log_msg for log_msg in all_messages)
    ]

    assert (  # noqa: S101
        not missing_messages
    ), f"Missing expected log messages: {missing_messages}"


# Then the connector state should contain the last processed package datetime
def _then_state_updated_with_package_id(orchestrator: Any) -> None:
    """Verify that the connector state was updated with the last package datetime."""
    fake_wm = orchestrator.work_manager
    assert "indicator_last_run_datetime" in fake_wm.updated_state  # noqa: S101
    stored = fake_wm.updated_state["indicator_last_run_datetime"]
    # Must be a valid ISO datetime string
    parsed = datetime.fromisoformat(stored)
    assert parsed is not None  # noqa: S101


# =====================
# Additional Test Cases for Coverage
# =====================


def _get_indicator_orchestrator(gti_config: DummyConfig, caplog: Any) -> Any:
    """Helper to get the OrchestratorIndicator instance from the main Orchestrator."""
    orchestrator = _given_orchestrator_with_test_setup(gti_config, caplog)
    return orchestrator.indicator_orchestrator


# --- _get_start_datetime tests (orchestrator_indicator lines 54-65) ---


def test_get_start_datetime_with_valid_state(
    gti_config: DummyConfig, caplog: Any
) -> None:
    """Valid ISO datetime in state → returns that datetime + 1 hour."""
    ind_orch = _get_indicator_orchestrator(gti_config, caplog)
    state = {"indicator_last_run_datetime": "2026-01-01T00:00:00+00:00"}
    result = ind_orch._get_start_datetime(state)
    expected = datetime(2026, 1, 1, 1, 0, 0, tzinfo=timezone.utc)
    assert result == expected  # noqa: S101


def test_get_start_datetime_with_naive_datetime(
    gti_config: DummyConfig, caplog: Any
) -> None:
    """Naive datetime in state → adds UTC then returns + 1 hour."""
    ind_orch = _get_indicator_orchestrator(gti_config, caplog)
    state = {"indicator_last_run_datetime": "2026-01-01T00:00:00"}
    result = ind_orch._get_start_datetime(state)
    expected = datetime(2026, 1, 1, 1, 0, 0, tzinfo=timezone.utc)
    assert result == expected  # noqa: S101


def test_get_start_datetime_with_invalid_datetime(
    gti_config: DummyConfig, caplog: Any
) -> None:
    """Invalid datetime string in state → logs warning and falls back to config."""
    ind_orch = _get_indicator_orchestrator(gti_config, caplog)
    state = {"indicator_last_run_datetime": "not-a-date"}
    result = ind_orch._get_start_datetime(state)
    # Falls back to now() - lookback, so should be in the recent past
    assert result <= datetime.now(timezone.utc)  # noqa: S101
    all_messages = [rec.getMessage() for rec in caplog.records]
    assert any(  # noqa: S101
        "Invalid last run datetime format" in msg for msg in all_messages
    )


# --- run with start_dt >= now (orchestrator_indicator lines 78-82) ---


@pytest.mark.asyncio
async def test_run_with_future_state_returns_immediately(
    gti_config: DummyConfig, caplog: Any
) -> None:
    """State with future datetime → logs 'No new packages' and returns."""
    ind_orch = _get_indicator_orchestrator(gti_config, caplog)
    future_dt = (datetime.now(timezone.utc) + timedelta(days=365)).isoformat()
    state = {"indicator_last_run_datetime": future_dt}
    await ind_orch.run(state)
    all_messages = [rec.getMessage() for rec in caplog.records]
    assert any(  # noqa: S101
        "No new packages to process" in msg for msg in all_messages
    )


# --- _process_package with exception (orchestrator_indicator lines 142-143) ---


@pytest.mark.asyncio
async def test_process_package_with_exception_logs_warning(
    gti_config: DummyConfig, caplog: Any, monkeypatch: Any
) -> None:
    """fetch raises an exception → logs warning without crashing."""
    from connector.src.custom.client_api.indicator.client_api_indicator import (
        ClientAPIIndicator,
    )

    async def _raise_on_fetch(self: Any, package_id: str, ioc_type: str) -> None:
        raise RuntimeError("network failure")

    monkeypatch.setattr(
        ClientAPIIndicator, "fetch_ioc_delta_package", _raise_on_fetch, raising=True
    )
    ind_orch = _get_indicator_orchestrator(gti_config, caplog)
    await ind_orch._process_package("2025010100", "file")
    all_messages = [rec.getMessage() for rec in caplog.records]
    assert any(  # noqa: S101
        "Error processing IOC delta package" in msg for msg in all_messages
    )


# --- _process_package with empty entries (orchestrator_indicator line 120) ---


@pytest.mark.asyncio
async def test_process_package_with_empty_entries_returns_early(
    gti_config: DummyConfig, caplog: Any, monkeypatch: Any
) -> None:
    """fetch returns None → early return without processing."""
    from connector.src.custom.client_api.indicator.client_api_indicator import (
        ClientAPIIndicator,
    )

    async def _return_none(self: Any, package_id: str, ioc_type: str) -> None:
        return None

    monkeypatch.setattr(
        ClientAPIIndicator, "fetch_ioc_delta_package", _return_none, raising=True
    )
    ind_orch = _get_indicator_orchestrator(gti_config, caplog)
    await ind_orch._process_package("2025010100", "file")
    all_messages = [rec.getMessage() for rec in caplog.records]
    # Should NOT log "Fetched IOC delta entries" since entries were empty
    assert not any(  # noqa: S101
        "Fetched IOC delta entries" in msg for msg in all_messages
    )


# --- BaseOrchestrator._log_relationships_summary (base_orchestrator lines 55-57) ---


def test_log_relationships_summary(gti_config: DummyConfig, caplog: Any) -> None:
    """_log_relationships_summary logs when subentities_ids is non-empty."""
    ind_orch = _get_indicator_orchestrator(gti_config, caplog)
    subentities_ids = {"malware": ["id1", "id2"], "campaign": ["id3"]}
    ind_orch._log_relationships_summary(subentities_ids, 0, 5, "indicator")
    all_messages = [rec.getMessage() for rec in caplog.records]
    assert any("Found relationships" in msg for msg in all_messages)  # noqa: S101


# --- BaseOrchestrator._log_entities_summary (base_orchestrator lines 79-87) ---


def test_log_entities_summary(gti_config: DummyConfig, caplog: Any) -> None:
    """_log_entities_summary logs entity type counts."""
    ind_orch = _get_indicator_orchestrator(gti_config, caplog)

    class FakeEntity:
        def __init__(self, entity_type: str) -> None:
            self.type = entity_type

    entities = [FakeEntity("indicator"), FakeEntity("indicator"), FakeEntity("malware")]
    ind_orch._log_entities_summary(entities, 0, 3, "indicator")
    all_messages = [rec.getMessage() for rec in caplog.records]
    assert any(
        "Converted to STIX entities" in msg for msg in all_messages
    )  # noqa: S101


# --- BaseOrchestrator._check_batch_size_and_flush (base_orchestrator lines 111-115) ---


def test_check_batch_size_and_flush_triggers_flush(
    gti_config: DummyConfig, caplog: Any
) -> None:
    """When current_batch + entities >= batch_size*2, flush is called."""
    ind_orch = _get_indicator_orchestrator(gti_config, caplog)
    mock_bp = MagicMock()
    mock_bp.config.batch_size = 10
    mock_bp.get_current_batch_size.return_value = 15
    entities = list(range(6))  # 15 + 6 = 21 >= 10*2=20
    ind_orch._check_batch_size_and_flush(mock_bp, entities)
    mock_bp.flush.assert_called_once()


def test_check_batch_size_and_flush_no_flush_needed(
    gti_config: DummyConfig, caplog: Any
) -> None:
    """When current_batch + entities < batch_size*2, flush is NOT called."""
    ind_orch = _get_indicator_orchestrator(gti_config, caplog)
    mock_bp = MagicMock()
    mock_bp.config.batch_size = 100
    mock_bp.get_current_batch_size.return_value = 5
    entities = list(range(3))  # 5 + 3 = 8 < 100*2=200
    ind_orch._check_batch_size_and_flush(mock_bp, entities)
    mock_bp.flush.assert_not_called()


# --- GTIIndicatorFetchError tests (gti_indicator_fetch_error lines 19-28) ---


def test_gti_indicator_fetch_error_basic() -> None:
    """Basic creation stores error message and default package_id."""
    from connector.src.custom.exceptions.fetch_errors.gti_indicator_fetch_error import (
        GTIIndicatorFetchError,
    )

    err = GTIIndicatorFetchError(message="connection timeout")
    assert "Error fetching IOC indicator delta: connection timeout" in str(
        err
    )  # noqa: S101
    assert err.package_id is None  # noqa: S101


def test_gti_indicator_fetch_error_with_package_id() -> None:
    """When package_id is provided, it is stored in structured_data."""
    from connector.src.custom.exceptions.fetch_errors.gti_indicator_fetch_error import (
        GTIIndicatorFetchError,
    )

    err = GTIIndicatorFetchError(message="not found", package_id="2025010112")
    assert err.package_id == "2025010112"  # noqa: S101
    assert err.structured_data["package_id"] == "2025010112"  # noqa: S101


def test_gti_indicator_fetch_error_without_package_id() -> None:
    """When no package_id, structured_data exists but has no package_id key."""
    from connector.src.custom.exceptions.fetch_errors.gti_indicator_fetch_error import (
        GTIIndicatorFetchError,
    )

    err = GTIIndicatorFetchError(message="server error")
    assert hasattr(err, "structured_data")  # noqa: S101
    assert "package_id" not in err.structured_data  # noqa: S101

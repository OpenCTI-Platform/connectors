"""Tests for OrchestratorSoftwareToolkit: __init__, _create_batch_processor, run, _update_index_inplace, _flush_batch_processor."""

import logging
from datetime import timedelta
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
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
        self.sent_bundles: list[Any] = []

    def get_state(self) -> dict[str, Any]:
        """Get the current state."""
        return {}

    def set_current_work_id(self, work_id: str) -> None:
        """Set the current work ID."""
        pass

    def update_state(
        self, state_key: str, date_str: str = "", error_flag: bool = False
    ) -> None:
        """Update state."""
        self.updated_state[state_key] = date_str

    def send_bundle(self, work_id: str, bundle: Any) -> None:
        """Send a bundle."""
        self.sent_bundles.append(bundle)

    def publish_report(self, *args: Any, **kwargs: Any) -> None:
        """Publish a report."""
        pass

    def initiate_work(self, name: str) -> str:
        """Initiate a new work item."""
        return "fake-work-id"

    def work_to_process(self, work_id: str) -> None:
        """Process a work item."""
        pass


class DummySoftwareToolkitConfig:
    """Dummy configuration for testing software toolkit orchestration."""

    def __init__(self):
        """Initialize DummySoftwareToolkitConfig."""
        self.api_key = SecretStr("fake-key")
        self.api_url = HttpUrl("https://fake-gti.api")
        self.tlp_level = "white"
        self.import_reports = False
        self.import_threat_actors = False
        self.import_malware_families = False
        self.import_vulnerabilities = False
        self.import_campaigns = False
        self.import_indicators = False
        self.import_software_toolkits = True
        self.software_toolkit_import_start_date = timedelta(days=1)
        self.software_toolkit_origins = ["google threat intelligence"]
        self.software_toolkit_extra_filters = []
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
        self.vulnerability_get_related_softwares = False
        self.indicator_import_start_date = timedelta(days=1)
        self.indicator_types = ["file"]


# =====================
# Helpers
# =====================


def _make_orchestrator(config=None, caplog=None):
    """Create an OrchestratorSoftwareToolkit with a FakeWorkManager."""
    from connector.src.custom.orchestrators.software_toolkit.orchestrator_software_toolkit import (
        OrchestratorSoftwareToolkit,
    )

    if config is None:
        config = DummySoftwareToolkitConfig()
    fake_wm = FakeWorkManager()
    logger = logging.getLogger("test_orchestrator_software_toolkit")
    logger.setLevel(logging.DEBUG)
    if caplog is not None:
        caplog.set_level(logging.DEBUG)

    orch = OrchestratorSoftwareToolkit(
        work_manager=fake_wm,  # type: ignore
        logger=logger,
        config=config,
        tlp_level="white",
    )
    return orch, fake_wm


# =====================
# __init__ and _create_batch_processor tests
# =====================


class TestOrchestratorSoftwareToolkitInit:
    """Tests for OrchestratorSoftwareToolkit initialization."""

    def test_given_valid_config_when_init_then_creates_converter_and_batch_processor(
        self,
    ):
        """__init__ sets up converter and batch_processor successfully."""
        orch, _ = _make_orchestrator()
        assert orch.converter is not None
        assert orch.batch_processor is not None
        assert orch.nb_current == 0

    def test_given_valid_config_when_create_batch_processor_then_returns_generic_batch_processor(
        self,
    ):
        """_create_batch_processor returns a GenericBatchProcessor."""
        from connector.src.utils.batch_processors import GenericBatchProcessor

        orch, _ = _make_orchestrator()
        bp = orch._create_batch_processor()
        assert isinstance(bp, GenericBatchProcessor)


# =====================
# _update_index_inplace tests
# =====================


class TestUpdateIndexInplace:
    """Tests for OrchestratorSoftwareToolkit._update_index_inplace."""

    def test_given_zero_total_when_update_index_then_shows_zero_zero(self):
        """When real_total_software_toolkits is 0, template shows (~ 0/0 ...)."""
        orch, _ = _make_orchestrator()
        orch.client_api = MagicMock()
        orch.client_api.real_total_software_toolkits = 0
        orch.batch_processor.config.work_name_template = (
            "Batch #1 (~ 0/0 software toolkits)"
        )
        orch._update_index_inplace()
        assert (
            "(~ 0/0 software toolkits)"
            in orch.batch_processor.config.work_name_template
        )

    def test_given_nonzero_total_when_update_index_then_increments_nb_current(self):
        """When real_total is set, nb_current increments and template updates."""
        orch, _ = _make_orchestrator()
        orch.client_api = MagicMock()
        orch.client_api.real_total_software_toolkits = 10
        orch.batch_processor.config.work_name_template = (
            "Batch #1 (~ 0/0 software toolkits)"
        )
        orch._update_index_inplace()
        assert orch.nb_current == 1
        assert (
            "(~ 1/10 software toolkits)"
            in orch.batch_processor.config.work_name_template
        )

    def test_given_multiple_calls_when_update_index_then_increments_each_time(self):
        """Multiple calls increment nb_current each time."""
        orch, _ = _make_orchestrator()
        orch.client_api = MagicMock()
        orch.client_api.real_total_software_toolkits = 5
        orch.batch_processor.config.work_name_template = (
            "Batch #1 (~ 0/0 software toolkits)"
        )
        orch._update_index_inplace()
        orch._update_index_inplace()
        assert orch.nb_current == 2
        assert (
            "(~ 2/5 software toolkits)"
            in orch.batch_processor.config.work_name_template
        )

    def test_given_no_pattern_in_template_when_update_index_then_template_unchanged(
        self,
    ):
        """When template has no match pattern, it is left unchanged."""
        orch, _ = _make_orchestrator()
        orch.client_api = MagicMock()
        orch.client_api.real_total_software_toolkits = 5
        original_template = "Batch #1 - no pattern here"
        orch.batch_processor.config.work_name_template = original_template
        orch._update_index_inplace()
        assert orch.batch_processor.config.work_name_template == original_template


# =====================
# _flush_batch_processor tests
# =====================


class TestFlushBatchProcessor:
    """Tests for OrchestratorSoftwareToolkit._flush_batch_processor."""

    def test_given_work_id_returned_when_flush_then_logs_info(self, caplog):
        """When flush returns a work_id, logs info about flushing."""
        orch, _ = _make_orchestrator(caplog=caplog)
        mock_bp = MagicMock()
        mock_bp.flush.return_value = "work-id-123"
        orch.batch_processor = mock_bp

        orch._flush_batch_processor()

        mock_bp.flush.assert_called_once()
        mock_bp.update_final_state.assert_called_once()

    def test_given_no_work_id_returned_when_flush_then_completes_without_error(self):
        """When flush returns None/falsy, completes without error."""
        orch, _ = _make_orchestrator()
        mock_bp = MagicMock()
        mock_bp.flush.return_value = None
        orch.batch_processor = mock_bp

        orch._flush_batch_processor()

        mock_bp.flush.assert_called_once()
        mock_bp.update_final_state.assert_called_once()

    def test_given_flush_raises_when_flush_then_logs_error_and_does_not_propagate(
        self, caplog
    ):
        """When flush raises an exception, it is caught and logged, not propagated."""
        orch, _ = _make_orchestrator(caplog=caplog)
        mock_bp = MagicMock()
        mock_bp.flush.side_effect = RuntimeError("flush failed")
        orch.batch_processor = mock_bp

        orch._flush_batch_processor()  # should not raise

        all_messages = [rec.getMessage() for rec in caplog.records]
        assert any(
            "Failed to flush software toolkit batch processor" in msg
            for msg in all_messages
        )


# =====================
# run() tests
# =====================


class TestOrchestratorRun:
    """Tests for OrchestratorSoftwareToolkit.run."""

    @pytest.mark.asyncio
    async def test_given_empty_api_response_when_run_then_flush_is_called(self):
        """When API yields no toolkits, flush is still called in finally block."""
        orch, _ = _make_orchestrator()
        orch.client_api = MagicMock()

        async def _empty_fetch(initial_state):
            return
            yield  # make it an async generator

        orch.client_api.fetch_software_toolkits = _empty_fetch
        mock_bp = MagicMock()
        mock_bp.flush.return_value = None
        mock_bp.config.batch_size = 9999
        mock_bp.config.work_name_template = "Batch #1 (~ 0/0 software toolkits)"
        mock_bp.get_current_batch_size.return_value = 0
        orch.batch_processor = mock_bp

        await orch.run(initial_state=None)

        mock_bp.flush.assert_called_once()

    @pytest.mark.asyncio
    async def test_given_single_toolkit_when_run_then_converts_and_adds_to_batch(
        self,
    ):
        """When API yields one toolkit, it is converted and added to batch."""
        orch, _ = _make_orchestrator()
        orch.client_api = MagicMock()
        orch.client_api.real_total_software_toolkits = 1

        fake_toolkit = MagicMock()
        fake_toolkit.id = "tool--abc"

        async def _single_toolkit_fetch(initial_state):
            yield [fake_toolkit]

        orch.client_api.fetch_software_toolkits = _single_toolkit_fetch

        fake_stix_entity = MagicMock()
        fake_stix_entity.type = "tool"
        orch.converter.convert_software_toolkit_to_stix = MagicMock(
            return_value=[fake_stix_entity]
        )
        orch.converter.convert_subentities_to_stix_with_linking = MagicMock(
            return_value=[]
        )

        orch.client_api.fetch_subentities = AsyncMock(
            return_value={
                "malware_families": [],
                "attack_techniques": [],
                "threat_actors": [],
            }
        )

        mock_bp = MagicMock()
        mock_bp.flush.return_value = None
        mock_bp.config.batch_size = 9999
        mock_bp.config.work_name_template = "Batch #1 (~ 0/0 software toolkits)"
        mock_bp.get_current_batch_size.return_value = 0
        orch.batch_processor = mock_bp

        await orch.run(initial_state=None)

        orch.converter.convert_software_toolkit_to_stix.assert_called_once_with(
            fake_toolkit
        )
        mock_bp.add_items.assert_called()

    @pytest.mark.asyncio
    async def test_given_toolkit_with_attack_techniques_when_run_then_uses_id_only_approach(
        self,
    ):
        """Attack techniques are handled via ID-only approach in run."""
        orch, _ = _make_orchestrator()
        orch.client_api = MagicMock()
        orch.client_api.real_total_software_toolkits = 1

        fake_toolkit = MagicMock()
        fake_toolkit.id = "tool--abc"

        async def _fetch(initial_state):
            yield [fake_toolkit]

        orch.client_api.fetch_software_toolkits = _fetch

        fake_attack_technique = MagicMock()
        fake_attack_technique.id = "attack-pattern--xyz"

        orch.client_api.fetch_subentities = AsyncMock(
            return_value={
                "malware_families": [],
                "attack_techniques": [fake_attack_technique],
                "threat_actors": [],
            }
        )

        fake_stix = MagicMock()
        fake_stix.type = "tool"
        orch.converter.convert_software_toolkit_to_stix = MagicMock(
            return_value=[fake_stix]
        )
        orch.converter.convert_subentities_to_stix_with_linking = MagicMock(
            return_value=[]
        )

        mock_bp = MagicMock()
        mock_bp.flush.return_value = None
        mock_bp.config.batch_size = 9999
        mock_bp.config.work_name_template = "Batch #1 (~ 0/0 software toolkits)"
        mock_bp.get_current_batch_size.return_value = 0
        orch.batch_processor = mock_bp

        await orch.run(initial_state=None)

        orch.converter.convert_subentities_to_stix_with_linking.assert_called_once()
        call_kwargs = orch.converter.convert_subentities_to_stix_with_linking.call_args
        subentities_arg = call_kwargs.kwargs.get("subentities", {})
        assert "attack_techniques" in subentities_arg

    @pytest.mark.asyncio
    async def test_given_api_raises_when_run_then_flush_still_called(self):
        """When API raises an exception, flush is still called in finally."""
        orch, _ = _make_orchestrator()
        orch.client_api = MagicMock()

        async def _raising_fetch(initial_state):
            raise RuntimeError("API failure")
            yield  # make it an async generator

        orch.client_api.fetch_software_toolkits = _raising_fetch

        mock_bp = MagicMock()
        mock_bp.flush.return_value = None
        mock_bp.config.batch_size = 9999
        mock_bp.config.work_name_template = "Batch #1 (~ 0/0 software toolkits)"
        mock_bp.get_current_batch_size.return_value = 0
        orch.batch_processor = mock_bp

        with pytest.raises(RuntimeError, match="API failure"):
            await orch.run(initial_state=None)

        mock_bp.flush.assert_called_once()

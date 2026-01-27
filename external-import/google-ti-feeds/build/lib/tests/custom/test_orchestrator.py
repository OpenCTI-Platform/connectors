"""Validate the main workflow A-to-Z by running the orchestrator, on working stubs."""

import json
import logging
from datetime import timedelta
from pathlib import Path
from typing import Any

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
        if state_key == "next_cursor_start_date":
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
    """Dummy configuration for testing purposes."""

    def __init__(
        self,
        api_key: SecretStr,
        report_import_start_date: timedelta,
        api_url: HttpUrl,
        import_reports: bool,
        report_types: list[str],
        report_origins: list[str],
        tlp_level: str,
    ):
        """Initialize the DummyConfig object."""
        self.api_key = api_key
        self.report_import_start_date = report_import_start_date
        self.threat_actor_import_start_date = timedelta(days=1)
        self.malware_family_import_start_date = timedelta(days=1)
        self.vulnerability_import_start_date = timedelta(days=1)
        self.campaign_import_start_date = timedelta(days=1)
        self.api_url = api_url
        self.import_reports = import_reports
        self.import_threat_actors = True
        self.import_malware_families = True
        self.import_vulnerabilities = True
        self.import_campaigns = True
        self.report_types = report_types
        self.report_origins = report_origins
        self.threat_actor_origins = "All"
        self.malware_family_origins = "All"
        self.vulnerability_origins = "All"
        self.tlp_level = tlp_level
        self.vulnerability_get_related_softwares = True


# =====================
# Fixtures
# =====================


@pytest.fixture(autouse=True)
def patch_perform_single_attempt(monkeypatch: Any) -> Any:
    """Before any test runs, replace RetryRequestStrategy._perform_single_attempt so that
    it never does a real HTTP call, but instead returns exactly the stub["response"].
    """
    from connector.src.utils.api_engine.retry_request_strategy import (
        RetryRequestStrategy,
    )

    debug_folder = Path(__file__).parent / "debug_responses"
    assert debug_folder.is_dir(), f"Missing {debug_folder=}"  # noqa: S101

    response_data = _load_debug_responses(debug_folder)

    async def _fake_perform_single_attempt(self) -> Any:  # type: ignore
        """Perform a single attempt using the stubbed responses."""
        model_mapping = {
            "GTIMalwareFamilyData": "malware_families",
            "GTIThreatActorData": "threat_actors",
            "GTIVulnerabilityData": "vulnerabilities",
            "GTIAttackTechniqueData": "attack_techniques",
            "GTIDomainData": "domains",
            "GTIFileData": "files",
            "GTIURLData": "urls",
            "GTIIPData": "ip_addresses",
            "GTIReportResponse": "main_reports",
            "GTIThreatActorResponse": "main_threat_actors",
            "GTIMalwareFamilyResponse": "main_malware_families",
            "GTIVulnerabilityResponse": "main_vulnerabilities",
            "GTIReportData": "reports",
            "GTICampaignResponse": "main_campaigns",
            "GTICampaignData": "campaigns",
        }

        if "relationship" in self.api_req.url:
            response_key = "relationships"
        elif (
            "/collections" in self.api_req.url
            and hasattr(self.api_req, "model")
            and self.api_req.model
        ):
            # Check if this is a main collection fetch or a specific collection entity fetch
            url_parts = self.api_req.url.split("/")
            if len(url_parts) > 4 and url_parts[4]:  # /collections/specific-id
                # This is a specific collection entity fetch (subentity)
                model_name = self.api_req.model.__name__
                response_key = model_mapping.get(model_name, "reports")
            else:
                # This is a main collection fetch
                model_name = self.api_req.model.__name__
                response_key = model_mapping.get(model_name, "main_reports")
        else:
            # Other subentity fetches
            model_name = (
                self.api_req.model.__name__
                if hasattr(self.api_req, "model") and self.api_req.model
                else None
            )
            response_key = model_mapping.get(model_name, "reports")

        raw_response = response_data[response_key]

        if self.api_req.response_key and self.api_req.response_key in raw_response:
            raw_response = raw_response[self.api_req.response_key]

        if self.api_req.model:
            return self.api_req.model.model_validate(raw_response)
        return raw_response

    monkeypatch.setattr(
        RetryRequestStrategy,
        "_perform_single_attempt",
        _fake_perform_single_attempt,
        raising=True,
    )

    yield


@pytest.fixture
def gti_config() -> DummyConfig:
    """Fixture for GTI configuration."""
    return DummyConfig(
        api_key=SecretStr("fake-key"),
        report_import_start_date=timedelta(days=1),
        api_url=HttpUrl("https://fake-gti.api"),
        import_reports=True,
        report_types=["All"],
        report_origins=["All"],
        tlp_level="white",
    )


@pytest.fixture
def expected_report_log_messages() -> list[str]:
    """Fixture for expected log messages in report orchestration."""
    return [
        "Fetched 1 reports from API (total of 1 items) - {'prefix': '[FetcherReport]'}",
        "Fetched 1 malware_families relationships from API - {'prefix': '[BaseFetcher]'}",
        "Fetched 1 threat_actors relationships from API - {'prefix': '[BaseFetcher]'}",
        "Fetched 1 attack_techniques relationships from API - {'prefix': '[BaseFetcher]'}",
        "Fetched 1 vulnerabilities relationships from API - {'prefix': '[BaseFetcher]'}",
        "Fetched 1 campaigns relationships from API - {'prefix': '[BaseFetcher]'}",
        "Fetched 1 domains relationships from API - {'prefix': '[BaseFetcher]'}",
        "Fetched 1 files relationships from API - {'prefix': '[BaseFetcher]'}",
        "Fetched 1 urls relationships from API - {'prefix': '[BaseFetcher]'}",
        "Fetched 1 ip_addresses relationships from API - {'prefix': '[BaseFetcher]'}",
        "Found relationships - {'prefix': '[OrchestratorReport]', 'current': 1, 'total': 1, 'relationships': 'malware_families: 1, threat_actors: 1, attack_techniques: 1, vulnerabilities: 1, campaigns: 1, domains: 1, files: 1, urls: 1, ip_addresses: 1'}",
        "Using ID-only approach for attack techniques (quota optimization) - {'prefix': '[OrchestratorReport]', 'attack_technique_count': 1}",
        "Fetching details for subentities - {'prefix': '[FetcherShared]', 'total_to_fetch': 8}",
        "Fetched entities - {'prefix': '[GenericFetcher]', 'count': 1, 'entity_type': 'malware families'}",
        "Fetched entities - {'prefix': '[GenericFetcher]', 'count': 1, 'entity_type': 'threat actors'}",
        "Fetched entities - {'prefix': '[GenericFetcher]', 'count': 1, 'entity_type': 'vulnerabilities'}",
        "Fetched entities - {'prefix': '[GenericFetcher]', 'count': 1, 'entity_type': 'campaigns'}",
        "Fetched entities - {'prefix': '[GenericFetcher]', 'count': 1, 'entity_type': 'domains'}",
        "Fetched entities - {'prefix': '[GenericFetcher]', 'count': 1, 'entity_type': 'files'}",
        "Fetched entities - {'prefix': '[GenericFetcher]', 'count': 1, 'entity_type': 'URLs'}",
        "Fetched entities - {'prefix': '[GenericFetcher]', 'count': 1, 'entity_type': 'IP addresses'}",
        "Fetched details - {'prefix': '[FetcherShared]', 'summary': 'malware_families: 1, threat_actors: 1, vulnerabilities: 1, campaigns: 1, domains: 1, files: 1, urls: 1, ip_addresses: 1'}",
        "Converted entities to STIX format - {'prefix': '[GenericConverter]', 'count': 33, 'entity_type': 'malware families'}",
        "Converted entities to STIX format - {'prefix': '[GenericConverter]', 'count': 53, 'entity_type': 'threat actors'}",
        "Converted entities to STIX format - {'prefix': '[GenericConverter]', 'count': 50, 'entity_type': 'vulnerabilities'}",
        "Converted entities to STIX format - {'prefix': '[GenericConverter]', 'count': 31, 'entity_type': 'Campaigns'}",
        "Converted entities to STIX format - {'prefix': '[GenericConverter]', 'count': 3, 'entity_type': 'domains'}",
        "Converted entities to STIX format - {'prefix': '[GenericConverter]', 'count': 3, 'entity_type': 'files'}",
        "Converted entities to STIX format - {'prefix': '[GenericConverter]', 'count': 3, 'entity_type': 'URLs'}",
        "Converted entities to STIX format - {'prefix': '[GenericConverter]', 'count': 3, 'entity_type': 'IP addresses'}",
        "Converted entities to STIX format - {'prefix': '[GenericConverter]', 'count': 1, 'entity_type': 'attack techniques'}",
        "Converted to STIX entities - {'prefix': '[OrchestratorReport]', 'current': 1, 'total': 1, 'entities_count': 195, 'entities_summary': 'identity: 48, report: 1, malware: 1, relationship: 85, location: 23, intrusion-set: 1, vulnerability: 1, software: 24, note: 1, campaign: 1, domain-name: 1, indicator: 4, file: 1, url: 1, ipv4-addr: 1, attack-pattern: 1'}",
        "Adding items to batch processor - {'prefix': '[GenericBatchProcessor]', 'count': 195, 'display_name': 'STIX objects'}",
        "Successfully added items - {'prefix': '[GenericBatchProcessor]', 'added_count': 195, 'total_count': 195, 'display_name': 'STIX objects'}",
        "Flushing remaining items - {'prefix': '[GenericBatchProcessor]', 'count': 197, 'display_name': 'STIX objects'}",
        "Processing batch - {'prefix': '[GenericBatchProcessor]', 'batch_num': 1, 'batch_size': 197, 'display_name': 'STIX objects', 'total_processed': 197}",
        "Sent batch to OpenCTI - {'prefix': '[GenericBatchProcessor]', 'batch_num': 1}",
        "Batch completed successfully - {'prefix': '[GenericBatchProcessor]', 'work_id': None, 'total_count': 197, 'type_summary': 'identity: 49, marking-definition: 1, report: 1, malware: 1, relationship: 85, location: 23, intrusion-set: 1, vulnerability: 1, software: 24, note: 1, campaign: 1, domain-name: 1, indicator: 4, file: 1, url: 1, ipv4-addr: 1, attack-pattern: 1'}",
        "Successfully processed batch #1. Total STIX objects sent: 197 - {'prefix': '[GenericBatchProcessor]', 'batch_num': 1, 'total_items_sent': 197}",
        "State update: Setting next_cursor_date - {'prefix': '[GenericBatchProcessor]', 'latest_date': '2024-07-11T20:05:01+00:00'}",
    ]


@pytest.fixture
def expected_threat_actor_log_messages() -> list[str]:
    """Fixture for expected log messages in threat actor orchestration."""
    return [
        "Fetched 1 threat_actors from API (total of 1 items) - {'prefix': '[FetcherThreatActor]'}",
        "Fetched 1 malware_families relationships from API - {'prefix': '[BaseFetcher]'}",
        "Fetched 1 attack_techniques relationships from API - {'prefix': '[BaseFetcher]'}",
        "Fetched 1 vulnerabilities relationships from API - {'prefix': '[BaseFetcher]'}",
        "Found relationships - {'prefix': '[OrchestratorThreatActor]', 'current': 1, 'total': 1, 'relationships': 'malware_families: 1, attack_techniques: 1, vulnerabilities: 1'}",
        "Using ID-only approach for attack techniques (quota optimization) - {'prefix': '[OrchestratorThreatActor]', 'attack_technique_count': 1}",
        "Fetching details for subentities - {'prefix': '[FetcherShared]', 'total_to_fetch': 2}",
        "Fetched entities - {'prefix': '[GenericFetcher]', 'count': 1, 'entity_type': 'malware families'}",
        "Fetched entities - {'prefix': '[GenericFetcher]', 'count': 1, 'entity_type': 'vulnerabilities'}",
        "Fetched details - {'prefix': '[FetcherShared]', 'summary': 'malware_families: 1, vulnerabilities: 1'}",
        "Converted entities to STIX format - {'prefix': '[GenericConverter]', 'count': 34, 'entity_type': 'malware families'}",
        "Converted entities to STIX format - {'prefix': '[GenericConverter]', 'count': 51, 'entity_type': 'vulnerabilities'}",
        "Converted entities to STIX format - {'prefix': '[GenericConverter]', 'count': 2, 'entity_type': 'attack techniques'}",
        "Converted to STIX entities - {'prefix': '[OrchestratorThreatActor]', 'current': 1, 'total': 1, 'entities_count': 140, 'entities_summary': 'location: 17, identity: 25, intrusion-set: 1, relationship: 69, malware: 1, vulnerability: 1, software: 24, note: 1, attack-pattern: 1'}",
        "Adding items to batch processor - {'prefix': '[GenericBatchProcessor]', 'count': 140, 'display_name': 'STIX objects'}",
        "Successfully added items - {'prefix': '[GenericBatchProcessor]', 'added_count': 140, 'total_count': 140, 'display_name': 'STIX objects'}",
        "Flushing remaining items - {'prefix': '[GenericBatchProcessor]', 'count': 142, 'display_name': 'STIX objects'}",
        "Processing batch - {'prefix': '[GenericBatchProcessor]', 'batch_num': 1, 'batch_size': 142, 'display_name': 'STIX objects', 'total_processed': 142}",
        "Sent batch to OpenCTI - {'prefix': '[GenericBatchProcessor]', 'batch_num': 1}",
        "Batch completed successfully - {'prefix': '[GenericBatchProcessor]', 'work_id': None, 'total_count': 142, 'type_summary': 'identity: 26, marking-definition: 1, location: 17, intrusion-set: 1, relationship: 69, malware: 1, vulnerability: 1, software: 24, note: 1, attack-pattern: 1'}",
        "Successfully processed batch #1. Total STIX objects sent: 142 - {'prefix': '[GenericBatchProcessor]', 'batch_num': 1, 'total_items_sent': 142}",
        "State update: Setting next_cursor_date - {'prefix': '[GenericBatchProcessor]', 'latest_date': '2025-06-03T03:03:32+00:00'}",
    ]


@pytest.fixture
def expected_malware_family_log_messages() -> list[str]:
    """Fixture for expected log messages in malware family orchestration."""
    return [
        "Fetched 1 malware_families from API (total of 1 items) - {'prefix': '[FetcherMalware]'}",
        "Fetched 1 threat_actors relationships from API - {'prefix': '[BaseFetcher]'}",
        "Fetched 1 attack_techniques relationships from API - {'prefix': '[BaseFetcher]'}",
        "Fetched 1 vulnerabilities relationships from API - {'prefix': '[BaseFetcher]'}",
        "Found relationships - {'prefix': '[OrchestratorMalware]', 'current': 1, 'total': 1, 'relationships': 'threat_actors: 1, attack_techniques: 1, vulnerabilities: 1'}",
        "Using ID-only approach for attack techniques (quota optimization) - {'prefix': '[OrchestratorMalware]', 'attack_technique_count': 1}",
        "Fetching details for subentities - {'prefix': '[FetcherShared]', 'total_to_fetch': 2}",
        "Fetched entities - {'prefix': '[GenericFetcher]', 'count': 1, 'entity_type': 'threat actors'}",
        "Fetched entities - {'prefix': '[GenericFetcher]', 'count': 1, 'entity_type': 'vulnerabilities'}",
        "Fetched details - {'prefix': '[FetcherShared]', 'summary': 'threat_actors: 1, vulnerabilities: 1'}",
        "Converted entities to STIX format - {'prefix': '[GenericConverter]', 'count': 54, 'entity_type': 'threat actors'}",
        "Converted entities to STIX format - {'prefix': '[GenericConverter]', 'count': 51, 'entity_type': 'vulnerabilities'}",
        "Converted entities to STIX format - {'prefix': '[GenericConverter]', 'count': 2, 'entity_type': 'attack techniques'}",
        "Converted to STIX entities - {'prefix': '[OrchestratorMalware]', 'current': 1, 'total': 1, 'entities_count': 140, 'entities_summary': 'identity: 25, malware: 1, relationship: 69, location: 17, intrusion-set: 1, vulnerability: 1, software: 24, note: 1, attack-pattern: 1'}",
        "Adding items to batch processor - {'prefix': '[GenericBatchProcessor]', 'count': 140, 'display_name': 'STIX objects'}",
        "Successfully added items - {'prefix': '[GenericBatchProcessor]', 'added_count': 140, 'total_count': 140, 'display_name': 'STIX objects'}",
        "Flushing remaining items - {'prefix': '[GenericBatchProcessor]', 'count': 142, 'display_name': 'STIX objects'}",
        "Processing batch - {'prefix': '[GenericBatchProcessor]', 'batch_num': 1, 'batch_size': 142, 'display_name': 'STIX objects', 'total_processed': 142}",
        "Sent batch to OpenCTI - {'prefix': '[GenericBatchProcessor]', 'batch_num': 1}",
        "Batch completed successfully - {'prefix': '[GenericBatchProcessor]', 'work_id': None, 'total_count': 142, 'type_summary': 'identity: 26, marking-definition: 1, malware: 1, relationship: 69, location: 17, intrusion-set: 1, vulnerability: 1, software: 24, note: 1, attack-pattern: 1'}",
        "Successfully processed batch #1. Total STIX objects sent: 142 - {'prefix': '[GenericBatchProcessor]', 'batch_num': 1, 'total_items_sent': 142}",
        "State update: Setting next_cursor_date - {'prefix': '[GenericBatchProcessor]', 'latest_date': '2025-05-09T17:11:12+00:00'}",
    ]


@pytest.fixture
def expected_vulnerability_log_messages_no_software() -> list[str]:
    """Fixture for expected log messages in vulnerability orchestration with software disabled."""
    return [
        "Fetched 1 vulnerabilities from API (total of 1 items) - {'prefix': '[FetcherVulnerability]'}",
        "Fetched 1 malware_families relationships from API - {'prefix': '[BaseFetcher]'}",
        "Fetched 1 attack_techniques relationships from API - {'prefix': '[BaseFetcher]'}",
        "Fetched 1 threat_actors relationships from API - {'prefix': '[BaseFetcher]'}",
        "Found relationships - {'prefix': '[OrchestratorVulnerability]', 'current': 1, 'total': 1, 'relationships': 'malware_families: 1, attack_techniques: 1, threat_actors: 1'}",
        "Using ID-only approach for attack techniques (quota optimization) - {'prefix': '[OrchestratorVulnerability]', 'attack_technique_count': 1}",
        "Fetching details for subentities - {'prefix': '[FetcherShared]', 'total_to_fetch': 2}",
        "Fetched entities - {'prefix': '[GenericFetcher]', 'count': 1, 'entity_type': 'malware families'}",
        "Fetched entities - {'prefix': '[GenericFetcher]', 'count': 1, 'entity_type': 'threat actors'}",
        "Fetched details - {'prefix': '[FetcherShared]', 'summary': 'malware_families: 1, threat_actors: 1'}",
        "Converted entities to STIX format - {'prefix': '[GenericConverter]', 'count': 34, 'entity_type': 'malware families'}",
        "Converted entities to STIX format - {'prefix': '[GenericConverter]', 'count': 54, 'entity_type': 'threat actors'}",
        "Converted entities to STIX format - {'prefix': '[GenericConverter]', 'count': 2, 'entity_type': 'attack techniques'}",
        "Converted to STIX entities - {'prefix': '[OrchestratorVulnerability]', 'current': 1, 'total': 1, 'entities_count': 92, 'entities_summary': 'vulnerability: 1, note: 1, identity: 25, malware: 1, relationship: 45, location: 17, intrusion-set: 1, attack-pattern: 1'}",
        "Adding items to batch processor - {'prefix': '[GenericBatchProcessor]', 'count': 92, 'display_name': 'STIX objects'}",
        "Successfully added items - {'prefix': '[GenericBatchProcessor]', 'added_count': 92, 'total_count': 92, 'display_name': 'STIX objects'}",
        "Flushing remaining items - {'prefix': '[GenericBatchProcessor]', 'count': 94, 'display_name': 'STIX objects'}",
        "Processing batch - {'prefix': '[GenericBatchProcessor]', 'batch_num': 1, 'batch_size': 94, 'display_name': 'STIX objects', 'total_processed': 94}",
        "Sent batch to OpenCTI - {'prefix': '[GenericBatchProcessor]', 'batch_num': 1}",
        "Batch completed successfully - {'prefix': '[GenericBatchProcessor]', 'work_id': None, 'total_count': 94, 'type_summary': 'identity: 26, marking-definition: 1, vulnerability: 1, note: 1, malware: 1, relationship: 45, location: 17, intrusion-set: 1, attack-pattern: 1'}",
        "Successfully processed batch #1. Total STIX objects sent: 94 - {'prefix': '[GenericBatchProcessor]', 'batch_num': 1, 'total_items_sent': 94}",
        "State update: Setting next_cursor_date - {'prefix': '[GenericBatchProcessor]', 'latest_date': '2025-06-25T08:22:55+00:00'}",
    ]


@pytest.fixture
def expected_vulnerability_log_messages() -> list[str]:
    """Fixture for expected log messages in vulnerability orchestration."""
    return [
        "Fetched 1 vulnerabilities from API (total of 1 items) - {'prefix': '[FetcherVulnerability]'}",
        "Fetched 1 malware_families relationships from API - {'prefix': '[BaseFetcher]'}",
        "Fetched 1 attack_techniques relationships from API - {'prefix': '[BaseFetcher]'}",
        "Fetched 1 threat_actors relationships from API - {'prefix': '[BaseFetcher]'}",
        "Found relationships - {'prefix': '[OrchestratorVulnerability]', 'current': 1, 'total': 1, 'relationships': 'malware_families: 1, attack_techniques: 1, threat_actors: 1'}",
        "Using ID-only approach for attack techniques (quota optimization) - {'prefix': '[OrchestratorVulnerability]', 'attack_technique_count': 1}",
        "Fetching details for subentities - {'prefix': '[FetcherShared]', 'total_to_fetch': 2}",
        "Fetched entities - {'prefix': '[GenericFetcher]', 'count': 1, 'entity_type': 'malware families'}",
        "Fetched entities - {'prefix': '[GenericFetcher]', 'count': 1, 'entity_type': 'threat actors'}",
        "Fetched details - {'prefix': '[FetcherShared]', 'summary': 'malware_families: 1, threat_actors: 1'}",
        "Converted entities to STIX format - {'prefix': '[GenericConverter]', 'count': 34, 'entity_type': 'malware families'}",
        "Converted entities to STIX format - {'prefix': '[GenericConverter]', 'count': 54, 'entity_type': 'threat actors'}",
        "Converted entities to STIX format - {'prefix': '[GenericConverter]', 'count': 2, 'entity_type': 'attack techniques'}",
        "Converted to STIX entities - {'prefix': '[OrchestratorVulnerability]', 'current': 1, 'total': 1, 'entities_count': 140, 'entities_summary': 'vulnerability: 1, software: 24, note: 1, relationship: 69, identity: 25, malware: 1, location: 17, intrusion-set: 1, attack-pattern: 1'}",
        "Adding items to batch processor - {'prefix': '[GenericBatchProcessor]', 'count': 140, 'display_name': 'STIX objects'}",
        "Successfully added items - {'prefix': '[GenericBatchProcessor]', 'added_count': 140, 'total_count': 140, 'display_name': 'STIX objects'}",
        "Flushing remaining items - {'prefix': '[GenericBatchProcessor]', 'count': 142, 'display_name': 'STIX objects'}",
        "Processing batch - {'prefix': '[GenericBatchProcessor]', 'batch_num': 1, 'batch_size': 142, 'display_name': 'STIX objects', 'total_processed': 142}",
        "Sent batch to OpenCTI - {'prefix': '[GenericBatchProcessor]', 'batch_num': 1}",
        "Batch completed successfully - {'prefix': '[GenericBatchProcessor]', 'work_id': None, 'total_count': 142, 'type_summary': 'identity: 26, marking-definition: 1, vulnerability: 1, software: 24, note: 1, relationship: 69, malware: 1, location: 17, intrusion-set: 1, attack-pattern: 1'}",
        "Successfully processed batch #1. Total STIX objects sent: 142 - {'prefix': '[GenericBatchProcessor]', 'batch_num': 1, 'total_items_sent': 142}",
        "State update: Setting next_cursor_date - {'prefix': '[GenericBatchProcessor]', 'latest_date': '2025-06-25T08:22:55+00:00'}",
    ]


@pytest.fixture
def expected_campaign_log_messages() -> list[str]:
    """Fixture for expected log messages in campaign orchestration."""
    return [
        "Fetched 1 campaigns from API (total of 1 items) - {'prefix': '[FetcherCampaign]'}",
        "Fetched 1 malware_families relationships from API - {'prefix': '[BaseFetcher]'}",
        "Fetched 1 attack_techniques relationships from API - {'prefix': '[BaseFetcher]'}",
        "Fetched 1 vulnerabilities relationships from API - {'prefix': '[BaseFetcher]'}",
        "Fetched 1 threat_actors relationships from API - {'prefix': '[BaseFetcher]'}",
        "Found relationships - {'prefix': '[OrchestratorCampaign]', 'current': 1, 'total': 1, 'relationships': 'malware_families: 1, attack_techniques: 1, vulnerabilities: 1, threat_actors: 1'}",
        "Using ID-only approach for attack techniques (quota optimization) - {'prefix': '[OrchestratorCampaign]', 'attack_technique_count': 1}",
        "Fetching details for subentities - {'prefix': '[FetcherShared]', 'total_to_fetch': 3}",
        "Fetched entities - {'prefix': '[GenericFetcher]', 'count': 1, 'entity_type': 'malware families'}",
        "Fetched entities - {'prefix': '[GenericFetcher]', 'count': 1, 'entity_type': 'vulnerabilities'}",
        "Fetched entities - {'prefix': '[GenericFetcher]', 'count': 1, 'entity_type': 'threat actors'}",
        "Fetched details - {'prefix': '[FetcherShared]', 'summary': 'malware_families: 1, vulnerabilities: 1, threat_actors: 1'}",
        "Converted entities to STIX format - {'prefix': '[GenericConverter]', 'count': 34, 'entity_type': 'malware families'}",
        "Converted entities to STIX format - {'prefix': '[GenericConverter]', 'count': 51, 'entity_type': 'vulnerabilities'}",
        "Converted entities to STIX format - {'prefix': '[GenericConverter]', 'count': 54, 'entity_type': 'threat actors'}",
        "Converted entities to STIX format - {'prefix': '[GenericConverter]', 'count': 2, 'entity_type': 'attack techniques'}",
        "Converted to STIX entities - {'prefix': '[OrchestratorCampaign]', 'current': 1, 'total': 1, 'entities_count': 172, 'entities_summary': 'location: 23, identity: 34, campaign: 1, relationship: 85, malware: 1, vulnerability: 1, software: 24, note: 1, intrusion-set: 1, attack-pattern: 1'}",
        "Adding items to batch processor - {'prefix': '[GenericBatchProcessor]', 'count': 172, 'display_name': 'STIX objects'}",
        "Successfully added items - {'prefix': '[GenericBatchProcessor]', 'added_count': 172, 'total_count': 172, 'display_name': 'STIX objects'}",
        "Flushing remaining items - {'prefix': '[GenericBatchProcessor]', 'count': 174, 'display_name': 'STIX objects'}",
        "Processing batch - {'prefix': '[GenericBatchProcessor]', 'batch_num': 1, 'batch_size': 174, 'display_name': 'STIX objects', 'total_processed': 174}",
        "Sent batch to OpenCTI - {'prefix': '[GenericBatchProcessor]', 'batch_num': 1}",
        "Batch completed successfully - {'prefix': '[GenericBatchProcessor]', 'work_id': None, 'total_count': 174, 'type_summary': 'identity: 35, marking-definition: 1, location: 23, campaign: 1, relationship: 85, malware: 1, vulnerability: 1, software: 24, note: 1, intrusion-set: 1, attack-pattern: 1'}",
        "Successfully processed batch #1. Total STIX objects sent: 174 - {'prefix': '[GenericBatchProcessor]', 'batch_num': 1, 'total_items_sent': 174}",
        "State update: Setting next_cursor_date - {'prefix': '[GenericBatchProcessor]', 'latest_date': '2025-07-30T22:01:05+00:00'}",
    ]


# =====================
# Test Cases
# =====================


# Scenario: Full orchestration workflow processes reports and entities successfully
@pytest.mark.asyncio
@pytest.mark.order(2)
async def test_full_orchestration_reports(
    caplog: Any, gti_config: DummyConfig, expected_report_log_messages: list[str]
) -> None:
    """Test the full report orchestration workflow from A to Z using stubs.

    - Uses exactly the stubs under tests/custom/debug_responses/:
      •   reports_*.json
      •   relationships_*.json
      •   <entity_type>_*.json
    - Verifies the expected log messages and orchestration results.
    """
    # Given an orchestrator with test configuration and logging setup
    orchestrator = _given_orchestrator_with_test_setup(gti_config, caplog)

    # When the orchestration workflow is executed
    await _when_orchestration_executed(orchestrator)

    # Then the orchestration should complete successfully with expected results and logs
    _then_orchestration_completed_successfully(caplog, expected_report_log_messages)


# Scenario: Full orchestration workflow processes threat actors and entities successfully
@pytest.mark.asyncio
@pytest.mark.order(2)
async def test_full_orchestration_threat_actors(
    caplog: Any, gti_config: DummyConfig, expected_threat_actor_log_messages: list[str]
) -> None:
    """Test the full threat actor orchestration workflow from A to Z using stubs.

    - Uses exactly the stubs under tests/custom/debug_responses/:
      •   threat_actors_*.json
      •   relationships_*.json
      •   <entity_type>_*.json
    - Verifies the expected log messages and orchestration results.
    """
    # Given an orchestrator with test configuration and logging setup
    orchestrator = _given_orchestrator_with_test_setup(gti_config, caplog)

    # When the threat actor orchestration workflow is executed
    await _when_threat_actor_orchestration_executed(orchestrator)

    # Then the orchestration should complete successfully with expected results and logs
    _then_orchestration_completed_successfully(
        caplog, expected_threat_actor_log_messages
    )


# Scenario: Full orchestration workflow processes malware families and entities successfully
@pytest.mark.asyncio
@pytest.mark.order(2)
async def test_full_orchestration_malware_families(
    caplog: Any,
    gti_config: DummyConfig,
    expected_malware_family_log_messages: list[str],
) -> None:
    """Test the full malware family orchestration workflow from A to Z using stubs.

    - Uses exactly the stubs under tests/custom/debug_responses/:
      •   malware_families_*.json
      •   relationships_*.json
      •   <entity_type>_*.json
    - Verifies the expected log messages and orchestration results.
    """
    # Given an orchestrator with test configuration and logging setup
    orchestrator = _given_orchestrator_with_test_setup(gti_config, caplog)

    # When the malware family orchestration workflow is executed
    await _when_malware_family_orchestration_executed(orchestrator)

    # Then the orchestration should complete successfully with expected results and logs
    _then_orchestration_completed_successfully(
        caplog, expected_malware_family_log_messages
    )


@pytest.mark.asyncio
@pytest.mark.order(2)
async def test_full_orchestration_vulnerabilities(
    caplog: Any,
    gti_config: DummyConfig,
    expected_vulnerability_log_messages: list[str],
) -> None:
    """Test the full vulnerability orchestration workflow from A to Z using stubs.

    - Uses exactly the stubs under tests/custom/debug_responses/:
      •   vulnerabilities_*.json
      •   relationships_*.json
      •   <entity_type>_*.json
    - Verifies the expected log messages and orchestration results.
    """
    # Given an orchestrator with test configuration and logging setup
    orchestrator = _given_orchestrator_with_test_setup(gti_config, caplog)

    # When the vulnerability orchestration workflow is executed
    await _when_vulnerability_orchestration_executed(orchestrator)

    # Then the orchestration should complete successfully with expected results and logs
    _then_orchestration_completed_successfully(
        caplog, expected_vulnerability_log_messages
    )


# Scenario: Full orchestration workflow processes campaigns and entities successfully
@pytest.mark.asyncio
@pytest.mark.order(2)
async def test_full_orchestration_campaigns(
    caplog: Any, gti_config: DummyConfig, expected_campaign_log_messages: list[str]
) -> None:
    """Test the full campaign orchestration workflow from A to Z using stubs.

    - Uses exactly the stubs under tests/custom/debug_responses/:
      •   campaigns_*.json
      •   relationships_*.json
      •   <entity_type>_*.json
    - Verifies the expected log messages and orchestration results.
    """
    # Given an orchestrator with test configuration and logging setup
    orchestrator = _given_orchestrator_with_test_setup(gti_config, caplog)

    # When the campaign orchestration workflow is executed
    await _when_campaign_orchestration_executed(orchestrator)

    # Then the orchestration should complete successfully with expected results and logs
    _then_orchestration_completed_successfully(caplog, expected_campaign_log_messages)


@pytest.mark.asyncio
@pytest.mark.order(2)
async def test_full_orchestration_vulnerabilities_no_software(
    caplog: Any,
    gti_config: DummyConfig,
    expected_vulnerability_log_messages_no_software: list[str],
) -> None:
    """Test the full vulnerability orchestration workflow with get_related_softwares disabled.

    This test verifies that when vulnerability_get_related_softwares is False,
    no software objects are created from CPE data.
    """
    # Given an orchestrator with test configuration and software disabled
    gti_config.vulnerability_get_related_softwares = False
    orchestrator = _given_orchestrator_with_test_setup(gti_config, caplog)

    # When the vulnerability orchestration workflow is executed
    await _when_vulnerability_orchestration_executed(orchestrator)

    # Then the orchestration should complete successfully without software entities
    _then_orchestration_completed_successfully(
        caplog, expected_vulnerability_log_messages_no_software
    )


# =====================
# GWT Gherkin-style functions
# =====================


# Given an orchestrator with test configuration and logging setup
def _given_orchestrator_with_test_setup(gti_config: DummyConfig, caplog: Any) -> Any:
    """Set up the orchestrator with test configuration and logging."""
    fake_wm = FakeWorkManager()

    logger = logging.getLogger("test_orchestrate_all")
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


# When the orchestration workflow is executed
async def _when_orchestration_executed(orchestrator: Any) -> Any:
    """Execute the orchestration workflow."""
    result = await orchestrator.run_report(initial_state=None)
    return result


# When the threat actor orchestration workflow is executed
async def _when_threat_actor_orchestration_executed(orchestrator: Any) -> Any:
    """Execute the threat actor orchestration workflow."""
    result = await orchestrator.run_threat_actor(initial_state=None)
    return result


# When the malware family orchestration workflow is executed
async def _when_malware_family_orchestration_executed(orchestrator: Any) -> Any:
    """Execute the malware family orchestration workflow."""
    result = await orchestrator.run_malware_family(initial_state=None)
    return result


# When the vulnerability orchestration workflow is executed
async def _when_vulnerability_orchestration_executed(orchestrator: Any) -> Any:
    """Execute the vulnerability orchestration workflow."""
    result = await orchestrator.run_vulnerability(initial_state=None)
    return result


# When the campaign orchestration workflow is executed
async def _when_campaign_orchestration_executed(orchestrator: Any) -> Any:
    """Execute the campaign orchestration workflow."""
    result = await orchestrator.run_campaign(initial_state=None)
    return result


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


# =====================
# Helper Functions
# =====================


def _load_debug_responses(debug_folder: Path) -> dict[str, Any]:
    """Load all debug response files and return as dictionary."""
    response_types = [
        "main_reports",
        "main_threat_actors",
        "main_malware_families",
        "main_vulnerabilities",
        "main_campaigns",
        "reports",
        "relationships",
        "attack_techniques",
        "vulnerabilities",
        "malware_families",
        "threat_actors",
        "campaigns",
        "domains",
        "files",
        "urls",
        "ip_addresses",
    ]

    response_data = {}

    for response_type in response_types:
        files = sorted(debug_folder.glob(f"{response_type}_*.json"))
        assert (  # noqa: S101
            len(files) == 1
        ), f"Expected exactly one {response_type}_*.json under {debug_folder}, got {len(files)}"

        data = json.loads(files[0].read_text(encoding="utf-8"))
        response_data[response_type] = data.get("response", data)

    return response_data

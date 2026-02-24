import json
import os
import sys
from dataclasses import asdict
from unittest.mock import patch

import pytest

from .factories import (
    AnalysisResponseFactory,
    DomainNameEnrichmentFactory,
    DomainResponseFactory,
    DownloadedFilesResponseFactory,
    FileEnrichmentFactory,
    HashClassificationFactory,
    Ipv4EnrichmentFactory,
    ReportIntelligenceResponseFactory,
    ReportResponseFactory,
    ResolutionResponseFactory,
    UploadDetailFactory,
    UrlEnrichmentFactory,
    UrlsResponseFactory,
)

sys.path.append(os.path.join(os.path.dirname(__file__), "..", "src"))


@pytest.fixture(autouse=True)
def correct_config():
    with patch(
        "os.environ",
        {
            "OPENCTI_URL": "http://url",
            "OPENCTI_TOKEN": "token",
            "CONNECTOR_ID": "connector_id",
            "CONNECTOR_NAME": "connector_name",
            "CONNECTOR_TYPE": "INTERNAL_ENRICHMENT",
            "CONNECTOR_LOG_LEVEL": "error",
            "CONNECTOR_SCOPE": "scope",
            "REVERSINGLABS_SPECTRA_ANALYZE_URL": "http://api",
            "REVERSINGLABS_SPECTRA_ANALYZE_TOKEN": "token",
            "REVERSINGLABS_MAX_TLP": "TLP:WHITE",
            "REVERSINGLABS_CLOUD_ANALYSIS": "false",
            "REVERSINGLABS_SANDBOX_OS": "windows11",
        },
    ):
        yield


@pytest.fixture(autouse=True)
def health_check_mock():
    with patch("pycti.OpenCTIApiClient.health_check", return_value=True):
        yield


@pytest.fixture(autouse=True)
def connector_register_mock():
    with patch(
        "pycti.OpenCTIApiConnector.register",
        return_value={
            "id": "connector_id",
            "connector_user_id": "1",
            "connector_state": "{}",
            "config": {
                "connection": {
                    "host": "rabbitmq",
                    "vhost": "/",
                    "use_ssl": False,
                    "port": 5672,
                    "user": "opencti",
                    "pass": "changeme",
                }
            },
            "jwks": {},
        },
    ):
        yield


@pytest.fixture(autouse=True)
def identity_create_mock():
    with patch(
        "pycti.Identity.create",
        return_value={
            "id": "identity_id",
            "type": "Organization",
            "standard_id": "identity--683c6912-757d-527e-ae38-3eb7f7fa2124",
        },
    ):
        yield


@pytest.fixture(autouse=True)
def connector_ping_mock():
    with patch(
        "pycti.OpenCTIApiConnector.ping",
        return_value={"connector_state": '{"last_run": "2024-01-01T00:00:00Z"}'},
    ):
        yield


@pytest.fixture(autouse=True)
def work_initiate_mock():
    with patch(
        "pycti.OpenCTIApiWork.initiate_work", return_value={"id": "work_id_123"}
    ):
        yield


@pytest.fixture(autouse=True)
def to_processed_mock():
    with patch("pycti.OpenCTIApiWork.to_processed", return_value=True):
        yield


@pytest.fixture
def file_enrichment_message():
    yield asdict(FileEnrichmentFactory())


@pytest.fixture
def detailed_report_response():
    report = ReportIntelligenceResponseFactory()
    with patch("ReversingLabs.SDK.a1000.A1000.get_detailed_report_v2") as mock_report:
        mock_report.return_value.status_code = 200
        mock_report.return_value.text = json.dumps(
            {
                "count": 1,
                "next": None,
                "previous": None,
                "results": [asdict(report)],
            }
        )
        yield report


@pytest.fixture(autouse=True)
def cyber_observable_update_field_mock():
    with patch("pycti.StixCyberObservable.update_field", return_value=True):
        yield


@pytest.fixture(autouse=True)
def cyber_observable_add_label_mock():
    with patch("pycti.StixCyberObservable.add_label", return_value=True):
        yield


@pytest.fixture(autouse=True)
def label_create_mock():
    with patch("pycti.Label.create", return_value={"id": "label_id"}):
        yield


@pytest.fixture
def url_enrichment_message():
    yield asdict(UrlEnrichmentFactory())


@pytest.fixture
def network_url_report_response():
    with patch("ReversingLabs.SDK.a1000.A1000.network_url_report") as mock_analysis:
        analysis = AnalysisResponseFactory()
        mock_analysis.return_value.json = lambda: analysis.to_dict()
        yield analysis


@pytest.fixture
def submit_url_for_analysis_response():
    with patch("ReversingLabs.SDK.a1000.A1000.submit_url_for_analysis") as mock_submit:
        detail = UploadDetailFactory()
        mock_submit.return_value.text = json.dumps(
            {
                "code": 201,
                "message": "Done.",
                "detail": asdict(detail),
            }
        )
        yield detail


@pytest.fixture
def check_submitted_url_status_response():
    with patch(
        "ReversingLabs.SDK.a1000.A1000.check_submitted_url_status"
    ) as mock_status:
        report = ReportIntelligenceResponseFactory()
        mock_status.return_value.text = json.dumps(
            {
                "processing_status": "complete",
                "message": "Processing complete.",
                "report": asdict(report),
            }
        )
        yield report


@pytest.fixture
def get_classification_v3_response():
    with patch(
        "ReversingLabs.SDK.a1000.A1000.get_classification_v3"
    ) as mock_classification:
        classification = HashClassificationFactory()
        mock_classification.return_value.text = json.dumps(asdict(classification))
        yield classification


@pytest.fixture
def ipv4_enrichment_message():
    yield asdict(Ipv4EnrichmentFactory())


@pytest.fixture
def network_files_from_ip_aggregated_response():
    with patch(
        "ReversingLabs.SDK.a1000.A1000.network_files_from_ip_aggregated"
    ) as mock_download:
        downloaded_files = DownloadedFilesResponseFactory()
        mock_download.return_value = asdict(downloaded_files)["downloaded_files"]
        yield downloaded_files


@pytest.fixture
def network_ip_addr_report_response():
    with patch("ReversingLabs.SDK.a1000.A1000.network_ip_addr_report") as mock_report:
        report = ReportResponseFactory()
        mock_report.return_value.json = lambda: asdict(report)
        yield report


@pytest.fixture
def network_ip_to_domain_aggregated_response():
    with patch(
        "ReversingLabs.SDK.a1000.A1000.network_ip_to_domain_aggregated"
    ) as mock_domain:
        resolution = ResolutionResponseFactory()
        mock_domain.return_value = asdict(resolution)["resolutions"]
        yield resolution


@pytest.fixture
def network_domain_report_response():
    with patch("ReversingLabs.SDK.a1000.A1000.network_domain_report") as mock_domain:
        domain = DomainResponseFactory()
        mock_domain.return_value.json = lambda: asdict(domain)
        yield domain


@pytest.fixture
def network_urls_from_ip_aggregated_response():
    with patch(
        "ReversingLabs.SDK.a1000.A1000.network_urls_from_ip_aggregated"
    ) as mock_domain:
        urls = UrlsResponseFactory()
        mock_domain.return_value = asdict(urls)["urls"]
        yield urls


@pytest.fixture
def domain_name_enrichment_message():
    yield asdict(DomainNameEnrichmentFactory())

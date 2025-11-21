import json
import os
import sys
from dataclasses import asdict
from unittest.mock import patch

import pytest

from .factories import FileEnrichmentFactory, ReportIntelligenceResponseFactory

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
            "REVERSINGLABS_SANDBOX_OS:": "windows10",
            "REVERSINGLABS_CREATE_INDICATORS": "true",
            "REVERSINGLABS_CLOUD_ANALYSIS": "false",
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

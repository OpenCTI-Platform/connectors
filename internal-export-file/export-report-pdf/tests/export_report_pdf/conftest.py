import os
from copy import deepcopy
from typing import Any
from unittest.mock import MagicMock, Mock

import pytest
from pytest_mock import MockerFixture


@pytest.fixture(name="config_dict")
def fixture_config_dict() -> dict[str, Any]:
    return {
        "opencti": {
            "url": "opencti-url",
            "token": "opencti-token",
        },
        "connector": {
            "id": "export-report-pdf-connector-id",
            "type": "INTERNAL_EXPORT_FILE",
            "name": "ExportReportPdf",
            "scope": "application/pdf",
            "confidence_level": 100,
            "log_level": "info",
        },
        "export_report_pdf": {
            "primary_color": "#ff8c00",
            "secondary_color": "#000000",
            "company_address_line_1": "Company Address Line 1",
            "company_address_line_2": "Company Address Line 2",
            "company_address_line_3": "Company Address Line 3",
            "company_phone_number": "+1-234-567-8900",
            "company_email": "export-report-pdf@email.com",
            "company_website": "https://export-report-pdf.com",
            "indicators_only": False,
            "defang_urls": True,
        },
    }


@pytest.fixture(name="mock_config")
def mock_config(mocker: MockerFixture, config_dict: dict[str, Any]) -> None:
    environ = deepcopy(os.environ)
    for key, value in config_dict.items():
        for sub_key, sub_value in value.items():
            if sub_value is not None:
                environ[f"{key.upper()}_{sub_key.upper()}"] = str(sub_value)
    mocker.patch("os.environ", environ)


@pytest.fixture(name="mocked_helper")
def fixture_mocked_helper(mocker: MockerFixture) -> Mock:
    helper = mocker.patch("pycti.OpenCTIConnectorHelper", MagicMock())
    # helper.connect_id = "test-connector-id"
    # helper.connect_name = "Test Connector"
    # helper.api.work.initiate_work.return_value = "work-id"
    # helper.get_state.return_value = {}
    # helper.stix2_create_bundle.return_value = "bundle"
    return helper

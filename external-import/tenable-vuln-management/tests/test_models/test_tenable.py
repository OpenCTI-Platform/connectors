"""
Test Tenable API Response model.

Notes:
    This uses example responses from https://developer.tenable.com/reference/exports-vulns-download-chunk [consulted on
        September 26th, 2024]
"""

import json
import sys
from pathlib import Path

import pytest

sys.path.append(str((Path(__file__).resolve().parent.parent.parent / "src")))

from tenable_vuln_management.models.common import ValidationWarning
from tenable_vuln_management.models.tenable import (
    VulnerabilityFinding,
    _convert_empty_dicts_and_lists_to_none,
)

BASE_DIR = Path(__file__).parent
RESPONSE_FILE = BASE_DIR / "resources" / "tenable_api_response.json"


def load_responses():
    # Load the JSON file
    with open(RESPONSE_FILE, "r") as file:
        responses = json.load(file)
    return responses


@pytest.mark.parametrize(
    "tenable_api_response_1_report",
    [
        pytest.param(raw_report, id=raw_report["plugin"]["name"])
        for raw_report in load_responses()
    ],
)
def test_vulnerability_finding_model_is_compatible_with_tenable_api_doc(
    tenable_api_response_1_report,
):
    # Given a tenable api response
    # When instantiating a vulnerability_finding
    # Then no pydantic issue is raised
    _ = VulnerabilityFinding.model_validate(tenable_api_response_1_report)


def test__convert_empty_dicts_and_lists_to_none_should_clean_nested_empty_dicts():
    # Given a tenable api response boby like dictionary
    to_clean = {"a": {"b": {}, "c": [1, {"e": {}, "f": []}]}}
    # When using the cleaning method
    cleaned = _convert_empty_dicts_and_lists_to_none(to_clean)
    # Then it should be cleaned
    assert cleaned == {"a": {"b": None, "c": [1, {"e": None, "f": None}]}}


@pytest.mark.parametrize(
    "tenable_api_response_1_report",
    [
        pytest.param(raw_report, id=raw_report["plugin"]["name"])
        for raw_report in load_responses()
    ],
)
def test_extra_field_in_resposnse_should_warn_with_ValidationWarning(
    tenable_api_response_1_report,
):
    # Given a tenable api response with an "extra" field
    # When instantiating a vulnerability_finding
    # Then A ValidationWarning is raised

    tenable_api_response_1_report["extra"] = "extra_value"

    with pytest.warns(ValidationWarning):
        _ = VulnerabilityFinding.model_validate(tenable_api_response_1_report)

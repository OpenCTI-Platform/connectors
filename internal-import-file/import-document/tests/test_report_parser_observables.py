from pathlib import Path
from unittest.mock import MagicMock

import pytest
from reportimporter.constants import RESULT_FORMAT_CATEGORY
from reportimporter.core import ReportImporter
from reportimporter.models import Observable
from reportimporter.report_parser import ReportParser


def _build_parser() -> ReportParser:
    config_path = (
        Path(__file__).resolve().parent.parent
        / "src"
        / "reportimporter"
        / "config"
        / "observable_config.ini"
    )
    observables = ReportImporter._parse_config(str(config_path), Observable)
    return ReportParser(
        helper=MagicMock(),
        entity_list=[],
        observable_list=observables,
    )


@pytest.mark.parametrize(
    "address",
    [
        # RFC 5737 documentation ranges.
        "192.0.2.123",
        "198.51.100.42",
        "203.0.113.42",
        # Public IPv4 controls.
        "1.1.1.1",
        "1.2.3.4",
    ],
)
def test_valid_ipv4_address_is_not_reclassified_as_phone_number(address):
    result = _build_parser().parse(f"Observed traffic from {address}.")

    assert result[address][RESULT_FORMAT_CATEGORY] == "IPv4-Addr.value"


def test_filtered_ipv4_address_is_not_reclassified_as_phone_number():
    address = "8.8.8.8"
    result = _build_parser().parse(f"Observed traffic from {address}.")

    assert address not in result


@pytest.mark.parametrize(
    "phone_number",
    [
        # ACMA fictional-use number
        "0491 570 006",
        "+61 491 570 006",
    ],
)
def test_phone_number_is_still_classified_as_phone_number(phone_number):
    result = _build_parser().parse(f"Call {phone_number} for assistance.")

    assert result[phone_number][RESULT_FORMAT_CATEGORY] == "Phone-Number.value"

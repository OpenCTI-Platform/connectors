"""
Regression tests for residual Phone-Number false positives and lost IPv4
addresses in the report parser (follow-up to #6677 / #7622).

Each test describes the EXPECTED behaviour. They are marked ``xfail`` with
``strict=True`` until the parser is fixed: CI stays green, and as soon as a
fix makes a test pass, the unexpected pass fails the run so that the marker
must be removed together with the fix.

See https://github.com/OpenCTI-Platform/connectors/issues/8253
"""

import ipaddress
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from pdfminer.layout import LTTextContainer
from reportimporter.constants import MIME_PDF, RESULT_FORMAT_CATEGORY
from reportimporter.core import ReportImporter
from reportimporter.models import Observable
from reportimporter.report_parser import ReportParser

PHONE = "Phone-Number.value"
IPV4 = "IPv4-Addr.value"

pytestmark = pytest.mark.xfail(
    strict=True,
    reason="Known IPv4 / Phone-Number extraction corner cases, see issue #8253",
)


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


def _values_of(result, category):
    return [k for k, v in result.items() if v[RESULT_FORMAT_CATEGORY] == category]


# ---------------------------------------------------------------------------
# Case 1: zero-padded IPv4 addresses (e.g. firewall exports)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "padded, canonical",
    [
        ("203.000.113.042", "203.0.113.42"),
        ("198.051.100.234", "198.51.100.234"),
    ],
)
def test_zero_padded_ipv4_is_not_reclassified_as_phone_number(padded, canonical):
    result = _build_parser().parse(f"C2 at {padded} observed.")

    assert _values_of(result, PHONE) == []


@pytest.mark.parametrize(
    "padded, canonical",
    [
        ("203.000.113.042", "203.0.113.42"),
        ("198.051.100.234", "198.51.100.234"),
    ],
)
def test_zero_padded_ipv4_is_still_extracted_as_ipv4(padded, canonical):
    result = _build_parser().parse(f"C2 at {padded} observed.")

    extracted = [ipaddress.IPv4Address(v) for v in _values_of(result, IPV4)]
    assert ipaddress.IPv4Address(canonical) in extracted


# ---------------------------------------------------------------------------
# Case 2: dotted quads with an invalid octet (not an IP, not a phone)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("bogus", ["999.168.1.10", "198.51.100.256"])
def test_dotted_quad_with_invalid_octet_is_not_a_phone_number(bogus):
    result = _build_parser().parse(f"Bogus {bogus} seen.")

    assert _values_of(result, PHONE) == []


# ---------------------------------------------------------------------------
# Case 3: dates, timestamps, version numbers and plain numbers
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "text",
    [
        "Seen on 2026-11-04 12:34:56 by the sensor.",
        "Seen on 2026.11.04 12:34:56 by the sensor.",
        "Connector version 7.260907.0 deployed.",
        "2026-11-04 12:34:56 203.0.113.42 GET /x 200 1234",
        "Transaction id 1234567890123 completed.",
    ],
)
def test_dates_versions_and_plain_numbers_are_not_phone_numbers(text):
    result = _build_parser().parse(text)

    assert _values_of(result, PHONE) == []


# ---------------------------------------------------------------------------
# Case 4: PDF lines are joined without a separator, merging adjacent IPs
# ---------------------------------------------------------------------------


def _fake_text_container(text: str):
    container = MagicMock(spec=LTTextContainer)
    container.get_text.return_value = text
    return container


def test_pdf_ipv4_on_consecutive_lines_are_all_extracted(tmp_path):
    addresses = ["194.213.18.38", "45.33.32.156", "104.16.132.229"]
    # pdfminer returns one "\n"-terminated line per row, no trailing spaces
    page = [_fake_text_container("".join(f"{a}\n" for a in addresses))]
    pdf_path = tmp_path / "iocs.pdf"
    pdf_path.write_bytes(b"%PDF-1.4\n%%EOF\n")

    with patch("reportimporter.report_parser.extract_pages", return_value=[page]):
        result = _build_parser().run_raw_parser(str(pdf_path), MIME_PDF)

    assert sorted(_values_of(result, IPV4)) == sorted(addresses)
    assert _values_of(result, PHONE) == []

import pytest
from src.services.converter.const import CVSS2_MAPPING, CVSS40_MAPPING
from src.services.utils.cpe_parser import parse_cpe_uri


def test_cvss_v2_and_v4_vector_strings_are_mapped():
    assert CVSS2_MAPPING["x_opencti_cvss_v2_vector_string"] == "vectorString"
    assert CVSS40_MAPPING["x_opencti_cvss_v4_vector_string"] == "vectorString"


def test_parse_cpe23_with_escaped_colons():
    parsed = parse_cpe_uri(r"cpe:2.3:a:ven\:dor:prod\:uct:1.0\:beta:*:*:*:*:*:*:*")
    assert parsed == {
        "part": "a",
        "vendor": r"ven\:dor",
        "product": r"prod\:uct",
        "version": r"1.0\:beta",
    }


def test_parse_cpe23_plain():
    parsed = parse_cpe_uri("cpe:2.3:o:vendor:product:1.0:*:*:*:*:*:*:*")
    assert (parsed["vendor"], parsed["product"], parsed["version"]) == (
        "vendor",
        "product",
        "1.0",
    )


def test_parse_cpe23_missing_component_raises():
    with pytest.raises(ValueError):
        parse_cpe_uri("cpe:2.3:a:vendor")

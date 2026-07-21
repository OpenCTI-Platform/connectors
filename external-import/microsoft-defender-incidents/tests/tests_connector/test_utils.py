import stix2
from connector.utils import (
    CASE_INCIDENT_PRIORITIES,
    detect_ip_version,
    find_matching_file_ids,
    format_date,
    format_datetime,
)


def test_detect_ip_version_ipv4():
    assert detect_ip_version("192.168.1.1") == "ipv4"


def test_detect_ip_version_ipv4_with_cidr():
    assert detect_ip_version("10.0.0.0/24") == "ipv4"


def test_detect_ip_version_ipv4_boundary():
    assert detect_ip_version("255.255.255.255") == "ipv4"


def test_detect_ip_version_ipv6():
    assert detect_ip_version("2001:db8::1") == "ipv6"


def test_detect_ip_version_ipv6_full():
    assert detect_ip_version("fe80::1") == "ipv6"


def test_format_datetime_with_valid_utc_date():
    result = format_datetime("2024-01-15T10:30:00+00:00")
    assert result == "2024-01-15T10:30:00Z"


def test_format_datetime_strips_microseconds():
    result = format_datetime("2024-01-15T10:30:00.123456+00:00")
    assert "." not in result
    assert result.endswith("Z")


def test_format_datetime_with_none():
    result = format_datetime(None)
    assert result.endswith("Z")
    assert "T" in result


def test_format_datetime_with_empty_string():
    result = format_datetime("   ")
    assert result.endswith("Z")


def test_format_datetime_preserves_non_utc_offset():
    result = format_datetime("2024-06-01T12:00:00+05:30")
    assert result == "2024-06-01T12:00:00+05:30"


def test_format_date_returns_int():
    result = format_date("2024-01-15T10:30:00Z")
    assert isinstance(result, int)
    assert result > 0


def test_format_date_consistent_value():
    result1 = format_date("2024-01-15T10:30:00Z")
    result2 = format_date("2024-01-15T10:30:00Z")
    assert result1 == result2


def test_find_matching_file_ids_with_match():
    stix_file = stix2.File(hashes={"MD5": "a" * 32}, name="malware.exe")
    result = find_matching_file_ids("malware.exe", [stix_file])
    assert len(result) == 1
    assert result[0] is stix_file


def test_find_matching_file_ids_no_name_match():
    stix_file = stix2.File(hashes={"MD5": "a" * 32}, name="other.exe")
    result = find_matching_file_ids("malware.exe", [stix_file])
    assert result == []


def test_find_matching_file_ids_empty_list():
    result = find_matching_file_ids("malware.exe", [])
    assert result == []


def test_find_matching_file_ids_non_file_objects():
    url = stix2.URL(value="http://example.com")
    result = find_matching_file_ids("malware.exe", [url])
    assert result == []


def test_find_matching_file_ids_mixed_objects():
    stix_file = stix2.File(hashes={"MD5": "a" * 32}, name="malware.exe")
    url = stix2.URL(value="http://example.com")
    result = find_matching_file_ids("malware.exe", [url, stix_file])
    assert len(result) == 1


def test_case_incident_priorities_high():
    assert CASE_INCIDENT_PRIORITIES["high"] == "P1"


def test_case_incident_priorities_medium():
    assert CASE_INCIDENT_PRIORITIES["medium"] == "P2"


def test_case_incident_priorities_low():
    assert CASE_INCIDENT_PRIORITIES["low"] == "P3"


def test_case_incident_priorities_informational():
    assert CASE_INCIDENT_PRIORITIES["informational"] == "P4"


def test_case_incident_priorities_unknown():
    assert CASE_INCIDENT_PRIORITIES["unknown"] == "P3"

import pytest
from internal_enrichment_connector.cim_parser import CIM_TO_STIX_MAP, CIMParser


def test_parse_ip_fields():
    parser = CIMParser()
    row = {"src_ip": "10.0.0.1", "dest_ip": "8.8.8.8"}

    observables = parser.parse_row(row)

    assert len(observables) == 2
    assert observables[0].stix_type == "IPv4-Addr"
    assert observables[1].stix_type == "IPv4-Addr"


def test_skip_metadata_fields():
    parser = CIMParser()
    row = {
        "action": "allowed",
        "vendor_product": "Palo Alto",
        "sourcetype": "cisco:asa",
    }

    assert parser.parse_row(row) == []


def test_skip_empty_values():
    parser = CIMParser()
    row = {
        "src_ip": "",
        "dest_ip": None,
        "url": "   ",
        "src_dns": "-",
        "dest_dns": "unknown",
        "user": "N/A",
        "src_user": "null",
        "dest_user": "none",
    }

    assert parser.parse_row(row) == []


def test_dedup_across_rows():
    parser = CIMParser()
    rows = [{"src_ip": "10.0.0.1"}, {"dest_ip": "10.0.0.1"}]

    observables = parser.parse_results(rows)
    assert len(observables) == 1
    assert observables[0].value == "10.0.0.1"


def test_required_cim_fields_present_in_mapping():
    required = {
        "src_ip",
        "dest_ip",
        "src_host",
        "dest_host",
        "http_user_agent",
        "src_dns",
        "dest_dns",
        "url",
        "uri_path",
        "uri_query",
        "user",
        "src_user",
        "dest_user",
        "src_mac",
        "dest_mac",
        "file_name",
        "file_path",
        "file_hash",
        "md5",
        "sha1",
        "sha256",
        "sha512",
        "process_name",
        "process_path",
        "process",
        "app",
        "email_src",
        "email_dst",
        "src_email",
        "dest_email",
        "sourcetype",
        "src",
        "dest",
        "host",
    }
    assert required.issubset(set(CIM_TO_STIX_MAP.keys()))


@pytest.mark.parametrize(
    ("field", "expected_type", "expected_property"),
    [
        ("src_dns", "Domain-Name", "value"),
        ("dest_dns", "Domain-Name", "value"),
        ("src_host", "Hostname", "value"),
        ("dest_host", "Hostname", "value"),
        ("url", "Url", "value"),
        ("uri_path", "Url", "value"),
        ("uri_query", "Url", "value"),
        ("user", "User-Account", "account_login"),
        ("src_user", "User-Account", "account_login"),
        ("dest_user", "User-Account", "account_login"),
        ("src_mac", "Mac-Addr", "value"),
        ("dest_mac", "Mac-Addr", "value"),
        ("process_name", "Process", "name"),
        ("process_path", "Process", "command_line"),
        ("process", "Process", "command_line"),
        ("app", "Software", "name"),
        ("email_src", "Email-Addr", "value"),
        ("email_dst", "Email-Addr", "value"),
        ("src_email", "Email-Addr", "value"),
        ("dest_email", "Email-Addr", "value"),
    ],
)
def test_static_field_mappings(field, expected_type, expected_property):
    parser = CIMParser()
    observables = parser.parse_row({field: "test-value"})

    assert len(observables) == 1
    assert observables[0].stix_type == expected_type
    assert observables[0].stix_property == expected_property
    assert observables[0].source_field == field


def test_unknown_fields_ignored():
    parser = CIMParser()
    row = {"totally_unknown": "foo", "another_weird": "bar"}

    assert parser.parse_row(row) == []


def test_user_agent_field():
    parser = CIMParser()
    row = {"http_user_agent": "Mozilla/5.0"}

    observables = parser.parse_row(row)
    assert len(observables) == 1
    assert observables[0].stix_type == "User-Agent"


def test_file_hash_aggregation_single_object():
    parser = CIMParser()
    row = {
        "md5": "a" * 32,
        "sha256": "b" * 64,
        "file_name": "malware.exe",
        "file_path": "/tmp/malware.exe",
    }

    observables = parser.parse_row(row)
    assert len(observables) == 1
    assert observables[0].stix_type == "StixFile"
    assert observables[0].stix_property == "object"
    assert observables[0].value["name"] == "malware.exe"
    assert observables[0].value["path"] == "/tmp/malware.exe"
    assert observables[0].value["hashes"] == {
        "MD5": "a" * 32,
        "SHA-256": "b" * 64,
    }


@pytest.mark.parametrize(
    ("field", "value", "expected_type"),
    [
        ("src", "1.2.3.4", "IPv4-Addr"),
        ("src", "2001:db8::1", "IPv6-Addr"),
        ("src", "example.org", "Domain-Name"),
        ("src", "my-host-01", "Hostname"),
        ("dest", "2.3.4.5", "IPv4-Addr"),
        ("dest", "2001:db8::2", "IPv6-Addr"),
        ("dest", "api.example.org", "Domain-Name"),
        ("dest", "workstation01", "Hostname"),
    ],
)
def test_polymorphic_src_dest_fields(field, value, expected_type):
    parser = CIMParser()
    observables = parser.parse_row({field: value})

    assert len(observables) == 1
    assert observables[0].stix_type == expected_type


def test_host_endpoint_sourcetype_creates_hostname():
    parser = CIMParser()
    row = {"host": "endpoint-a", "sourcetype": "WinEventLog:Security"}

    observables = parser.parse_row(row)
    assert len(observables) == 1
    assert observables[0].source_field == "host"
    assert observables[0].stix_type == "Hostname"


def test_host_network_device_sourcetype_skipped():
    parser = CIMParser()
    row = {"host": "fw-01", "sourcetype": "pan:traffic"}

    observables = parser.parse_row(row)
    assert observables == []


def test_host_unknown_sourcetype_falls_back_to_polymorphic():
    parser = CIMParser()
    row = {"host": "203.0.113.10", "sourcetype": "unknown:source"}

    observables = parser.parse_row(row)
    assert len(observables) == 1
    assert observables[0].stix_type == "IPv4-Addr"


def test_dedup_src_and_src_ip_same_value_single_observable():
    parser = CIMParser()
    row = {"src": "1.1.1.1", "src_ip": "1.1.1.1"}

    observables = parser.parse_row(row)
    assert len(observables) == 1
    assert observables[0].stix_type == "IPv4-Addr"
    assert observables[0].value == "1.1.1.1"


def test_skip_private_ips_flag_disabled_by_default():
    parser = CIMParser()
    row = {"src_ip": "10.10.10.10"}

    observables = parser.parse_row(row)
    assert len(observables) == 1
    assert observables[0].value == "10.10.10.10"


def test_skip_private_ips_flag_enabled():
    parser = CIMParser(skip_private_ips=True)
    row = {"src_ip": "10.10.10.10", "dest_ip": "8.8.8.8"}

    observables = parser.parse_row(row)
    assert len(observables) == 1
    assert observables[0].value == "8.8.8.8"

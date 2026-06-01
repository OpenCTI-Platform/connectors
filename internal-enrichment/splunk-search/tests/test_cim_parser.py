from internal_enrichment_connector.cim_parser import CIMParser, CIM_TO_STIX_MAP


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
    row = {"src_ip": "", "dest_ip": None, "url": "   "}

    assert parser.parse_row(row) == []


def test_dedup_across_rows():
    parser = CIMParser()
    rows = [{"src_ip": "10.0.0.1"}, {"dest_ip": "10.0.0.1"}]

    observables = parser.parse_results(rows)
    assert len(observables) == 1
    assert observables[0].value == "10.0.0.1"


def test_all_cim_fields_mapped():
    parser = CIMParser()
    row = {
        key: "value"
        for key in CIM_TO_STIX_MAP
        if CIM_TO_STIX_MAP[key] is not None
    }

    observables = parser.parse_row(row)
    assert len(observables) == len([k for k, v in CIM_TO_STIX_MAP.items() if v is not None])


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


def test_file_hash_field():
    parser = CIMParser()
    row = {"file_hash": "a" * 64}

    observables = parser.parse_row(row)
    assert len(observables) == 1
    assert observables[0].stix_type == "StixFile"
    assert observables[0].stix_property == "hashes"

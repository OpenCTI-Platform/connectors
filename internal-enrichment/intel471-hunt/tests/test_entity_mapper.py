from src import entity_mapper


def test_intrusion_set_uses_actors_filter():
    entity = {"entity_type": "Intrusion-Set", "name": "TeamPCP", "aliases": []}
    assert entity_mapper.build_query(entity) == [{"actors": ["TeamPCP"]}]


def test_threat_actor_also_uses_actors_filter():
    entity = {"entity_type": "Threat-Actor", "name": "Some Actor"}
    assert entity_mapper.build_query(entity) == [{"actors": ["Some Actor"]}]


def test_threat_actor_group_uses_actors_filter():
    entity = {"entity_type": "Threat-Actor-Group", "name": "TeamPCP"}
    assert entity_mapper.build_query(entity) == [{"actors": ["TeamPCP"]}]


def test_threat_actor_individual_uses_actors_filter():
    entity = {"entity_type": "Threat-Actor-Individual", "name": "John Doe"}
    assert entity_mapper.build_query(entity) == [{"actors": ["John Doe"]}]


def test_aliases_are_included():
    entity = {
        "entity_type": "Intrusion-Set",
        "name": "TeamPCP",
        "aliases": ["PCP", "TeamPCP"],
    }
    assert entity_mapper.build_query(entity) == [{"actors": ["TeamPCP", "PCP"]}]


def test_campaign_uses_campaigns_filter():
    entity = {"entity_type": "Campaign", "name": "Shai-Hulud 2.0"}
    assert entity_mapper.build_query(entity) == [{"campaigns": ["Shai-Hulud 2.0"]}]


def test_attack_pattern_prefers_mitre_id():
    entity = {
        "entity_type": "Attack-Pattern",
        "name": "JavaScript",
        "x_mitre_id": "T1059.007",
    }
    assert entity_mapper.build_query(entity) == [{"mitre_technique_ids": ["T1059.007"]}]


def test_attack_pattern_uses_external_reference_when_no_x_mitre_id():
    entity = {
        "entity_type": "Attack-Pattern",
        "name": "JavaScript",
        "external_references": [
            {"source_name": "mitre-attack", "external_id": "T1059.007"},
        ],
    }
    assert entity_mapper.build_query(entity) == [{"mitre_technique_ids": ["T1059.007"]}]


def test_attack_pattern_falls_back_to_name():
    entity = {"entity_type": "Attack-Pattern", "name": "JavaScript"}
    assert entity_mapper.build_query(entity) == [
        {"mitre_technique_names": ["JavaScript"]}
    ]


def test_attack_pattern_recognises_mitre_id_in_name_field():
    """When the name itself is a T-id (e.g. user types `--entity-name T1027`),
    treat it as the MITRE id, not as a technique name."""
    entity = {"entity_type": "Attack-Pattern", "name": "T1027"}
    assert entity_mapper.build_query(entity) == [{"mitre_technique_ids": ["T1027"]}]


def test_attack_pattern_subtechnique_id_in_name_field():
    entity = {"entity_type": "Attack-Pattern", "name": "t1059.007"}
    assert entity_mapper.build_query(entity) == [{"mitre_technique_ids": ["T1059.007"]}]


def test_vulnerability_uses_exploit_or_vulns():
    entity = {"entity_type": "Vulnerability", "name": "CVE-2024-12345"}
    assert entity_mapper.build_query(entity) == [
        {"exploit_or_vulns": ["CVE-2024-12345"]}
    ]


def test_malware_uses_threat_names():
    entity = {"entity_type": "Malware", "name": "Shai-Hulud"}
    assert entity_mapper.build_query(entity) == [{"threat_names": ["Shai-Hulud"]}]


def test_tool_uses_tools_filter():
    entity = {"entity_type": "Tool", "name": "Cobalt Strike"}
    assert entity_mapper.build_query(entity) == [{"tools": ["Cobalt Strike"]}]


def test_sector_uses_target_industries():
    entity = {"entity_type": "Sector", "name": "Financial Services"}
    assert entity_mapper.build_query(entity) == [
        {"target_industries": ["Financial Services"]}
    ]


def test_country_fans_out_to_target_and_source():
    entity = {"entity_type": "Country", "name": "China"}
    assert entity_mapper.build_query(entity) == [
        {"target_countries": ["China"]},
        {"source_countries": ["China"]},
    ]


def test_region_fans_out_to_target_and_source():
    entity = {"entity_type": "Region", "name": "Eastern Asia"}
    assert entity_mapper.build_query(entity) == [
        {"target_regions": ["Eastern Asia"]},
        {"source_regions": ["Eastern Asia"]},
    ]


def test_generic_location_country_subtype():
    entity = {
        "entity_type": "Location",
        "name": "Germany",
        "x_opencti_location_type": "Country",
    }
    assert entity_mapper.build_query(entity) == [
        {"target_countries": ["Germany"]},
        {"source_countries": ["Germany"]},
    ]


def test_generic_location_region_subtype():
    entity = {
        "entity_type": "Location",
        "name": "Asia",
        "x_opencti_location_type": "Region",
    }
    assert entity_mapper.build_query(entity) == [
        {"target_regions": ["Asia"]},
        {"source_regions": ["Asia"]},
    ]


def test_location_city_subtype_unsupported():
    entity = {
        "entity_type": "Location",
        "name": "Berlin",
        "x_opencti_location_type": "City",
    }
    assert entity_mapper.build_query(entity) is None


def test_unsupported_entity_returns_none():
    assert entity_mapper.build_query({"entity_type": "Channel", "name": "X"}) is None


def test_no_name_returns_none():
    assert entity_mapper.build_query({"entity_type": "Intrusion-Set"}) is None


def test_none_entity_returns_none():
    assert entity_mapper.build_query(None) is None

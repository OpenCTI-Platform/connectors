from splunk_connector.converter_to_stix import ConverterToStix


def test_saved_search_creates_spl_indicator_note_and_attack_pattern():
    converter = ConverterToStix(tlp_level="amber", confidence=60)

    objects = converter.saved_search_to_stix(
        {
            "name": "Suspicious PowerShell",
            "id": "https://splunk.example.com/servicesNS/nobody/search/saved/searches/Suspicious",
            "content": {
                "search": "index=wineventlog powershell T1059.001",
                "description": "Detects suspicious PowerShell",
                "cron_schedule": "*/15 * * * *",
                "dispatch.earliest_time": "-15m",
                "dispatch.latest_time": "now",
                "mitre_attack_id": "T1059.001",
            },
        },
        note_type="Search Parameters",
    )

    types = [obj["type"] for obj in objects]
    indicator = next(obj for obj in objects if obj["type"] == "indicator")
    note = next(obj for obj in objects if obj["type"] == "note")

    assert "indicator" in types
    assert "attack-pattern" in types
    assert "relationship" in types
    assert indicator["pattern_type"] == "spl"
    assert indicator["pattern"] == "index=wineventlog powershell T1059.001"
    assert note["note_types"] == ["Search Parameters"]
    assert "dispatch.earliest_time" in note["content"]
    relationship = next(obj for obj in objects if obj["type"] == "relationship")
    assert relationship["relationship_type"] == "indicates"


def test_asset_creates_infrastructure_and_owner_relationship():
    converter = ConverterToStix()

    objects = converter.asset_identity_to_stix(
        {
            "record_type": "asset",
            "host": "server01.example.com",
            "owner": "alice",
            "ip": "192.0.2.10",
        }
    )

    types = [obj["type"] for obj in objects]
    infrastructure = next(obj for obj in objects if obj["type"] == "infrastructure")

    assert "infrastructure" in types
    assert "identity" in types
    assert "relationship" in types
    assert infrastructure["infrastructure_types"] == ["unknown"]


def test_asset_infrastructure_type_can_be_derived_from_metadata():
    converter = ConverterToStix()

    objects = converter.asset_identity_to_stix(
        {
            "record_type": "asset",
            "host": "firewall01.example.com",
            "category": "network firewall",
        }
    )

    infrastructure = next(obj for obj in objects if obj["type"] == "infrastructure")
    assert infrastructure["infrastructure_types"] == ["routers-switches"]


def test_finding_creates_incident_sighting_and_attack_pattern():
    converter = ConverterToStix()

    objects = converter.finding_to_stix(
        {
            "title": "Suspicious login",
            "severity": "high",
            "_time": "2026-05-31T12:00:00Z",
            "finding_id": "finding-1",
            "mitre_attack_id": "T1078",
        }
    )

    types = [obj["type"] for obj in objects]
    incident = next(obj for obj in objects if obj["type"] == "incident")

    assert "incident" in types
    assert "sighting" in types
    assert "attack-pattern" in types
    relationship = next(obj for obj in objects if obj["type"] == "relationship")
    assert incident["severity"] == "high"
    assert relationship["relationship_type"] == "uses"


def test_mitre_extraction_ignores_unrelated_string_fields():
    converter = ConverterToStix()

    objects = converter.finding_to_stix(
        {
            "title": "Ticket T1078-upgrade",
            "severity": "high",
            "description": "Server T1234 rebooted",
        }
    )

    assert "attack-pattern" not in [obj["type"] for obj in objects]


def test_mitre_extraction_uses_attack_or_mitre_fields():
    converter = ConverterToStix()

    objects = converter.finding_to_stix(
        {
            "title": "Suspicious login",
            "severity": "high",
            "attack_technique": "T1078",
        }
    )

    assert "attack-pattern" in [obj["type"] for obj in objects]

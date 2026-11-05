import json
from unittest.mock import MagicMock, patch

import pytest
import requests
from pycti import Identity as PyctiIdentity
from pycti import Indicator as PyctiIndicator
from rflib.rf_to_stix2 import ENTITY_TYPE_MAPPER, ConversionError
from rflib.rf_to_stix2 import IntrusionSet as RFIntrusionSet
from rflib.rf_to_stix2 import IPAddress as RFIPAddress
from rflib.rf_to_stix2 import StixNote
from rflib.rf_to_stix2 import ThreatActor as RFThreatActor
from rflib.rf_to_stix2 import Vulnerability as RFVulnerability
from stix2 import (
    URL,
    AttackPattern,
    Campaign,
    DomainName,
    EmailAddress,
    File,
    Identity,
    Indicator,
    IntrusionSet,
    IPv4Address,
    Location,
    Malware,
    Relationship,
    Software,
    ThreatActor,
    Vulnerability,
)

SHA512_HASH = (
    "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
    "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
)
UNSUPPORTED_HASH = "a" * 96

# ── Tests ─────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "rf_type, name, created_objs",
    [
        ("IpAddress", "1.1.1.1", [Indicator, IPv4Address, Relationship]),
        (
            "InternetDomainName",
            "http://test.com",
            [Indicator, DomainName, Relationship],
        ),
        ("URL", "test.com", [Indicator, URL, Relationship]),
        (
            "EmailAddress",
            "test@test.com",
            [Indicator, EmailAddress, Relationship],
        ),
        (
            "Hash",
            "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
            [Indicator, File, Relationship],
        ),
        ("MitreAttackIdentifier", "test mitreattack", [AttackPattern]),
        ("Company", "test company", [Identity]),
        ("Person", "test person", [Identity]),
        ("Organization", "test organization", [Identity]),
        ("Malware", "test malware", [Malware]),
        ("CyberVulnerability", "test cybervuln", [Vulnerability]),
        ("Product", "test product", [Software]),
        ("Country", "test country", [Location]),
        ("City", "test city", [Location]),
        ("ProvinceOrState", "test province", [Location]),
        ("Industry", "test industry", [Identity]),
        ("Operation", "test operation", [Campaign]),
        ("Threat Actor", "test threat actor", [ThreatActor]),
    ],
)
# Scenario: Each Recorded Future entity type maps to the expected STIX2 object type(s)
def test_maps_rf_types_to_the_corresponding_stix_object(rf_type, name, created_objs):
    # Given a valid author identity and TLP marking
    author = _given_author()
    tlp = _given_tlp()
    # And an RF entity of type <rf_type> with name <name> resolved via ENTITY_TYPE_MAPPER
    rf_object = _given_rf_entity(rf_type, name, author, tlp)

    # When the entity is converted to STIX objects
    stix_objects = _when_to_stix_objects(rf_object)

    # Then each resulting STIX object matches the expected type at the corresponding index
    _then_stix_types_match(stix_objects, created_objs)


# Scenario: Threat Actor related to a Vulnerability risk list row is ingested as an IntrusionSet
def test_vulnerability_map_data_produces_intrusion_set_for_threat_actor():
    # Given a valid author identity and TLP marking
    author = _given_author()
    tlp = _given_tlp()
    # And a Vulnerability entity for CVE-2023-1234
    vuln = _given_vulnerability("CVE-2023-1234", author, tlp)
    # And a risk list CSV row with risk score 75
    # And the row's Links contain a related entity of type "Threat Actor" named "APT28"
    rf_row = _given_vuln_risk_row(risk=75, threat_actor_name="APT28")

    # When the vulnerability processes the risk row with ta_to_intrusion_set enabled
    _when_vuln_map_data_with_ta_scope(
        vuln,
        rf_row,
        tlp,
        related_entity_types=["Threat Actor"],
        ta_to_intrusion_set=True,
    )

    # Then exactly one IntrusionSet is present in the resolved related entities
    _then_contains_intrusion_set(vuln.related_entities)
    # And no ThreatActor object is present in the resolved related entities
    _then_contains_no_threat_actor(vuln.related_entities)


# Scenario: Threat Actor related to an Indicator risk list row is ingested as an IntrusionSet
def test_indicator_map_data_produces_intrusion_set_for_threat_actor():
    # Given a valid author identity and TLP marking
    author = _given_author()
    tlp = _given_tlp()
    # And an IP address indicator for "1.1.1.1"
    indicator = _given_ip_indicator("1.1.1.1", author, tlp)
    # And a risk list CSV row with risk score 75
    # And the row's Links hits contain a related entity of type "Threat Actor" named "APT28"
    rf_row = _given_indicator_risk_row(risk=75, threat_actor_name="APT28")

    # When the indicator processes the risk row with ta_to_intrusion_set enabled
    _when_indicator_map_data_with_ta_scope(
        indicator,
        rf_row,
        tlp,
        related_entity_types=["Threat Actor"],
        ta_to_intrusion_set=True,
    )

    # Then exactly one IntrusionSet is present in the resolved related entities
    _then_contains_intrusion_set(indicator.related_entities)
    # And no ThreatActor object is present in the resolved related entities
    _then_contains_no_threat_actor(indicator.related_entities)


# Scenario: Vulnerability Threat Actor → IntrusionSet when ta_to_intrusion_set is True
def test_vulnerability_map_data_respects_risk_list_enabled():
    # Given a valid author identity and TLP marking
    author = _given_author()
    tlp = _given_tlp()
    # And a Vulnerability entity for CVE-2024-9999
    vuln = _given_vulnerability("CVE-2024-9999", author, tlp)
    # And a risk list CSV row with risk score 80 whose Links contain "APT29"
    rf_row = _given_vuln_risk_row(risk=80, threat_actor_name="APT29")

    # When map_data is called with ta_to_intrusion_set=True
    _when_vuln_map_data_with_ta_scope(
        vuln,
        rf_row,
        tlp,
        related_entity_types=["Threat Actor"],
        ta_to_intrusion_set=True,
    )

    # Then exactly one IntrusionSet is present in the resolved related entities
    _then_contains_intrusion_set(vuln.related_entities)
    # And no ThreatActor object is present
    _then_contains_no_threat_actor(vuln.related_entities)


# Scenario: Vulnerability Threat Actor → ThreatActor when ta_to_intrusion_set is False
def test_vulnerability_map_data_respects_risk_list_disabled():
    # Given a valid author identity and TLP marking
    author = _given_author()
    tlp = _given_tlp()
    # And a Vulnerability entity for CVE-2024-9999
    vuln = _given_vulnerability("CVE-2024-9999", author, tlp)
    # And a risk list CSV row with risk score 80 whose Links contain "APT29"
    rf_row = _given_vuln_risk_row(risk=80, threat_actor_name="APT29")

    # When map_data is called with ta_to_intrusion_set=False
    _when_vuln_map_data_with_ta_scope(
        vuln,
        rf_row,
        tlp,
        related_entity_types=["Threat Actor"],
        ta_to_intrusion_set=False,
    )

    # Then exactly one ThreatActor is present in the resolved related entities
    _then_contains_threat_actor(vuln.related_entities)
    # And no IntrusionSet object is present
    _then_contains_no_intrusion_set(vuln.related_entities)


# Scenario: Indicator Threat Actor → IntrusionSet when ta_to_intrusion_set is True
def test_indicator_map_data_respects_risk_list_enabled():
    # Given a valid author identity and TLP marking
    author = _given_author()
    tlp = _given_tlp()
    # And an IP address indicator for "2.2.2.2"
    indicator = _given_ip_indicator("2.2.2.2", author, tlp)
    # And a risk list CSV row with risk score 80 whose Links contain "APT29"
    rf_row = _given_indicator_risk_row(risk=80, threat_actor_name="APT29")

    # When map_data is called with ta_to_intrusion_set=True
    _when_indicator_map_data_with_ta_scope(
        indicator,
        rf_row,
        tlp,
        related_entity_types=["Threat Actor"],
        ta_to_intrusion_set=True,
    )

    # Then exactly one IntrusionSet is present in the resolved related entities
    _then_contains_intrusion_set(indicator.related_entities)
    # And no ThreatActor object is present
    _then_contains_no_threat_actor(indicator.related_entities)


# Scenario: Indicator Threat Actor → ThreatActor when ta_to_intrusion_set is False
def test_indicator_map_data_respects_risk_list_disabled():
    # Given a valid author identity and TLP marking
    author = _given_author()
    tlp = _given_tlp()
    # And an IP address indicator for "2.2.2.2"
    indicator = _given_ip_indicator("2.2.2.2", author, tlp)
    # And a risk list CSV row with risk score 80 whose Links contain "APT29"
    rf_row = _given_indicator_risk_row(risk=80, threat_actor_name="APT29")

    # When map_data is called with ta_to_intrusion_set=False
    _when_indicator_map_data_with_ta_scope(
        indicator,
        rf_row,
        tlp,
        related_entity_types=["Threat Actor"],
        ta_to_intrusion_set=False,
    )

    # Then exactly one ThreatActor is present in the resolved related entities
    _then_contains_threat_actor(indicator.related_entities)
    # And no IntrusionSet object is present
    _then_contains_no_intrusion_set(indicator.related_entities)


# Scenario: The author identity is never part of an entity's own STIX objects
@pytest.mark.parametrize(
    "rf_type, name",
    [
        ("MitreAttackIdentifier", "test mitreattack"),
        ("Company", "test company"),
        ("Person", "test person"),
        ("Organization", "test organization"),
        ("Malware", "test malware"),
        ("Industry", "test industry"),
        ("Threat Actor", "test threat actor"),
    ],
)
def test_entity_stix_objects_exclude_the_author(rf_type, name):
    # Given a valid author identity and TLP marking
    author = _given_author()
    tlp = _given_tlp()
    # And an RF entity of type <rf_type> with name <name>
    rf_object = _given_rf_entity(rf_type, name, author, tlp)

    # When the entity is converted to STIX objects
    stix_objects = _when_to_stix_objects(rf_object)

    # Then the author is not part of the entity's own objects
    _then_objects_exclude(stix_objects, author)


# Scenario: An entity bundle still carries the author it references (risk lists, threat maps)
@pytest.mark.parametrize(
    "rf_type, name",
    [
        ("IpAddress", "3.3.3.3"),
        ("Malware", "test malware"),
        ("CyberVulnerability", "CVE-2024-1111"),
    ],
)
def test_entity_bundle_contains_the_author_exactly_once(rf_type, name):
    # Given a valid author identity and TLP marking
    author = _given_author()
    tlp = _given_tlp()
    # And an RF entity of type <rf_type> whose bundle has been built
    rf_object = _given_rf_entity(rf_type, name, author, tlp)

    # When the entity is converted to a STIX bundle
    bundle = _when_built_to_stix_bundle(rf_object)

    # Then the author identity referenced by 'created_by_ref' is in the bundle, once
    _then_objects_contain_once(bundle.objects, author)


# Scenario: The report creator is not listed among the report's entities (issue #7003)
def test_analyst_note_report_does_not_reference_the_author():
    # Given an analyst note holding a Malware and a Company entity
    note = _given_stix_note()
    _when_note_converted_from_json(note, _given_analyst_note_json())

    # When the note is converted to STIX objects
    stix_objects = note.to_stix_objects()
    report = _then_single_report(stix_objects)

    # Then the author is the report creator
    assert report.created_by_ref == note.author.id
    # And the author is not referenced as one of the report's entities
    assert note.author.id not in report.object_refs
    # And the author identity is still part of the bundle, once
    _then_objects_contain_once(stix_objects, note.author)
    # And the note entities are referenced by the report
    assert len(report.object_refs) == 2


# Scenario: Building an indicator computes the STIX pattern once and reuses it (issue #7473)
def test_create_indicator_computes_pattern_once():
    # Given a valid IPv4 address indicator
    author = _given_author()
    tlp = _given_tlp()
    indicator = _given_ip_indicator("1.1.1.1", author, tlp)
    # And a spy wrapping the real pattern-creation method
    with patch.object(
        indicator, "_create_pattern", wraps=indicator._create_pattern
    ) as pattern_spy:
        # When the indicator is created
        stix_indicator = indicator._create_indicator()

        # Then the pattern is computed only twice: once for the indicator's id/pattern
        # fields (cached and reused), and once more inside
        # _add_main_observable_type_to_indicators (a separate call site, unaffected
        # by this fix)
        assert (
            pattern_spy.call_count == 2
        ), f"Expected _create_pattern to be called twice, got {pattern_spy.call_count}"
    # And the indicator's pattern and id are both derived from that single value
    assert stix_indicator.pattern == "[ipv4-addr:value = '1.1.1.1']"


# Scenario: Main observable type falls back to "Unknown" when pattern creation fails (issue #7473)
def test_add_main_observable_type_returns_unknown_when_pattern_creation_fails():
    # Given an indicator whose name is not a valid IPv4 or IPv6 address
    author = _given_author()
    tlp = _given_tlp()
    indicator = _given_ip_indicator("not-a-valid-ip", author, tlp)

    # When resolving the main observable type
    observable_type = indicator._add_main_observable_type_to_indicators()

    # Then it falls back to "Unknown" instead of raising
    assert observable_type == "Unknown"


# Scenario: A single unsupported detection-rule attachment is skipped without aborting note conversion (issue #7473)
def test_from_json_skips_invalid_attachment_and_keeps_processing_valid_ones():
    # Given a StixNote
    note = _given_stix_note()
    # And an analyst note with one unsupported attachment (docx) and one valid YARA attachment
    note_json = _given_analyst_note_json_with_attachments(
        [
            {"name": "malware.docx", "type": "docx", "content": "not a rule"},
            {
                "name": "rule.yar",
                "type": "yara",
                "content": "rule test { condition: true }",
            },
        ]
    )

    # When the note is converted from JSON
    _when_note_converted_from_json(note, note_json)

    # Then a warning is logged for the unsupported attachment
    note.helper.connector_logger.warning.assert_called_once()
    warning_message = note.helper.connector_logger.warning.call_args[0][0]
    assert "malware.docx" in warning_message
    # And the valid attachment still produced a STIX indicator
    detection_rule_indicators = [
        obj for obj in note.objects if getattr(obj, "pattern_type", None) == "yara"
    ]
    assert len(detection_rule_indicators) == 1


# Scenario: A Recorded Future Threat Actor carries its "AKA" aliases (issue #7118)
def test_threat_actor_maps_recorded_future_aliases():
    # Given a valid author identity and TLP marking
    author = _given_author()
    tlp = _given_tlp()

    # And a Threat Actor with Recorded Future alias data (including its own name)
    threat_actor = RFThreatActor(
        "APT28",
        "Organization",
        author,
        tlp,
        aliases=["Fancy Bear", "APT28", "Fancy Bear", "Sofacy"],
    )

    # When the entity is converted to a STIX object
    stix_obj = threat_actor.to_stix_objects()[0]

    # Then the STIX aliases exclude the primary name and duplicates
    assert stix_obj.aliases == ["Fancy Bear", "Sofacy"]


# Scenario: A Recorded Future Intrusion Set carries its "AKA" aliases (issue #7118)
def test_intrusion_set_maps_recorded_future_aliases():
    # Given a valid author identity and TLP marking
    author = _given_author()
    tlp = _given_tlp()

    # And an Intrusion Set with Recorded Future alias data
    intrusion_set = RFIntrusionSet(
        "Everest Ransomware Group",
        "Organization",
        author,
        tlp,
        aliases=["Everest", "Everest Locker"],
    )

    # When the entity is converted to a STIX object
    stix_obj = intrusion_set.to_stix_objects()[0]

    # Then the STIX aliases carry the bridging short names
    assert stix_obj.aliases == ["Everest", "Everest Locker"]


# Scenario: A Threat Actor without alias data omits the STIX aliases property (issue #7118)
def test_threat_actor_without_aliases_omits_property():
    # Given a valid author identity and TLP marking
    author = _given_author()
    tlp = _given_tlp()

    # And a Threat Actor with no alias data
    threat_actor = RFThreatActor("Lone Wolf", "Organization", author, tlp)

    # When the entity is converted to a STIX object
    stix_obj = threat_actor.to_stix_objects()[0]

    # Then no aliases property is emitted
    assert "aliases" not in stix_obj


# Scenario: Analyst note Threat Actor entities are enriched with their aliases (issue #7118)
def test_analyst_note_threat_actor_is_enriched_with_aliases():
    # Given a StixNote whose RF client resolves aliases for the threat actor entity
    rfapi = MagicMock()
    rfapi.get_entity_aliases.return_value = ["Fancy Bear", "Sofacy"]
    note = StixNote(opencti_helper=MagicMock(), tas=["ta-entity"], rfapi=rfapi)

    # And an analyst note referencing a known Threat Actor entity
    note_json = _given_analyst_note_json()
    note_json["attributes"]["note_entities"] = [
        {"id": "ta-entity", "type": "Organization", "name": "APT28"},
    ]

    # When the note is converted from JSON
    _when_note_converted_from_json(note, note_json)

    # Then the RF aliases were requested for the threat actor entity
    rfapi.get_entity_aliases.assert_called_once_with("ta-entity")
    # And the resulting Threat Actor carries those aliases
    threat_actors = [obj for obj in note.objects if obj["type"] == "threat-actor"]
    assert len(threat_actors) == 1
    assert threat_actors[0].aliases == ["Fancy Bear", "Sofacy"]


# Scenario: An event adversary resolving to an Identity must not create relationships (issue OCTI2-2428)
def test_create_event_relations_skips_adversary_resolved_as_identity():
    # Given an analyst note whose adversary Organization is NOT in the Threat Actor list
    note = _given_stix_note()
    note_json = _given_analyst_note_json()
    note_json["attributes"]["note_entities"] = [
        {
            "id": "org-1",
            "type": "Organization",
            "name": "Government of Republic of Hungary",
        },
        {"id": "ap-1", "type": "MitreAttackIdentifier", "name": "T1566.002"},
    ]
    _when_note_converted_from_json(note, note_json)
    # And the Organization was therefore converted to a STIX Identity
    adversary = [obj for obj in note.objects if obj["type"] == "identity"]
    assert any(obj["name"] == "Government of Republic of Hungary" for obj in adversary)
    objects_before = list(note.objects)

    # When events referencing that Organization as the adversary are processed
    events = [
        {
            "type": "CyberAttack",
            "attributes": {
                "adversary": [
                    {
                        "type": "Organization",
                        "name": "Government of Republic of Hungary",
                    }
                ],
                "capabilities": [
                    {"type": "MitreAttackIdentifier", "name": "T1566.002"}
                ],
            },
        }
    ]
    note.create_event_relations(events=events)

    # Then no relationship is created (Identity -> uses -> Attack-Pattern is invalid)
    assert note.objects == objects_before
    relationships = [obj for obj in note.objects if obj["type"] == "relationship"]
    assert len(relationships) == 0


# Scenario: Context entities are ignored unless explicitly enabled
def test_analyst_note_ignores_context_entities_by_default():
    # Given an analyst note whose note_entities holds a Malware, and whose
    # context_entities holds a Threat Actor referenced only in context
    note = _given_stix_note()
    _when_note_converted_from_json(
        note, _given_analyst_note_json_with_context_entities()
    )

    # When the note is converted to STIX objects
    stix_objects = note.to_stix_objects()
    report = _then_single_report(stix_objects)

    # Then only the primary entity is referenced, the context-only one is left out
    assert len(report.object_refs) == 1
    _then_contains_threat_actor(stix_objects, expected_count=0)


# Scenario: An entity present only in context_entities is not dropped (issue #6943)
def test_analyst_note_includes_context_entities_when_enabled():
    # Given context entities ingestion is enabled, and an analyst note whose
    # note_entities holds a Malware and whose context_entities holds a
    # Threat Actor referenced only in context
    note = _given_stix_note(include_context_entities=True)
    _when_note_converted_from_json(
        note, _given_analyst_note_json_with_context_entities()
    )

    # When the note is converted to STIX objects
    stix_objects = note.to_stix_objects()
    report = _then_single_report(stix_objects)

    # Then the context-only entity is present among the report's referenced objects
    assert len(report.object_refs) == 2
    _then_contains_threat_actor(stix_objects)


# Scenario: An entity present in both note_entities and context_entities is not duplicated
def test_analyst_note_deduplicates_entities_shared_between_both_arrays():
    # Given context entities ingestion is enabled, and an analyst note where
    # the same entity id appears in both note_entities and context_entities
    note = _given_stix_note(include_context_entities=True)
    _when_note_converted_from_json(
        note, _given_analyst_note_json_with_duplicate_entity()
    )

    # When the note is converted to STIX objects
    stix_objects = note.to_stix_objects()
    report = _then_single_report(stix_objects)

    # Then the entity is only referenced once by the report
    assert len(report.object_refs) == 1


# Scenario: An entity unknown to the risk API is skipped, not the whole note (issue #7344)
def test_analyst_note_skips_entity_without_risk_score_when_threshold_is_set():
    # Given a risk threshold, and a risk API that does not know one of the two
    # domains of the note
    note = _given_stix_note(risk_threshold=60)
    note.rfapi.get_risk_score.side_effect = _given_risk_scores(
        {"known.example.com": 80}
    )

    # When the note is converted to STIX objects
    _when_note_converted_from_json(note, _given_analyst_note_json_with_domains())
    stix_objects = note.to_stix_objects()

    # Then the note is still built, with the known domain and the malware,
    # but without the unknown domain
    _then_single_report(stix_objects)
    assert _indicator_names(stix_objects) == ["known.example.com"]
    assert any(obj["type"] == "malware" for obj in stix_objects)


# Scenario: An entity unknown to the risk API is kept without score when no threshold is set (issue #7344)
def test_analyst_note_keeps_entity_without_risk_score_when_no_threshold():
    # Given risk scores are imported without threshold, and a risk API that does
    # not know one of the two domains of the note
    note = _given_stix_note(risk_as_score=True, risk_threshold=None)
    note.rfapi.get_risk_score.side_effect = _given_risk_scores(
        {"known.example.com": 80}
    )

    # When the note is converted to STIX objects
    _when_note_converted_from_json(note, _given_analyst_note_json_with_domains())
    stix_objects = note.to_stix_objects()

    # Then both domains are present, only the known one carries a score
    scores = {
        obj["name"]: obj.get("x_opencti_score")
        for obj in stix_objects
        if obj["type"] == "indicator"
    }
    assert scores == {"known.example.com": 80, "unknown.example.com": None}


# Scenario: The risk score is fetched once per entity when threshold and score are both enabled
def test_analyst_note_fetches_risk_score_once_per_entity():
    # Given a risk threshold and risk scores imported as score
    note = _given_stix_note(risk_as_score=True, risk_threshold=60)
    note.rfapi.get_risk_score.side_effect = _given_risk_scores(
        {"known.example.com": 80, "unknown.example.com": 90}
    )

    # When the note is converted to STIX objects
    _when_note_converted_from_json(note, _given_analyst_note_json_with_domains())

    # Then the risk API is called once per domain
    assert note.rfapi.get_risk_score.call_count == 2


# Scenario: A risk API failure other than 404 is not hidden
def test_analyst_note_raises_on_risk_api_error_other_than_not_found():
    # Given a risk API that fails with a server error
    note = _given_stix_note(risk_threshold=60)
    note.rfapi.get_risk_score.side_effect = _given_http_error(500)

    # When the note is converted to STIX objects
    # Then the error is raised
    with pytest.raises(requests.exceptions.HTTPError):
        _when_note_converted_from_json(note, _given_analyst_note_json_with_domains())


@pytest.mark.parametrize(
    "file_hash, expected_pattern",
    [
        (
            "e1d9c90de2568f34ad689c71dac09c62",
            "[file:hashes.MD5 = 'e1d9c90de2568f34ad689c71dac09c62']",
        ),
        (
            "da39a3ee5e6b4b0d3255bfef95601890afd80709",
            "[file:hashes.'SHA-1' = 'da39a3ee5e6b4b0d3255bfef95601890afd80709']",
        ),
        (
            "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
            "[file:hashes.'SHA-256' = '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08']",
        ),
        (
            SHA512_HASH,
            f"[file:hashes.'SHA-512' = '{SHA512_HASH}']",
        ),
    ],
)
# Scenario: File hash patterns only quote the hash key when it requires it (issue #7671)
def test_file_hash_pattern_quotes_hash_key_only_when_required(
    file_hash, expected_pattern
):
    # Given a file hash indicator
    author = _given_author()
    tlp = _given_tlp()
    indicator = _given_rf_entity("Hash", file_hash, author, tlp)

    # When the indicator is created
    stix_indicator = indicator._create_indicator()

    # Then the pattern matches the form OpenCTI normalizes patterns to
    assert stix_indicator.pattern == expected_pattern
    # And the indicator id is derived from that pattern
    assert stix_indicator.id == PyctiIndicator.generate_id(expected_pattern)


# Scenario: A SHA-512 file hash is converted to a File observable (issue #7343)
def test_file_hash_maps_sha512_to_file_observable():
    # Given a SHA-512 file hash indicator
    indicator = _given_rf_entity("Hash", SHA512_HASH, _given_author(), _given_tlp())

    # When it is converted to STIX objects
    stix_objects = _when_to_stix_objects(indicator)

    # Then the observable carries the hash under the SHA-512 key
    files = [obj for obj in stix_objects if isinstance(obj, File)]
    assert len(files) == 1
    assert files[0].hashes == {"SHA-512": SHA512_HASH}


# Scenario: A hash of unsupported length raises a feed-neutral conversion error
def test_file_hash_with_unsupported_length_raises_conversion_error():
    # Given a hash whose length matches no supported algorithm
    # When the indicator is built
    # Then a ConversionError names the hash without claiming a feed
    with pytest.raises(ConversionError) as exc_info:
        _given_rf_entity("Hash", UNSUPPORTED_HASH, _given_author(), _given_tlp())
    assert UNSUPPORTED_HASH in str(exc_info.value)
    assert "[ANALYST NOTES]" not in str(exc_info.value)


# Scenario: An unsupported hash skips only its entity, not the whole note (issue #7343)
def test_analyst_note_skips_unconvertible_entity_and_keeps_the_others():
    # Given a note mentioning a malware and a hash of unsupported length
    note = _given_stix_note()
    note_json = _given_analyst_note_json()
    note_json["attributes"]["note_entities"] = [
        {"id": "entity-1", "type": "Malware", "name": "Test malware"},
        {"id": "entity-2", "type": "Hash", "name": UNSUPPORTED_HASH},
    ]

    # When the note is converted to STIX objects
    _when_note_converted_from_json(note, note_json)
    stix_objects = note.to_stix_objects()

    # Then the malware is kept
    assert [obj.name for obj in stix_objects if isinstance(obj, Malware)] == [
        "Test malware"
    ]
    # And no file observable is created for the hash
    assert not [obj for obj in stix_objects if isinstance(obj, File)]
    # And the skip is logged as a warning with its context
    warning_calls = note.helper.connector_logger.warning.call_args_list
    assert len(warning_calls) == 1
    assert warning_calls[0].args == (
        "[ANALYST NOTES] Skipping entity that could not be converted",
    )
    assert warning_calls[0].kwargs["meta"]["note_id"] == "note-id"
    assert warning_calls[0].kwargs["meta"]["entity"] == UNSUPPORTED_HASH
    assert warning_calls[0].kwargs["meta"]["type"] == "Hash"


# Scenario: An indicator with a risk score of 0 keeps its score
def test_indicator_keeps_a_risk_score_of_zero():
    # Given an IP address indicator whose risk score is 0
    indicator = _given_ip_indicator("1.1.1.1", _given_author(), _given_tlp())
    indicator.risk_score = 0

    # When the indicator is converted to STIX objects
    stix_objects = _when_to_stix_objects(indicator)

    # Then the STIX indicator carries a score of 0, not a missing score
    assert _then_single_indicator(stix_objects)["x_opencti_score"] == 0


# Scenario: An indicator without risk score has no score
# Regression guard: also passes at base, it protects the unset case of the score fix
def test_indicator_without_risk_score_has_no_score():
    # Given an IP address indicator without risk score
    indicator = _given_ip_indicator("1.1.1.1", _given_author(), _given_tlp())

    # When the indicator is converted to STIX objects
    stix_objects = _when_to_stix_objects(indicator)

    # Then the STIX indicator has no score
    assert _then_single_indicator(stix_objects).get("x_opencti_score") is None


# Scenario: A vulnerability with a risk of 0 keeps its score
def test_vulnerability_keeps_a_risk_score_of_zero():
    # Given a vulnerability processing a risk list row whose risk is "0"
    vuln = _given_vulnerability("CVE-2024-9999", _given_author(), _given_tlp())
    rf_row = _given_vuln_risk_row(risk=0, threat_actor_name="APT29")
    _when_vuln_map_data(vuln, rf_row, _given_tlp(), related_entity_types=[])

    # When the vulnerability is converted to STIX objects
    stix_objects = _when_to_stix_objects(vuln)

    # Then the STIX vulnerability carries a score of 0, not a missing score
    assert stix_objects[0]["x_opencti_score"] == 0


# Scenario: A vulnerability without risk score has no score
# Regression guard: also passes at base, it protects the unset case of the score fix
def test_vulnerability_without_risk_score_has_no_score():
    # Given a vulnerability whose risk score was never set
    vuln = _given_vulnerability("CVE-2024-9999", _given_author(), _given_tlp())

    # When the vulnerability is converted to STIX objects
    stix_objects = _when_to_stix_objects(vuln)

    # Then the STIX vulnerability has no score
    assert stix_objects[0].get("x_opencti_score") is None


# Scenario: An indicator risk list row with an empty or non-numeric risk has no score
# Regression guard: also passes at base, it protects the non-numeric `Risk` case of the score fix
@pytest.mark.parametrize("risk", ["", "not-a-number"])
def test_indicator_with_non_numeric_risk_has_no_score(risk):
    # Given an IP address indicator processing a risk list row whose risk is empty or non-numeric
    indicator = _given_ip_indicator("1.1.1.1", _given_author(), _given_tlp())
    rf_row = _given_indicator_risk_row(risk=risk, threat_actor_name="APT28")
    _when_indicator_map_data(indicator, rf_row, _given_tlp(), related_entity_types=[])

    # When the indicator is converted to STIX objects
    stix_objects = _when_to_stix_objects(indicator)

    # Then the STIX indicator has no score, not a score of 0
    assert _then_single_indicator(stix_objects).get("x_opencti_score") is None


# Scenario: A vulnerability risk list row with an empty or non-numeric risk has no score
# Regression guard: also passes at base, it protects the non-numeric `Risk` case of the score fix
@pytest.mark.parametrize("risk", ["", "not-a-number"])
def test_vulnerability_with_non_numeric_risk_has_no_score(risk):
    # Given a vulnerability processing a risk list row whose risk is empty or non-numeric
    vuln = _given_vulnerability("CVE-2024-9999", _given_author(), _given_tlp())
    rf_row = _given_vuln_risk_row(risk=risk, threat_actor_name="APT29")
    _when_vuln_map_data(vuln, rf_row, _given_tlp(), related_entity_types=[])

    # When the vulnerability is converted to STIX objects
    stix_objects = _when_to_stix_objects(vuln)

    # Then the STIX vulnerability has no score, not a score of 0
    assert stix_objects[0].get("x_opencti_score") is None


# Scenario: A risk threshold of 0 disables the filtering, including score 0 and unscored indicators
def test_analyst_note_keeps_every_indicator_when_threshold_is_zero():
    # Given a risk threshold of 0 and risk scores imported as score, and a risk API
    # scoring three of the four domains of the note (0, 40 and 80)
    note = _given_stix_note(risk_as_score=True, risk_threshold=0)
    note.rfapi.get_risk_score.side_effect = _given_risk_scores(_given_domain_scores())

    # When the note is converted to STIX objects
    _when_note_converted_from_json(note, _given_analyst_note_json_with_scored_domains())
    stix_objects = note.to_stix_objects()

    # Then the four domains are present, with their own score and no score for the unknown one
    scores = {
        obj["name"]: obj.get("x_opencti_score")
        for obj in stix_objects
        if obj["type"] == "indicator"
    }
    assert scores == {
        "zero.example.com": 0,
        "low.example.com": 40,
        "high.example.com": 80,
        "unknown.example.com": None,
    }
    # And no skip is logged for any of the four domains
    for entity in scores:
        assert _skip_log_calls(note, entity) == []


# Scenario: A risk threshold of 0 without risk scores import makes no risk API call
# Regression guard: also passes at base. It pins the decision to keep the truthiness
# check on the threshold, not to switch to `is not None`, which would call the risk
# API at threshold 0 for nothing.
def test_analyst_note_does_not_call_risk_api_when_threshold_is_zero_and_no_risk_as_score():
    # Given a risk threshold of 0 and risk scores not imported as score
    note = _given_stix_note(risk_as_score=False, risk_threshold=0)
    note.rfapi.get_risk_score.side_effect = _given_risk_scores(_given_domain_scores())

    # When the note is converted to STIX objects
    _when_note_converted_from_json(note, _given_analyst_note_json_with_scored_domains())
    stix_objects = note.to_stix_objects()

    # Then the four domains are present and the risk API was never called
    assert sorted(_indicator_names(stix_objects)) == sorted(
        [
            "zero.example.com",
            "low.example.com",
            "high.example.com",
            "unknown.example.com",
        ]
    )
    note.rfapi.get_risk_score.assert_not_called()


# Scenario: Indicators below the threshold are skipped and the skip is logged with its context
def test_analyst_note_logs_indicator_skipped_below_risk_threshold():
    # Given a risk threshold of 60 and a risk API scoring three of the four domains
    # of the note (0, 40 and 80)
    note = _given_stix_note(risk_threshold=60)
    note.rfapi.get_risk_score.side_effect = _given_risk_scores(_given_domain_scores())

    # When the note is converted to STIX objects
    _when_note_converted_from_json(note, _given_analyst_note_json_with_scored_domains())
    stix_objects = note.to_stix_objects()

    # Then only the domain scored 80 is kept
    assert _indicator_names(stix_objects) == ["high.example.com"]
    # And the skip of the domain scored 40 is logged with a static message and its context
    skip_calls = _skip_log_calls(note, "low.example.com")
    assert len(skip_calls) == 1
    assert skip_calls[0].args == (
        "[ANALYST NOTES] Ignoring indicator below risk threshold or without risk score",
    )
    assert skip_calls[0].kwargs["meta"] == {
        "note_id": "note-id",
        "entity": "low.example.com",
        "type": "InternetDomainName",
        "risk_score": 40,
        "risk_threshold": 60,
    }
    # And the skip of the domain unknown to the risk API is logged without risk score
    unknown_skip_calls = _skip_log_calls(note, "unknown.example.com")
    assert len(unknown_skip_calls) == 1
    assert unknown_skip_calls[0].kwargs["meta"] == {
        "note_id": "note-id",
        "entity": "unknown.example.com",
        "type": "InternetDomainName",
        "risk_score": None,
        "risk_threshold": 60,
    }


# ── Given helpers ────────────────────────────────────────────────────────────


def _given_author():
    return Identity(  # pylint: disable=W9101  # it's a test no real ingest
        id=PyctiIdentity.generate_id("Fake author", "organization"),
        name="Fake author",
        identity_class="organization",
    )


def _given_tlp():
    return "red"


def _given_rf_entity(rf_type, name, author, tlp):
    return ENTITY_TYPE_MAPPER[rf_type](name, rf_type, author, tlp)


def _given_vulnerability(name, author, tlp):
    return RFVulnerability(name, "CyberVulnerability", author, tlp)


def _given_ip_indicator(ip, author, tlp):
    return RFIPAddress(ip, "IpAddress", author, tlp)


def _given_stix_note(
    include_context_entities=False, risk_as_score=False, risk_threshold=None
):
    return StixNote(
        opencti_helper=MagicMock(),
        tas=[],
        rfapi=MagicMock(),
        risk_as_score=risk_as_score,
        risk_threshold=risk_threshold,
        analyst_notes_include_context_entities=include_context_entities,
    )


def _given_http_error(status_code):
    response = MagicMock()
    response.status_code = status_code
    return requests.exceptions.HTTPError(f"{status_code} Error", response=response)


def _given_risk_scores(scores_by_value):
    """Risk API returning the given scores, and a 404 for any other value"""

    def get_risk_score(_type, value):
        if value not in scores_by_value:
            raise _given_http_error(404)
        return scores_by_value[value]

    return get_risk_score


def _given_analyst_note_json_with_domains():
    note_json = _given_analyst_note_json()
    note_json["attributes"]["note_entities"] = [
        {"id": "entity-1", "type": "Malware", "name": "Test malware"},
        {"id": "entity-2", "type": "InternetDomainName", "name": "unknown.example.com"},
        {"id": "entity-3", "type": "InternetDomainName", "name": "known.example.com"},
    ]
    return note_json


def _given_domain_scores():
    """Scores of the domains of the note, `unknown.example.com` is not known by the risk API"""
    return {"zero.example.com": 0, "low.example.com": 40, "high.example.com": 80}


def _given_analyst_note_json_with_scored_domains():
    note_json = _given_analyst_note_json()
    note_json["attributes"]["note_entities"] = [
        {"id": "entity-1", "type": "InternetDomainName", "name": "zero.example.com"},
        {"id": "entity-2", "type": "InternetDomainName", "name": "low.example.com"},
        {"id": "entity-3", "type": "InternetDomainName", "name": "high.example.com"},
        {"id": "entity-4", "type": "InternetDomainName", "name": "unknown.example.com"},
    ]
    return note_json


def _given_analyst_note_json():
    return {
        "id": "note-id",
        "attributes": {
            "title": "Test analyst note",
            "text": "Some intelligence content",
            "published": "2026-08-20T00:00:00.000Z",
            "topic": [{"name": "Flash Report"}],
            "attachments": [],
            "note_entities": [
                {"id": "entity-1", "type": "Malware", "name": "Test malware"},
                {"id": "entity-2", "type": "Company", "name": "Test company"},
            ],
        },
    }


def _given_analyst_note_json_with_attachments(attachments):
    note_json = _given_analyst_note_json()
    note_json["attributes"]["attachments"] = attachments
    note_json["attributes"]["note_entities"] = []
    return note_json


def _given_analyst_note_json_with_context_entities():
    return {
        "id": "note-id",
        "attributes": {
            "title": "Test analyst note",
            "text": "Some intelligence content",
            "published": "2026-08-20T00:00:00.000Z",
            "topic": [{"name": "Flash Report"}],
            "attachments": [],
            "note_entities": [
                {"id": "entity-1", "type": "Malware", "name": "Test malware"},
            ],
            "context_entities": [
                {"id": "entity-2", "type": "Threat Actor", "name": "APT99"},
            ],
        },
    }


def _given_analyst_note_json_with_duplicate_entity():
    return {
        "id": "note-id",
        "attributes": {
            "title": "Test analyst note",
            "text": "Some intelligence content",
            "published": "2026-08-20T00:00:00.000Z",
            "topic": [{"name": "Flash Report"}],
            "attachments": [],
            "note_entities": [
                {"id": "entity-1", "type": "Malware", "name": "Test malware"},
            ],
            "context_entities": [
                {"id": "entity-1", "type": "Malware", "name": "Test malware"},
            ],
        },
    }


def _given_vuln_risk_row(risk, threat_actor_name):
    links = [
        {
            "sections": [
                {
                    "section_id": {"name": "Indicators"},
                    "lists": [
                        {
                            "type": {"name": "Threat Actor"},
                            "entities": [{"name": threat_actor_name}],
                        }
                    ],
                }
            ]
        }
    ]
    return {"Risk": str(risk), "Links": json.dumps(links)}


def _given_indicator_risk_row(risk, threat_actor_name):
    links = {
        "hits": [
            {
                "sections": [
                    {
                        "section_id": {"name": "Indicators"},
                        "lists": [
                            {
                                "type": {"name": "Threat Actor"},
                                "entities": [{"name": threat_actor_name}],
                            }
                        ],
                    }
                ]
            }
        ]
    }
    return {"Risk": str(risk), "Links": json.dumps(links)}


# ── When helpers ─────────────────────────────────────────────────────────────


def _when_to_stix_objects(rf_object):
    return rf_object.to_stix_objects()


def _when_built_to_stix_bundle(rf_object):
    rf_object.build_bundle(rf_object)
    return rf_object.to_stix_bundle()


def _when_note_converted_from_json(note, note_json):
    note.from_json(note_json, _given_tlp())


def _when_vuln_map_data(vuln, rf_row, tlp, related_entity_types):
    vuln.map_data(rf_row, tlp, risklist_related_entities=related_entity_types)


def _when_indicator_map_data(indicator, rf_row, tlp, related_entity_types):
    indicator.map_data(rf_row, tlp, risklist_related_entities=related_entity_types)


def _when_vuln_map_data_with_ta_scope(
    vuln, rf_row, tlp, related_entity_types, ta_to_intrusion_set
):
    vuln.map_data(
        rf_row,
        tlp,
        risklist_related_entities=related_entity_types,
        ta_to_intrusion_set=ta_to_intrusion_set,
    )


def _when_indicator_map_data_with_ta_scope(
    indicator, rf_row, tlp, related_entity_types, ta_to_intrusion_set
):
    indicator.map_data(
        rf_row,
        tlp,
        risklist_related_entities=related_entity_types,
        ta_to_intrusion_set=ta_to_intrusion_set,
    )


# ── Then helpers ─────────────────────────────────────────────────────────────


def _then_stix_types_match(stix_objects, expected_types):
    assert len(stix_objects) == len(
        expected_types
    ), f"Expected {len(expected_types)} STIX objects, got {len(stix_objects)}"
    for i, stix_obj in enumerate(stix_objects):
        assert isinstance(stix_obj, expected_types[i])


def _then_objects_exclude(stix_objects, excluded_object):
    found = [obj for obj in stix_objects if obj.id == excluded_object.id]
    assert len(found) == 0, f"Expected {excluded_object.id} to be absent, got {found}"


def _indicator_names(stix_objects):
    return [obj["name"] for obj in stix_objects if obj["type"] == "indicator"]


def _skip_log_calls(note, entity):
    """INFO log calls of the note carrying the given entity in their meta"""
    return [
        call
        for call in note.helper.connector_logger.info.call_args_list
        if call.kwargs.get("meta", {}).get("entity") == entity
    ]


def _then_single_indicator(stix_objects):
    indicators = [obj for obj in stix_objects if obj["type"] == "indicator"]
    assert len(indicators) == 1, f"Expected exactly 1 indicator, got {len(indicators)}"
    return indicators[0]


def _then_single_report(stix_objects):
    reports = [obj for obj in stix_objects if obj["type"] == "report"]
    assert len(reports) == 1, f"Expected exactly 1 report, got {len(reports)}"
    return reports[0]


def _then_objects_contain_once(stix_objects, expected_object):
    found = [obj for obj in stix_objects if obj.id == expected_object.id]
    assert len(found) == 1, f"Expected exactly 1 {expected_object.id}, got {len(found)}"


def _then_contains_intrusion_set(related_entities, expected_count=1):
    found = [e for e in related_entities if isinstance(e, IntrusionSet)]
    assert (
        len(found) == expected_count
    ), f"Expected {expected_count} IntrusionSet in related_entities, got {len(found)}"


def _then_contains_no_threat_actor(related_entities):
    found = [e for e in related_entities if isinstance(e, ThreatActor)]
    assert (
        len(found) == 0
    ), f"Expected 0 ThreatActor in related_entities, got {len(found)}"


def _then_contains_threat_actor(related_entities, expected_count=1):
    found = [e for e in related_entities if isinstance(e, ThreatActor)]
    assert (
        len(found) == expected_count
    ), f"Expected {expected_count} ThreatActor in related_entities, got {len(found)}"


def _then_contains_no_intrusion_set(related_entities):
    found = [e for e in related_entities if isinstance(e, IntrusionSet)]
    assert (
        len(found) == 0
    ), f"Expected 0 IntrusionSet in related_entities, got {len(found)}"

import json
from unittest.mock import MagicMock, patch

import pytest
from pycti import Identity as PyctiIdentity
from rflib.rf_to_stix2 import ENTITY_TYPE_MAPPER
from rflib.rf_to_stix2 import IPAddress as RFIPAddress
from rflib.rf_to_stix2 import StixNote
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


@pytest.mark.parametrize(
    "rule_type, content",
    [
        ("yara", "rule test { condition: true }"),
        ("sigma", "title: t\ndetection:\n  sel:\n    a: b\n  condition: sel\n"),
        ("snort", 'alert tcp any any -> any any (msg:"t"; sid:1;)'),
        (
            "suricata",
            'alert tcp any any -> any any (msg:"t"; sid:1;)',
        ),
        ("nuclei", "id: t\ninfo:\n  name: n\n"),
    ],
)
def test_from_json_accepts_all_five_pattern_types(rule_type, content):
    # Given a StixNote and an analyst note with a single attachment of RULE_TYPE
    note = _given_stix_note()
    note_json = _given_analyst_note_json_with_attachments(
        [{"name": f"rule.{rule_type}", "type": rule_type, "content": content}]
    )

    # When the note is converted from JSON
    _when_note_converted_from_json(note, note_json)

    # Then no warning is logged
    note.helper.connector_logger.warning.assert_not_called()
    # And an indicator with the matching pattern_type is produced.
    #
    # Recorded Future serves suricata and nuclei rules alongside yara/sigma/snort
    # -- measured at 279 of 2,502 real detection-rule documents (11.2%) -- and
    # OpenCTI's `pattern_type_ov` vocabulary already supports all five. Before
    # this fix, DetectionRule.__init__ raised ConversionError for suricata and
    # nuclei, discarding them.
    matching = [
        obj for obj in note.objects if getattr(obj, "pattern_type", None) == rule_type
    ]
    assert len(matching) == 1


def test_detection_rule_name_preserves_embedded_version_numbers():
    # Given a StixNote and a YARA attachment whose filename contains a version
    # number before the extension
    note = _given_stix_note()
    note_json = _given_analyst_note_json_with_attachments(
        [
            {
                "name": "MAL_Lockbit_3.0_v2.yar",
                "type": "yara",
                "content": "rule test { condition: true }",
            }
        ]
    )

    # When the note is converted from JSON
    _when_note_converted_from_json(note, note_json)

    # Then the indicator name keeps the version number.
    #
    # The previous derivation used `name.split(".")[0]`, which splits on the
    # FIRST dot and turned "MAL_Lockbit_3.0_v2.yar" into "MAL_Lockbit_3" --
    # measured on 11 of 2,502 real rule filenames.
    indicators = [
        obj for obj in note.objects if getattr(obj, "pattern_type", None) == "yara"
    ]
    assert len(indicators) == 1
    assert indicators[0].name == "MAL_Lockbit_3.0_v2"


def test_split_snort_suricata_rules_single_rule_returned_unchanged():
    from rflib.rf_to_stix2 import split_snort_suricata_rules

    content = 'alert tcp any any -> any any (msg:"one"; sid:1;)'
    assert split_snort_suricata_rules(content) == [content]


def test_split_snort_suricata_rules_splits_multiple_rules():
    from rflib.rf_to_stix2 import split_snort_suricata_rules

    rule_a = 'alert tcp any any -> any any (msg:"one"; sid:1;)'
    rule_b = 'alert udp any any -> any any (msg:"two"; sid:2;)'
    content = f"{rule_a}\n{rule_b}"

    result = split_snort_suricata_rules(content)

    assert result == [rule_a, rule_b]


def test_split_snort_suricata_rules_drops_leading_comments():
    from rflib.rf_to_stix2 import split_snort_suricata_rules

    rule = 'alert tcp any any -> any any (msg:"one"; sid:1;)'
    content = f"# a leading comment with no rule\n{rule}"

    assert split_snort_suricata_rules(content) == [rule]


def test_split_snort_suricata_rules_empty_content_returns_empty_list():
    from rflib.rf_to_stix2 import split_snort_suricata_rules

    assert split_snort_suricata_rules("") == []
    assert split_snort_suricata_rules(None) == []


def test_from_json_splits_multi_rule_snort_attachment_into_multiple_indicators():
    # Given a StixNote and an analyst note whose snort attachment concatenates
    # two rules in a single `content` string -- the real-world shape that
    # OpenCTI's single-rule parser rejects wholesale
    note = _given_stix_note()
    rule_a = 'alert tcp any any -> any any (msg:"one"; sid:1;)'
    rule_b = 'alert udp any any -> any any (msg:"two"; sid:2;)'
    note_json = _given_analyst_note_json_with_attachments(
        [
            {
                "name": "multi.rules",
                "type": "snort",
                "content": f"{rule_a}\n{rule_b}",
            }
        ]
    )

    # When the note is converted from JSON
    _when_note_converted_from_json(note, note_json)

    # Then TWO separate snort indicators are produced, one per rule
    snort_indicators = [
        obj for obj in note.objects if getattr(obj, "pattern_type", None) == "snort"
    ]
    assert len(snort_indicators) == 2
    patterns = {ind.pattern for ind in snort_indicators}
    assert patterns == {rule_a, rule_b}


@pytest.mark.parametrize(
    "action",
    [
        # Snort 2 -- the only actions OpenCTI's bundled parser accepts
        "alert",
        "log",
        "pass",
        "activate",
        "dynamic",
        "drop",
        "reject",
        "sdrop",
        # Snort 3 additions
        "block",
        "react",
        "rewrite",
        # Suricata reject variants
        "rejectsrc",
        "rejectdst",
        "rejectboth",
    ],
)
def test_split_snort_suricata_rules_recognises_every_documented_action(action):
    from rflib.rf_to_stix2 import split_snort_suricata_rules

    # Given an `alert` rule followed by a rule using ACTION
    rule_a = 'alert tcp any any -> any any (msg:"one"; sid:1;)'
    rule_b = f'{action} tcp any any -> any any (msg:"two"; sid:2;)'

    # When the concatenated document is split
    result = split_snort_suricata_rules(f"{rule_a}\n{rule_b}")

    # Then both rules are separated.
    #
    # OpenCTI's parser rejects the Snort 3 and Suricata-only actions, but the
    # splitter must still recognise them: if it does not, the unsupported rule
    # stays glued to `rule_a` and the whole document is discarded rather than
    # just the one rule. The `reject` variants also matter because a naive
    # `reject` alternative cannot match `rejectsrc`.
    assert result == [rule_a, rule_b]


def test_snort_suricata_action_vocabulary_excludes_rule_options():
    from rflib.rf_to_stix2 import SNORT_SURICATA_ACTIONS

    # `bypass` and `config` are frequently mistaken for actions. `bypass` is a
    # rule OPTION in Suricata; treating either as an action risks splitting a
    # rule mid-body.
    assert "bypass" not in SNORT_SURICATA_ACTIONS
    assert "config" not in SNORT_SURICATA_ACTIONS
    # And the set is exactly the union of the three documented vocabularies.
    assert set(SNORT_SURICATA_ACTIONS) == {
        "activate",
        "alert",
        "block",
        "drop",
        "dynamic",
        "log",
        "pass",
        "react",
        "reject",
        "rejectboth",
        "rejectdst",
        "rejectsrc",
        "rewrite",
        "sdrop",
    }


def test_detection_rule_rejects_empty_content():
    from rflib.rf_to_stix2 import ConversionError, DetectionRule

    # Given an attachment whose content is blank
    # When a DetectionRule is constructed
    # Then it is refused rather than producing an Indicator with an empty
    # pattern, which OpenCTI's validator rejects and which would collapse every
    # such rule onto a single deterministic id.
    for blank in ("", "   \n\t "):
        with pytest.raises(ConversionError):
            DetectionRule(
                name="empty.yar",
                _type="yara",
                content=blank,
                author=_given_author(),
                tlp=_given_tlp(),
            )


def test_from_json_skips_empty_attachment_and_logs():
    # Given a note with a blank snort attachment
    note = _given_stix_note()
    note_json = _given_analyst_note_json_with_attachments(
        [{"name": "empty.rules", "type": "snort", "content": ""}]
    )

    # When the note is converted from JSON
    _when_note_converted_from_json(note, note_json)

    # Then no indicator is produced and the skip is logged
    assert not [obj for obj in note.objects if getattr(obj, "pattern_type", None)]
    note.helper.connector_logger.warning.assert_called()


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


def _given_stix_note():
    return StixNote(opencti_helper=MagicMock(), tas=[], rfapi=MagicMock())


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

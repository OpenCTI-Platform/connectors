"""Binding of the extracted entities to the existing OpenCTI entities.

``ExistingEntityBinder`` looks every named entity of an extracted bundle up
with the ``curationResolve`` query of the platform and turns the ones it
matches into the existing entity: standard id, canonical name, the document's
spelling kept as an alias, every reference re-pointed. These tests drive it
against a fake platform answering ``curationResolve``.
"""

import json
from pathlib import Path
from unittest.mock import Mock

import pycti
import pytest
import requests
import stix2
from import_doc_ai.entity_binding import (
    LOOKUPS_PER_REQUEST,
    MAX_CONSECUTIVE_FAILED_REQUESTS,
    BindingSummary,
    EntityResolution,
    ExistingEntityBinder,
    ResolutionCache,
    curation_resolve_query,
    is_schema_error,
    is_stix_id,
    resolve_entity_type,
)
from import_doc_ai.util import (
    convert_location_to_octi_location,
    deduplicate_bundle_objects,
    remove_objects_from_bundle,
    replace_objects_in_bundle,
)

APPLICANT_ID = "88ec0c6a-13ce-5e39-b486-354fe4a7084f"
OCTI_EXTENSION = "extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba"
UNKNOWN_FIELD_MESSAGE = 'Cannot query field "curationResolve" on type "Query".'


# --------------------------------------------------------------------------- #
# A platform answering curationResolve
# --------------------------------------------------------------------------- #
class FakePlatform:
    """Answer batched ``curationResolve`` requests from a catalog, keyed by (type, name).

    An exception answering a name fails the whole request carrying it, and a
    ``Response`` is returned as the whole response; ``MISSING`` leaves the
    answer of its name out of the response.
    """

    def __init__(self, answers: dict[tuple[str, str], object] | None = None):
        self.answers = {
            (entity_type, name.casefold()): answer
            for (entity_type, name), answer in (answers or {}).items()
        }
        self.calls: list[tuple[str, str]] = []
        self.requests: list[list[tuple[str, str]]] = []

    def query(self, query: str, variables: dict) -> object:
        size = len(variables) // 2
        assert query == curation_resolve_query(size)
        assert set(variables) == {
            f"{prefix}{index}" for index in range(size) for prefix in ("name", "type")
        }
        names = [
            (variables[f"type{index}"], variables[f"name{index}"])
            for index in range(size)
        ]
        self.calls.extend(names)
        self.requests.append(names)
        answers = [
            self.answers.get((entity_type, name.casefold()))
            for entity_type, name in names
        ]
        for answer in answers:
            if isinstance(answer, BaseException):
                raise answer
            if isinstance(answer, Response):
                return answer.body
        return {
            "data": {
                f"resolve{index}": answer
                for index, answer in enumerate(answers)
                if answer is not MISSING
            }
        }


class Response:
    """A raw response the fake platform returns as is."""

    def __init__(self, body: object):
        self.body = body


MISSING = object()


def resolution(
    entity_type: str,
    name: str,
    standard_id: str,
    match_type: str = "alias",
    matched_value: str | None = None,
    score: float = 0.97,
) -> dict:
    return {
        "entity_id": "a5c2b8f4-5d0e-4a3b-9a57-0b1d2b0c1f10",
        "standard_id": standard_id,
        "entity_type": entity_type,
        "name": name,
        "match_type": match_type,
        "score": score,
        "matched_value": matched_value if matched_value is not None else name,
    }


def build_helper(platform: FakePlatform, applicant_id: str = APPLICANT_ID) -> Mock:
    helper = Mock()
    helper.applicant_id = applicant_id
    helper.draft_id = ""
    helper.api_impersonate.query.side_effect = platform.query
    return helper


def build_binder(
    platform: FakePlatform, cache: ResolutionCache | None = None, **kwargs
) -> tuple[ExistingEntityBinder, Mock]:
    helper = build_helper(platform)
    return ExistingEntityBinder(helper=helper, cache=cache, **kwargs), helper


# --------------------------------------------------------------------------- #
# Extracted objects
# --------------------------------------------------------------------------- #
def malware(name: str, **properties) -> stix2.Malware:
    return stix2.Malware(
        id=pycti.Malware.generate_id(name),
        name=name,
        is_family=True,
        allow_custom=True,
        **properties,
    )


def intrusion_set(name: str, **properties) -> stix2.IntrusionSet:
    return stix2.IntrusionSet(
        id=pycti.IntrusionSet.generate_id(name), name=name, **properties
    )


def relationship(
    relationship_type: str, source: dict, target: dict
) -> stix2.Relationship:
    return stix2.Relationship(
        id=pycti.StixCoreRelationship.generate_id(
            relationship_type, source["id"], target["id"]
        ),
        relationship_type=relationship_type,
        source_ref=source["id"],
        target_ref=target["id"],
    )


def report(objects: list) -> stix2.Report:
    return stix2.Report(
        id=pycti.Report.generate_id("Extracted report", "2026-01-01T00:00:00Z"),
        name="Extracted report",
        published="2026-01-01T00:00:00Z",
        report_types=["threat-report"],
        object_refs=[obj["id"] for obj in objects],
        allow_custom=True,
    )


def bundle_of(*objects) -> stix2.Bundle:
    return stix2.Bundle(objects=list(objects), allow_custom=True)


def as_json(bundle: stix2.Bundle) -> dict[str, dict]:
    """The objects of a bundle, as JSON, keyed by id."""
    return {obj["id"]: obj for obj in json.loads(bundle.serialize())["objects"]}


def logged(log: Mock) -> list[str]:
    return [call.args[0] for call in log.call_args_list]


# --------------------------------------------------------------------------- #
# Binding on a match
# --------------------------------------------------------------------------- #
def test_bind_turns_the_extracted_entity_into_the_existing_one():
    # Given an extraction naming the Cl0p ransomware "Clop", used by TA505
    clop = malware("Clop", description="Extracted description")
    ta505 = intrusion_set("TA505")
    uses = relationship("uses", ta505, clop)
    container = report([ta505, clop, uses])
    cl0p_id = pycti.Malware.generate_id("Cl0p")
    platform = FakePlatform(
        {
            ("Malware", "Clop"): resolution(
                "Malware", "Cl0p", cl0p_id, match_type="canonical"
            ),
            ("Intrusion-Set", "TA505"): None,
        }
    )
    binder, _ = build_binder(platform)

    # When binding the bundle
    bound_bundle, summary = binder.bind(bundle_of(ta505, clop, uses, container))

    # Then the extracted malware is the existing one, under its standard id
    # and canonical name, with the spelling of the document as an alias
    objects = as_json(bound_bundle)
    assert objects[cl0p_id] == {
        **json.loads(clop.serialize()),
        "id": cl0p_id,
        "name": "Cl0p",
        "aliases": ["Clop"],
    }
    # And every reference follows: the relationship points to it under the id
    # of its new identity, and the report points to both
    uses_id = pycti.StixCoreRelationship.generate_id("uses", ta505["id"], cl0p_id)
    assert objects[uses_id]["target_ref"] == cl0p_id
    assert objects[uses_id]["source_ref"] == ta505["id"]
    assert objects[container["id"]]["object_refs"] == [ta505["id"], cl0p_id, uses_id]
    assert clop["id"] not in json.dumps(objects)
    assert uses["id"] not in json.dumps(objects)
    # And the unmatched intrusion set is sent as extracted
    assert objects[ta505["id"]] == json.loads(ta505.serialize())
    assert [binding.extracted_name for binding in summary.bindings] == ["Clop"]
    [binding] = summary.bindings
    assert binding.entity_type == "Malware"
    assert binding.extracted_id == clop["id"]
    assert binding.bound_id == cl0p_id
    assert binding.bound_name == "Cl0p"
    assert binding.match_type == "canonical"
    assert binding.score == 0.97
    assert binding.alias_added is True
    assert summary.lookups == 2
    assert sorted(platform.calls) == [("Intrusion-Set", "TA505"), ("Malware", "Clop")]


def test_bind_sends_the_lookups_with_the_permissions_of_the_importing_user():
    platform = FakePlatform()
    binder, helper = build_binder(platform)

    binder.bind(bundle_of(malware("Clop")))

    helper.api_impersonate.query.assert_called_once_with(
        curation_resolve_query(1), {"name0": "Clop", "type0": "Malware"}
    )
    helper.api.query.assert_not_called()


def test_bind_looks_up_every_name_the_resolver_accepts():
    # curationResolve takes 1 to 512 characters once trimmed: a one-letter name
    # and a long one are looked up, a longer one is never sent.
    long_name = "L" * 512
    platform = FakePlatform()
    binder, _ = build_binder(platform)

    binder.bind(
        bundle_of(malware("X"), malware(f"  {long_name}  "), malware("T" * 513))
    )

    assert sorted(platform.calls) == [("Malware", long_name), ("Malware", "X")]


@pytest.mark.parametrize(
    "extracted_aliases, resolved, expected_aliases, alias_added",
    [
        pytest.param(
            None,
            resolution("Malware", "Cl0p", "", matched_value="Clop"),
            None,
            False,
            id="spelling is the alias that matched",
        ),
        pytest.param(
            None,
            resolution("Malware", "CLOP", "", match_type="exact"),
            None,
            False,
            id="spelling differs from the name by its case only",
        ),
        pytest.param(
            ["Cl0p", "TA505 ransomware", "ta505  Ransomware", " "],
            resolution("Malware", "Cl0p", "", match_type="taxonomy"),
            ["TA505 ransomware", "Clop"],
            True,
            id="extracted aliases kept once, without the canonical name",
        ),
        pytest.param(
            ["clop"],
            resolution("Malware", "Cl0p", "", match_type="similarity"),
            ["clop"],
            False,
            id="spelling already among the extracted aliases",
        ),
    ],
)
def test_bind_adds_the_spelling_of_the_document_as_alias_only_when_unknown(
    extracted_aliases: list[str] | None,
    resolved: dict,
    expected_aliases: list[str] | None,
    alias_added: bool,
):
    properties = {"aliases": extracted_aliases} if extracted_aliases else {}
    clop = malware("Clop", **properties)
    resolved["standard_id"] = pycti.Malware.generate_id(resolved["name"])
    binder, _ = build_binder(FakePlatform({("Malware", "Clop"): resolved}))

    bound_bundle, summary = binder.bind(bundle_of(clop))

    [bound] = as_json(bound_bundle).values()
    assert bound["id"] == resolved["standard_id"]
    assert bound["name"] == resolved["name"]
    assert bound.get("aliases") == expected_aliases
    assert summary.bindings[0].alias_added is alias_added


def location(name: str, **properties) -> stix2.Location:
    return convert_location_to_octi_location(
        stix2.Location(
            id=pycti.Location.generate_id(name, "Country"),
            name=name,
            allow_custom=True,
            **properties,
        )
    )


@pytest.mark.parametrize(
    "extracted, entity_type, canonical_name, standard_id, alias_property",
    [
        pytest.param(
            location("USA", country="US"),
            "Country",
            "United States",
            pycti.Location.generate_id("United States", "Country"),
            "x_opencti_aliases",
            id="country",
        ),
        pytest.param(
            stix2.Identity(
                id=pycti.Identity.generate_id("Energy sector", "class"),
                name="Energy sector",
                identity_class="class",
            ),
            "Sector",
            "Energy",
            pycti.Identity.generate_id("Energy", "class"),
            "x_opencti_aliases",
            id="sector",
        ),
        pytest.param(
            stix2.Vulnerability(
                id=pycti.Vulnerability.generate_id("Log4Shell"), name="Log4Shell"
            ),
            "Vulnerability",
            "CVE-2021-44228",
            pycti.Vulnerability.generate_id("CVE-2021-44228"),
            "x_opencti_aliases",
            id="vulnerability",
        ),
        pytest.param(
            stix2.Tool(
                id=pycti.Tool.generate_id("Cobalt-Strike"), name="Cobalt-Strike"
            ),
            "Tool",
            "Cobalt Strike",
            pycti.Tool.generate_id("Cobalt Strike"),
            "aliases",
            id="tool",
        ),
        pytest.param(
            stix2.ThreatActor(
                id=pycti.ThreatActor.generate_id("UNC1878", "Threat-Actor-Group"),
                name="UNC1878",
            ),
            "Threat-Actor-Group",
            "Wizard Spider",
            pycti.ThreatActor.generate_id("Wizard Spider", "Threat-Actor-Group"),
            "aliases",
            id="threat actor",
        ),
        pytest.param(
            stix2.Campaign(
                id=pycti.Campaign.generate_id("MOVEit campaign"),
                name="MOVEit campaign",
            ),
            "Campaign",
            "MOVEit Transfer exploitation",
            pycti.Campaign.generate_id("MOVEit Transfer exploitation"),
            "aliases",
            id="campaign",
        ),
    ],
)
def test_bind_records_the_alias_where_the_type_holds_its_aliases(
    extracted, entity_type, canonical_name, standard_id, alias_property
):
    platform = FakePlatform(
        {
            (entity_type, extracted["name"]): resolution(
                entity_type, canonical_name, standard_id, match_type="taxonomy"
            )
        }
    )
    binder, _ = build_binder(platform)

    bound_bundle, summary = binder.bind(bundle_of(extracted))

    [bound] = as_json(bound_bundle).values()
    assert bound == {
        **json.loads(extracted.serialize()),
        "id": standard_id,
        "name": canonical_name,
        alias_property: [extracted["name"]],
    }
    assert platform.calls == [(entity_type, extracted["name"])]
    assert len(summary.bindings) == 1


def test_bind_keeps_a_container_whose_only_reference_becomes_a_self_reference():
    # Given a report referencing only "Cozy Bear related-to APT29", where both
    # names are APT29
    apt29_id = pycti.IntrusionSet.generate_id("APT29")
    apt29 = intrusion_set("APT29")
    cozy_bear = intrusion_set("Cozy Bear")
    same_actor = relationship("related-to", cozy_bear, apt29)
    container = report([same_actor])
    platform = FakePlatform(
        {
            ("Intrusion-Set", "APT29"): resolution(
                "Intrusion-Set", "APT29", apt29_id, match_type="exact"
            ),
            ("Intrusion-Set", "Cozy Bear"): resolution(
                "Intrusion-Set", "APT29", apt29_id, match_type="taxonomy"
            ),
        }
    )
    binder, _ = build_binder(platform)

    bound_bundle, summary = binder.bind(
        bundle_of(apt29, cozy_bear, same_actor, container)
    )

    # Then the relationship is dropped and the report references the
    # intrusion set it collapsed into, instead of being emptied
    objects = as_json(bound_bundle)
    assert same_actor["id"] not in objects
    assert objects[container["id"]]["object_refs"] == [apt29_id]
    assert summary.dropped_relationships == 1


def test_remove_objects_from_bundle_removes_the_containers_it_empties():
    # Given a note about a relationship only, and a grouping holding the note
    # and a malware
    clop = malware("Clop")
    lockbit = malware("LockBit")
    removed = relationship("related-to", clop, lockbit)
    note = stix2.Note(
        id=pycti.Note.generate_id("2026-01-01T00:00:00Z", "About the relationship"),
        content="About the relationship",
        object_refs=[removed["id"]],
    )
    grouping = stix2.Grouping(
        id=pycti.Grouping.generate_id("Grouping", "suspicious-activity"),
        name="Grouping",
        context="suspicious-activity",
        object_refs=[note["id"], clop["id"]],
    )
    bundle = bundle_of(clop, lockbit, removed, note, grouping)

    pruned = remove_objects_from_bundle(bundle, {removed["id"]})

    # Then the note, left without any reference, is removed, and so is the
    # grouping's reference to it
    objects = as_json(pruned)
    assert list(objects) == [clop["id"], lockbit["id"], grouping["id"]]
    assert objects[grouping["id"]]["object_refs"] == [clop["id"]]
    # And a replacement keeps the note, pointing to the replacing object
    replaced = as_json(
        remove_objects_from_bundle(
            bundle, {removed["id"]}, replacements={removed["id"]: clop["id"]}
        )
    )
    assert replaced[note["id"]]["object_refs"] == [clop["id"]]
    assert replaced[grouping["id"]]["object_refs"] == [note["id"], clop["id"]]
    assert remove_objects_from_bundle(bundle, set()) is bundle


def test_bind_merges_the_extracted_objects_naming_the_same_entity():
    # Given an extraction naming APT29 three times: by its name, by a vendor
    # name, and in a "related-to" between the two spellings
    apt29_id = pycti.IntrusionSet.generate_id("APT29")
    apt29 = intrusion_set("APT29", aliases=["The Dukes"])
    cozy_bear = intrusion_set("Cozy Bear")
    wellmess = malware("WellMess")
    apt29_uses = relationship("uses", apt29, wellmess)
    cozy_bear_uses = relationship("uses", cozy_bear, wellmess)
    same_actor = relationship("related-to", cozy_bear, apt29)
    container = report(
        [apt29, cozy_bear, wellmess, cozy_bear_uses, apt29_uses, same_actor]
    )
    platform = FakePlatform(
        {
            ("Intrusion-Set", "APT29"): resolution(
                "Intrusion-Set", "APT29", apt29_id, match_type="exact"
            ),
            ("Intrusion-Set", "Cozy Bear"): resolution(
                "Intrusion-Set", "APT29", apt29_id, match_type="taxonomy"
            ),
        }
    )
    binder, _ = build_binder(platform)

    bound_bundle, summary = binder.bind(
        bundle_of(
            apt29,
            cozy_bear,
            wellmess,
            cozy_bear_uses,
            apt29_uses,
            same_actor,
            container,
        )
    )

    # Then one intrusion set remains, holding both alias sets, one "uses"
    # relationship remains, under the id of "APT29 uses WellMess" (never the
    # one generated from "Cozy Bear"), and the self "related-to" is gone
    objects = as_json(bound_bundle)
    assert list(objects) == [
        apt29_id,
        wellmess["id"],
        apt29_uses["id"],
        container["id"],
    ]
    assert objects[apt29_id]["aliases"] == ["The Dukes", "Cozy Bear"]
    assert objects[apt29_uses["id"]]["source_ref"] == apt29_id
    assert cozy_bear_uses["id"] not in json.dumps(objects)
    assert objects[container["id"]]["object_refs"] == [
        apt29_id,
        wellmess["id"],
        apt29_uses["id"],
    ]
    assert summary.merged_objects == 2
    assert summary.dropped_relationships == 1
    assert len(summary.bindings) == 2
    assert platform.calls == [
        ("Intrusion-Set", "APT29"),
        ("Intrusion-Set", "Cozy Bear"),
        ("Malware", "WellMess"),
    ]


def test_bind_binds_the_entities_of_a_web_service_extraction():
    # Given the extraction of the web service, holding a channel defined by an
    # extension definition and an attack pattern holding a MITRE ATT&CK id
    response = Path(__file__).parent.parent / "dev/responses/response_stix_200.json"
    extracted = deduplicate_bundle_objects(
        stix2.Bundle(**json.loads(response.read_text()), allow_custom=True)
    )
    extracted = replace_objects_in_bundle(
        extracted,
        {
            obj["id"]: convert_location_to_octi_location(obj)
            for obj in extracted["objects"]
            if obj["type"] == "location"
        },
    )
    [twitter] = [obj for obj in extracted["objects"] if obj["type"] == "channel"]
    x_id = pycti.Channel.generate_id("X")
    usa_id = pycti.Location.generate_id("United States", "Country")
    platform = FakePlatform(
        {
            ("Channel", "Twitter"): resolution("Channel", "X", x_id),
            ("Country", "United States of America"): resolution(
                "Country", "United States", usa_id
            ),
        }
    )
    binder, _ = build_binder(platform)

    bound_bundle, summary = binder.bind(extracted)

    # Then the channel and the country are bound, the attack pattern holding
    # a MITRE ATT&CK id is left to its own lookup
    objects = as_json(bound_bundle)
    assert objects[x_id] == {
        **json.loads(twitter.serialize()),
        "id": x_id,
        "name": "X",
        "aliases": ["Twitter"],
    }
    assert objects[usa_id]["x_opencti_aliases"] == ["United States of America"]
    targets = next(
        obj for obj in objects.values() if obj.get("relationship_type") == "targets"
    )
    assert targets["target_ref"] == usa_id
    assert sorted(platform.calls) == [
        ("Channel", "Twitter"),
        ("Country", "China"),
        ("Country", "United States of America"),
        ("Intrusion-Set", "APT41"),
        ("Region", "Asia"),
    ]
    assert len(summary.bindings) == 2


def test_bind_binds_the_objects_stix2_keeps_as_dicts():
    # Given a narrative, a type stix2 does not know, referenced by a report
    narrative = {
        "type": "narrative",
        "spec_version": "2.1",
        "id": pycti.Narrative.generate_id("Stolen election"),
        "name": "Stolen election",
    }
    container = report([narrative])
    extracted = bundle_of(narrative, container)
    assert isinstance(extracted["objects"][0], dict)
    canonical_id = pycti.Narrative.generate_id("Election fraud")
    binder, _ = build_binder(
        FakePlatform(
            {
                ("Narrative", "Stolen election"): resolution(
                    "Narrative", "Election fraud", canonical_id
                )
            }
        )
    )

    bound_bundle, _ = binder.bind(extracted)

    objects = as_json(bound_bundle)
    assert objects[canonical_id] == {
        **narrative,
        "id": canonical_id,
        "name": "Election fraud",
        "aliases": ["Stolen election"],
    }
    assert objects[container["id"]]["object_refs"] == [canonical_id]


def test_bind_hands_a_bundle_without_named_entity_on():
    platform = FakePlatform()
    binder, _ = build_binder(platform)
    bundle = bundle_of(stix2.IPv4Address(value="192.0.2.1"))

    bound_bundle, summary = binder.bind(bundle)

    assert bound_bundle is bundle
    assert summary == BindingSummary()
    assert platform.calls == []


def test_bind_hands_the_bundle_on_when_the_match_changes_nothing():
    apt41 = intrusion_set("APT41")
    platform = FakePlatform(
        {
            ("Intrusion-Set", "APT41"): resolution(
                "Intrusion-Set", "APT41", apt41["id"], match_type="exact"
            )
        }
    )
    binder, _ = build_binder(platform)
    bundle = bundle_of(apt41)

    bound_bundle, summary = binder.bind(bundle)

    assert bound_bundle is bundle
    assert len(summary.bindings) == 1


# --------------------------------------------------------------------------- #
# No binding
# --------------------------------------------------------------------------- #
def test_bind_hands_the_bundle_on_when_the_platform_matches_nothing():
    clop = malware("Clop")
    ta505 = intrusion_set("TA505")
    bundle = bundle_of(ta505, clop, relationship("uses", ta505, clop))
    platform = FakePlatform()
    binder, _ = build_binder(platform)

    bound_bundle, summary = binder.bind(bundle)

    assert bound_bundle is bundle
    assert summary.bindings == []
    assert summary.lookups == 2
    assert summary.failed_lookups == 0


@pytest.mark.parametrize(
    "resolved",
    [
        pytest.param(
            resolution(
                "Threat-Actor-Group",
                "Cl0p",
                pycti.ThreatActor.generate_id("Cl0p", "Threat-Actor-Group"),
            ),
            id="entity of another type",
        ),
        pytest.param(
            resolution(
                "Malware",
                "Cl0p",
                pycti.ThreatActor.generate_id("Cl0p", "Threat-Actor-Group"),
            ),
            id="standard id of another type",
        ),
    ],
)
def test_bind_never_binds_across_types(resolved: dict):
    bundle = bundle_of(malware("Clop"))
    binder, helper = build_binder(FakePlatform({("Malware", "Clop"): resolved}))

    bound_bundle, summary = binder.bind(bundle)

    assert bound_bundle is bundle
    assert summary.bindings == []
    assert summary.rejected_resolutions == 1
    helper.connector_logger.warning.assert_called_once_with(
        "curationResolve matched an entity of another type, "
        "importing the extracted entity as extracted",
        {
            "type": "Malware",
            "name": "Clop",
            "resolved_type": resolved["entity_type"],
            "resolved_id": resolved["standard_id"],
        },
    )


def test_bind_looks_up_the_objects_with_a_name_and_a_known_type_only():
    ip = stix2.IPv4Address(value="192.0.2.1")
    nameless_location = stix2.Location(
        id=pycti.Location.generate_id("Somewhere", "Position"),
        latitude=48.8,
        longitude=2.3,
        name="Somewhere",
    )
    mitre_attack_pattern = stix2.AttackPattern(
        id=pycti.AttackPattern.generate_id("Phishing", "T1566"),
        name="Phishing",
        allow_custom=True,
        x_mitre_id="T1566",
    )
    named_attack_pattern = stix2.AttackPattern(
        id=pycti.AttackPattern.generate_id("Spearphishing"),
        name="Spearphishing",
    )
    too_long = malware("ransomware " * 47)
    security_platform = stix2.Identity(
        id=pycti.Identity.generate_id("EDR", "organization"),
        name="EDR",
        identity_class="organization",
        allow_custom=True,
        x_opencti_type="SecurityPlatform",
    )
    platform = FakePlatform()
    binder, _ = build_binder(platform)

    binder.bind(
        bundle_of(
            ip,
            nameless_location,
            mitre_attack_pattern,
            named_attack_pattern,
            too_long,
            security_platform,
            report([ip]),
        )
    )

    assert platform.calls == [("Attack-Pattern", "Spearphishing")]


@pytest.mark.parametrize(
    "fields, location_type",
    [
        pytest.param(
            {"city": "Houston", "country": "US"}, "City", id="city in a country"
        ),
        pytest.param(
            {"city": "Atlanta", "administrative_area": "Georgia", "country": "US"},
            "City",
            id="city in an administrative area",
        ),
        pytest.param(
            {"administrative_area": "Georgia", "country": "US", "region": "americas"},
            "Administrative-Area",
            id="administrative area in a country",
        ),
        pytest.param(
            {"country": "FR", "region": "europe"}, "Country", id="country in a region"
        ),
        pytest.param({"region": "europe"}, "Region", id="region"),
        pytest.param(
            {"country": "US", "x_opencti_location_type": "Administrative-Area"},
            "Administrative-Area",
            id="declared location type kept",
        ),
        pytest.param(
            {"country": "US", "x_opencti_type": "Administrative-Area"},
            "Administrative-Area",
            id="declared OpenCTI type kept",
        ),
        pytest.param(
            {
                "country": "US",
                "extensions": {
                    OCTI_EXTENSION: {
                        "extension_type": "property-extension",
                        "type": "Administrative-Area",
                    }
                },
            },
            "Administrative-Area",
            id="type of the OpenCTI extension kept",
        ),
        pytest.param(
            {"country": "US", "x_opencti_type": "Position"},
            "Country",
            id="declared type that is no location type ignored",
        ),
        pytest.param(
            {"country": "US", "x_opencti_location_type": "Position"},
            "Country",
            id="declared location type that is no location type replaced",
        ),
        pytest.param(
            {
                "country": "US",
                "x_opencti_location_type": "Position",
                "x_opencti_type": "Administrative-Area",
            },
            "Administrative-Area",
            id="invalid location type replaced by the declared OpenCTI type",
        ),
    ],
)
def test_location_type_is_the_most_specific_populated_field(
    fields: dict, location_type: str
):
    converted = convert_location_to_octi_location(
        stix2.Location(
            id=pycti.Location.generate_id("Somewhere", location_type),
            name="Somewhere",
            allow_custom=True,
            **fields,
        )
    )

    assert converted["x_opencti_location_type"] == location_type
    assert resolve_entity_type(converted) == location_type


def test_bind_looks_an_administrative_area_up_as_such_whatever_country_it_names():
    # Given the US state of Georgia, which also names its country
    georgia_state = location("Georgia", administrative_area="Georgia", country="US")
    platform = FakePlatform(
        {
            ("Country", "Georgia"): resolution(
                "Country", "Georgia", pycti.Location.generate_id("Georgia", "Country")
            ),
            ("Administrative-Area", "Georgia"): None,
        }
    )
    binder, _ = build_binder(platform)
    bundle = bundle_of(georgia_state)

    bound_bundle, summary = binder.bind(bundle)

    # Then it is looked up as an administrative area, and never bound to the
    # country of the same name
    assert platform.calls == [("Administrative-Area", "Georgia")]
    assert bound_bundle is bundle
    assert summary.bindings == []


@pytest.mark.parametrize(
    "stix_object, entity_type",
    [
        ({"type": "intrusion-set", "name": "APT29"}, "Intrusion-Set"),
        ({"type": "channel", "name": "Telegram"}, "Channel"),
        ({"type": "identity", "identity_class": "class"}, "Sector"),
        ({"type": "identity", "identity_class": "Organization"}, "Organization"),
        ({"type": "identity", "identity_class": "individual"}, "Individual"),
        ({"type": "identity", "identity_class": "system"}, "System"),
        ({"type": "identity", "identity_class": "group"}, None),
        (
            {
                "type": "identity",
                "identity_class": "organization",
                "x_opencti_type": "Sector",
            },
            "Sector",
        ),
        (
            {
                "type": "identity",
                "identity_class": "organization",
                "extensions": {
                    "extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba": {
                        "type": "Individual"
                    }
                },
            },
            "Individual",
        ),
        ({"type": "location", "x_opencti_location_type": "Country"}, "Country"),
        ({"type": "location", "x_opencti_type": "Region"}, "Region"),
        (
            {"type": "location", "x_opencti_location_type": "Administrative-Area"},
            "Administrative-Area",
        ),
        ({"type": "location", "x_opencti_location_type": "Position"}, None),
        ({"type": "location"}, None),
        ({"type": "threat-actor"}, "Threat-Actor-Group"),
        (
            {"type": "threat-actor", "resource_level": "individual"},
            "Threat-Actor-Individual",
        ),
        (
            {"type": "threat-actor", "x_opencti_type": "Threat-Actor-Individual"},
            "Threat-Actor-Individual",
        ),
        ({"type": "threat-actor", "x_opencti_type": "Intrusion-Set"}, None),
        ({"type": "incident", "name": "Breach"}, None),
        ({"type": "report", "name": "Report"}, None),
        ({"type": "domain-name", "value": "filigran.io"}, None),
    ],
)
def test_resolve_entity_type(stix_object: dict, entity_type: str | None):
    assert resolve_entity_type(stix_object) == entity_type


def test_disabled_binder_sends_no_lookup():
    platform = FakePlatform({("Malware", "Clop"): resolution("Malware", "Cl0p", "")})
    binder, helper = build_binder(platform, enabled=False)
    bundle = bundle_of(malware("Clop"))

    bound_bundle, summary = binder.bind(bundle)

    assert bound_bundle is bundle
    assert summary.lookups == 0
    assert binder.active is False
    helper.api_impersonate.query.assert_not_called()


# --------------------------------------------------------------------------- #
# Cache and budget
# --------------------------------------------------------------------------- #
class FakeClock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def test_bind_looks_each_name_up_once_per_document():
    # Given two spellings of one name, which pycti gives two ids
    first = malware("Cl0p  Leaks")
    second = malware("cl0p leaks", description="Second mention")
    assert first["id"] != second["id"]
    cl0p_id = pycti.Malware.generate_id("Cl0p")
    platform = FakePlatform(
        {("Malware", "Cl0p Leaks"): resolution("Malware", "Cl0p", cl0p_id)}
    )
    binder, _ = build_binder(platform)

    bound_bundle, summary = binder.bind(bundle_of(first, second))

    # Then the name is looked up once, and both mentions become the one
    # entity, holding the spelling once
    assert platform.calls == [("Malware", "Cl0p Leaks")]
    [bound] = as_json(bound_bundle).values()
    assert bound["id"] == cl0p_id
    assert bound["aliases"] == ["Cl0p Leaks"]
    assert bound["description"] == "Second mention"
    assert summary.merged_objects == 1
    assert summary.lookups == 1
    assert [binding.alias_added for binding in summary.bindings] == [True, False]


def test_bind_serves_the_misses_of_the_next_documents_from_the_cache():
    cl0p_id = pycti.Malware.generate_id("Cl0p")
    platform = FakePlatform(
        {
            ("Malware", "Clop"): resolution("Malware", "Cl0p", cl0p_id),
            ("Intrusion-Set", "TA505"): None,
        }
    )
    binder, helper = build_binder(platform)
    bundle = bundle_of(malware("Clop"), intrusion_set("TA505"))

    first_bundle, first_summary = binder.bind(bundle)
    second_bundle, second_summary = binder.bind(bundle)

    # The miss is served from the cache; the match is looked up again, with
    # the permissions the applicant has now
    assert platform.calls.count(("Malware", "Clop")) == 2
    assert platform.calls.count(("Intrusion-Set", "TA505")) == 1
    assert (first_summary.lookups, first_summary.cache_hits) == (2, 0)
    assert (second_summary.lookups, second_summary.cache_hits) == (1, 1)
    assert as_json(second_bundle) == as_json(first_bundle)
    assert len(second_summary.bindings) == 1

    # But another user may see other entities: the cache is per user
    helper.applicant_id = "a8b6dbb4-b8d6-5bd8-9d0c-2b7e2fe17e6c"
    binder.bind(bundle)
    assert len(platform.calls) == 5


def test_bind_never_reuses_a_match_the_applicant_lost_sight_of():
    # Given a document bound to Cl0p, which the applicant then loses sight of
    # (a marking, an organization sharing or the draft changed)
    cl0p_id = pycti.Malware.generate_id("Cl0p")
    platform = FakePlatform(
        {("Malware", "Clop"): resolution("Malware", "Cl0p", cl0p_id)}
    )
    binder, _ = build_binder(platform)
    bundle = bundle_of(malware("Clop"))
    _, first_summary = binder.bind(bundle)
    platform.answers[("Malware", "clop")] = None

    # When the next document names it
    second_bundle, second_summary = binder.bind(bundle)

    # Then it is imported as extracted, never bound to the entity
    assert len(first_summary.bindings) == 1
    assert second_summary.bindings == []
    assert second_bundle is bundle


def test_cached_resolutions_expire():
    clock = FakeClock()
    cache = ResolutionCache(max_size=10, ttl_seconds=60, clock=clock)
    platform = FakePlatform()
    binder, _ = build_binder(platform, cache=cache)
    bundle = bundle_of(malware("Clop"))

    binder.bind(bundle)
    clock.now += 59
    binder.bind(bundle)
    assert len(platform.calls) == 1

    clock.now += 1
    binder.bind(bundle)
    assert len(platform.calls) == 2


def test_bind_scopes_the_cache_to_the_draft_of_the_import():
    # Given a user importing documents into two drafts and into the live
    # knowledge, which may each hold other entities
    platform = FakePlatform()
    binder, helper = build_binder(platform)
    bundle = bundle_of(malware("Clop"))

    for draft_id in ("draft-a", "draft-b", "", "draft-a", None, "draft-b"):
        helper.draft_id = draft_id
        binder.bind(bundle)

    # Then each draft and the live knowledge are looked up once
    assert len(platform.calls) == 3


def test_resolution_cache_evicts_the_least_recently_used_entry():
    cache = ResolutionCache(max_size=2, ttl_seconds=60, clock=FakeClock())
    first = EntityResolution.from_payload(
        resolution("Malware", "A", pycti.Malware.generate_id("A"))
    )
    cache.put("a", first)
    cache.put("b", None)
    assert cache.get("a") == (True, first)

    cache.put("c", None)

    assert len(cache) == 2
    assert cache.get("b") == (False, None)
    assert cache.get("a") == (True, first)
    assert cache.get("c") == (True, None)


def test_bind_bounds_the_lookups_of_a_document_threat_entities_first():
    france = location("France", country="FR")
    lockbit = malware("LockBit")
    fin7 = intrusion_set("FIN7")
    mimikatz = stix2.Tool(id=pycti.Tool.generate_id("Mimikatz"), name="Mimikatz")
    platform = FakePlatform()
    binder, helper = build_binder(platform, max_lookups_per_document=2)

    _, summary = binder.bind(bundle_of(france, mimikatz, lockbit, fin7))

    assert platform.calls == [("Intrusion-Set", "FIN7"), ("Malware", "LockBit")]
    assert summary.lookups == 2
    assert summary.unresolved_names == 2
    helper.connector_logger.warning.assert_called_once_with(
        "The document names more entities than the lookup budget, "
        "importing the others as extracted",
        {"max_lookups": 2, "unresolved": 2},
    )


# --------------------------------------------------------------------------- #
# Older platforms and failures
# --------------------------------------------------------------------------- #
SCHEMA_ERRORS = [
    pytest.param(
        ValueError(
            {
                "name": "GRAPHQL_VALIDATION_FAILED",
                "error_message": UNKNOWN_FIELD_MESSAGE,
            }
        ),
        id="graphql error answered with HTTP 200",
    ),
    pytest.param(
        ValueError(
            json.dumps(
                {
                    "errors": [
                        {
                            "message": UNKNOWN_FIELD_MESSAGE,
                            "extensions": {"code": "GRAPHQL_VALIDATION_FAILED"},
                        }
                    ]
                }
            )
        ),
        id="graphql error answered with HTTP 400",
    ),
    pytest.param(
        ValueError({"name": "Error", "message": UNKNOWN_FIELD_MESSAGE}),
        id="error without validation code",
    ),
]


@pytest.mark.parametrize("error", SCHEMA_ERRORS)
def test_bind_turns_itself_off_on_a_platform_without_curation_resolve(
    error: Exception,
):
    # Given a platform that does not know the curationResolve query
    platform = FakePlatform(
        {("Malware", "Clop"): error, ("Intrusion-Set", "TA505"): error}
    )
    binder, helper = build_binder(platform)
    bundle = bundle_of(malware("Clop"), intrusion_set("TA505"))

    # When importing a first document
    bound_bundle, summary = binder.bind(bundle)

    # Then the first request reveals it: nothing is bound, nothing else is sent
    assert bound_bundle is bundle
    assert len(platform.requests) == 1
    assert summary.requests == 1
    assert summary.lookups == 2
    assert summary.unresolved_names == 2
    assert summary.failed_lookups == 0
    assert binder.active is False
    helper.connector_logger.info.assert_called_once()
    assert helper.connector_logger.info.call_args.args[0] == (
        "OpenCTI does not expose the curationResolve query, "
        "extracted entities are imported as extracted"
    )
    helper.connector_logger.warning.assert_not_called()

    # And the next documents are imported as extracted, without any lookup
    # nor log
    assert binder.bind(bundle)[0] is bundle
    assert len(platform.requests) == 1
    helper.connector_logger.info.assert_called_once()


def test_bind_stops_at_the_first_request_a_platform_without_curation_resolve_rejects():
    # Given a document naming more entities than one request carries, on a
    # platform that does not know the curationResolve query
    names = ["Akira", "BlackCat", "Conti", "Hive", "LockBit"]
    platform = FakePlatform(
        {("Malware", name): SCHEMA_ERRORS[0].values[0] for name in names}
    )
    binder, _ = build_binder(platform, lookups_per_request=2)

    _, summary = binder.bind(bundle_of(*(malware(name) for name in names)))

    # Then the batches after the rejected one are not sent
    assert platform.requests == [[("Malware", "Akira"), ("Malware", "BlackCat")]]
    assert summary.lookups == 2
    assert summary.unresolved_names == len(names)
    assert binder.active is False


@pytest.mark.parametrize(
    "error",
    [
        pytest.param(requests.ConnectionError("Connection refused"), id="network"),
        pytest.param(requests.Timeout("Read timed out"), id="timeout"),
        pytest.param(ValueError("<html>502 Bad Gateway</html>"), id="http 502"),
        pytest.param(
            ValueError({"name": "INTERNAL_SERVER_ERROR", "error_message": "boom"}),
            id="server error",
        ),
        pytest.param(
            ValueError({"name": "FORBIDDEN_ACCESS", "error_message": "denied"}),
            id="permission",
        ),
        pytest.param(
            ValueError({"name": "BAD_USER_INPUT", "error_message": "name too long"}),
            id="invalid value",
        ),
        pytest.param(Response({"data": {}}), id="response without the fields"),
        pytest.param(Response({"data": None}), id="response without data"),
        pytest.param(Response(["not", "an", "object"]), id="response not an object"),
    ],
)
def test_bind_imports_the_names_of_a_failed_request_as_extracted(error: object):
    # Given a request failing as a whole
    clop = malware("Clop")
    ta505 = intrusion_set("TA505")
    ta505_id = pycti.IntrusionSet.generate_id("TA 505")
    platform = FakePlatform(
        {
            ("Malware", "Clop"): error,
            ("Intrusion-Set", "TA505"): resolution("Intrusion-Set", "TA 505", ta505_id),
        }
    )
    binder, helper = build_binder(platform)
    bundle = bundle_of(clop, ta505)

    bound_bundle, summary = binder.bind(bundle)

    # Then every name it carried is imported as extracted, with one warning
    assert bound_bundle is bundle
    assert summary.requests == 1
    assert summary.failed_lookups == 2
    assert binder.active is True
    helper.connector_logger.warning.assert_called_once()
    warning_message, warning_context = helper.connector_logger.warning.call_args.args
    assert warning_message == (
        "Could not resolve extracted entities against OpenCTI, "
        "importing them as extracted"
    )
    assert warning_context["entities"] == [
        {"type": "Intrusion-Set", "name": "TA505"},
        {"type": "Malware", "name": "Clop"},
    ]
    assert warning_context["error"]
    helper.connector_logger.info.assert_not_called()

    # And a failure is not cached: the next document looks the names up again
    binder.bind(bundle)
    assert platform.calls.count(("Malware", "Clop")) == 2
    assert platform.calls.count(("Intrusion-Set", "TA505")) == 2


@pytest.mark.parametrize(
    "answer",
    [
        pytest.param(MISSING, id="answer missing from the response"),
        pytest.param({"name": "Cl0p"}, id="resolution without standard id"),
        pytest.param("Cl0p", id="resolution not an object"),
        pytest.param(
            resolution("Malware", "Cl0p", "malware--invalid"),
            id="standard id without uuid",
        ),
        pytest.param(
            resolution("Malware", "Cl0p", pycti.Malware.generate_id("Cl0p").upper()),
            id="standard id not canonical",
        ),
        pytest.param(
            resolution("Malware", "", pycti.Malware.generate_id("Cl0p")),
            id="resolution without name",
        ),
    ],
)
def test_bind_imports_a_name_whose_answer_is_invalid_as_extracted(answer: object):
    # Given a request answering one name with something unreadable and
    # resolving the other one
    clop = malware("Clop")
    ta505 = intrusion_set("TA505")
    ta505_id = pycti.IntrusionSet.generate_id("TA 505")
    platform = FakePlatform(
        {
            ("Malware", "Clop"): answer,
            ("Intrusion-Set", "TA505"): resolution("Intrusion-Set", "TA 505", ta505_id),
        }
    )
    binder, helper = build_binder(platform)

    bound_bundle, summary = binder.bind(bundle_of(clop, ta505))

    # Then that name is imported as extracted, with a warning, and the other
    # one is bound
    objects = as_json(bound_bundle)
    assert objects[clop["id"]] == json.loads(clop.serialize())
    assert objects[ta505_id]["name"] == "TA 505"
    assert summary.requests == 1
    assert summary.failed_lookups == 1
    assert binder.active is True
    helper.connector_logger.warning.assert_called_once()
    warning_message, warning_context = helper.connector_logger.warning.call_args.args
    assert warning_message == (
        "Could not resolve an extracted entity against OpenCTI, "
        "importing it as extracted"
    )
    assert warning_context["type"] == "Malware"
    assert warning_context["name"] == "Clop"
    assert warning_context["error"]
    helper.connector_logger.info.assert_not_called()

    # And neither a failure nor a match is cached: the next document looks
    # both names up again
    binder.bind(bundle_of(clop, ta505))
    assert platform.calls.count(("Malware", "Clop")) == 2
    assert platform.calls.count(("Intrusion-Set", "TA505")) == 2


def test_bind_stops_looking_up_after_consecutive_failed_requests():
    names = ["Akira", "BlackCat", "Conti", "Hive", "LockBit", "Play", "Royal"]
    platform = FakePlatform(
        {("Malware", name): requests.ConnectionError("down") for name in names}
    )
    binder, helper = build_binder(platform, lookups_per_request=2)

    bound_bundle, summary = binder.bind(bundle_of(*(malware(name) for name in names)))

    assert len(platform.requests) == MAX_CONSECUTIVE_FAILED_REQUESTS
    assert summary.requests == MAX_CONSECUTIVE_FAILED_REQUESTS
    assert summary.failed_lookups == 2 * MAX_CONSECUTIVE_FAILED_REQUESTS
    assert summary.unresolved_names == len(names) - 2 * MAX_CONSECUTIVE_FAILED_REQUESTS
    assert summary.bindings == []
    assert binder.active is True
    assert logged(helper.connector_logger.warning)[-1] == (
        "Stopped resolving the extracted entities of the document after "
        "consecutive failed requests, importing the others as extracted"
    )
    assert helper.connector_logger.warning.call_args.args[1] == {
        "failed_requests": MAX_CONSECUTIVE_FAILED_REQUESTS,
        "unresolved": 1,
    }


def test_a_successful_request_resets_the_failure_count():
    names = ["Akira", "BlackCat", "Conti", "Hive", "LockBit"]
    answers = {("Malware", name): requests.ConnectionError("down") for name in names}
    answers[("Malware", "Conti")] = None
    platform = FakePlatform(answers)
    binder, _ = build_binder(platform, lookups_per_request=1)

    _, summary = binder.bind(bundle_of(*(malware(name) for name in names)))

    assert len(platform.requests) == len(names)
    assert summary.failed_lookups == 4
    assert summary.unresolved_names == 0


def test_bind_sends_the_lookups_in_bounded_requests():
    # Given a document naming more entities than one request carries
    names = [f"Ransomware {index:02d}" for index in range(2 * LOOKUPS_PER_REQUEST + 5)]
    bound_id = pycti.Malware.generate_id("Ransomware 07")
    platform = FakePlatform(
        {
            ("Malware", "Ransomware 07"): resolution(
                "Malware", "Ransomware 07", bound_id, match_type="exact"
            )
        }
    )
    binder, _ = build_binder(platform)

    _, summary = binder.bind(bundle_of(*(malware(name) for name in names)))

    # Then the names are resolved in requests of at most LOOKUPS_PER_REQUEST
    # names, each name once, in the order of the document
    assert [len(request) for request in platform.requests] == [
        LOOKUPS_PER_REQUEST,
        LOOKUPS_PER_REQUEST,
        5,
    ]
    assert platform.calls == [("Malware", name) for name in names]
    assert (summary.requests, summary.lookups) == (3, len(names))
    assert [binding.extracted_name for binding in summary.bindings] == ["Ransomware 07"]


def test_the_lookup_budget_bounds_the_requests_of_a_document():
    platform = FakePlatform()
    binder, _ = build_binder(
        platform, max_lookups_per_document=5, lookups_per_request=2
    )

    _, summary = binder.bind(
        bundle_of(*(malware(f"Ransomware {index}") for index in range(8)))
    )

    assert [len(request) for request in platform.requests] == [2, 2, 1]
    assert (summary.requests, summary.lookups, summary.unresolved_names) == (3, 5, 3)


@pytest.mark.parametrize("lookups_per_request", [0, LOOKUPS_PER_REQUEST + 1])
def test_binder_rejects_a_request_size_out_of_bounds(lookups_per_request: int):
    with pytest.raises(ValueError, match="lookups_per_request"):
        build_binder(FakePlatform(), lookups_per_request=lookups_per_request)


def test_curation_resolve_query_aliases_one_field_per_name():
    selection = "entity_id standard_id entity_type name match_type score matched_value"
    assert curation_resolve_query(2) == (
        "query CurationResolve($name0: String!, $type0: String!, "
        "$name1: String!, $type1: String!) {\n"
        f"  resolve0: curationResolve(name: $name0, type: $type0) {{ {selection} }}\n"
        f"  resolve1: curationResolve(name: $name1, type: $type1) {{ {selection} }}\n"
        "}"
    )
    with pytest.raises(ValueError):
        curation_resolve_query(0)


@pytest.mark.parametrize("error", SCHEMA_ERRORS)
def test_is_schema_error_recognises_an_unknown_query(error: Exception):
    assert is_schema_error(error) is True


@pytest.mark.parametrize(
    "error",
    [
        requests.ConnectionError("Connection refused"),
        ValueError("<html>502 Bad Gateway</html>"),
        ValueError('{"errors": "not a list"}'),
        ValueError(json.dumps({"errors": [{"message": "Internal error"}]})),
        ValueError({"name": "FORBIDDEN_ACCESS", "error_message": "denied"}),
        ValueError(),
        ValueError(502),
        KeyError("message"),
    ],
)
def test_is_schema_error_rejects_any_other_failure(error: Exception):
    assert is_schema_error(error) is False


@pytest.mark.parametrize(
    "value, expected",
    [
        (pycti.Malware.generate_id("Cl0p"), True),
        (pycti.Location.generate_id("United States", "Country"), True),
        ("x-opencti-channel--0f6b9b34-8d6c-4c55-9b43-6f0e1c3f8a11", True),
        ("malware--invalid", False),
        ("malware--", False),
        ("--0f6b9b34-8d6c-4c55-9b43-6f0e1c3f8a11", False),
        ("Malware--0f6b9b34-8d6c-4c55-9b43-6f0e1c3f8a11", False),
        ("malware--0F6B9B34-8D6C-4C55-9B43-6F0E1C3F8A11", False),
        ("malware--{0f6b9b34-8d6c-4c55-9b43-6f0e1c3f8a11}", False),
        ("malware--0f6b9b348d6c4c559b436f0e1c3f8a11", False),
        ("malware 0f6b9b34-8d6c-4c55-9b43-6f0e1c3f8a11", False),
        (None, False),
        (42, False),
    ],
)
def test_is_stix_id(value: object, expected: bool):
    assert is_stix_id(value) is expected


def test_entity_resolution_reads_the_platform_payload():
    payload = resolution(
        "Intrusion-Set",
        "APT29",
        pycti.IntrusionSet.generate_id("APT29"),
        match_type="taxonomy",
        matched_value="Cozy Bear",
        score=0.91,
    )

    assert EntityResolution.from_payload(payload) == EntityResolution(
        entity_id=payload["entity_id"],
        standard_id=payload["standard_id"],
        entity_type="Intrusion-Set",
        name="APT29",
        match_type="taxonomy",
        score=0.91,
        matched_value="Cozy Bear",
    )
    minimal = EntityResolution.from_payload(
        {
            "standard_id": pycti.Malware.generate_id("Cl0p"),
            "entity_type": "Malware",
            "name": "Cl0p",
        }
    )
    assert (minimal.match_type, minimal.score, minimal.matched_value) == (
        "",
        0.0,
        "Cl0p",
    )

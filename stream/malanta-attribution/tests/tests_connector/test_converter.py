import pytest
from connector.converter_to_stix import ConverterToStix

INDICATOR_ID = "indicator--0a95e840-5dab-4a71-a74f-5c5ed91a6a76"
TLP_AMBER = "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82"


@pytest.fixture
def converter():
    return ConverterToStix(author_name="Malanta.ai")


@pytest.fixture
def indicator():
    """An Indicator shaped like the live feed's payload."""
    return {
        "id": INDICATOR_ID,
        "type": "indicator",
        "confidence": 73,
        "labels": ["IOC", "apt:APT38", "domain", "source:lazarus.day"],
        "object_marking_refs": [TLP_AMBER],
    }


def test_author_is_an_organization(converter):
    assert converter.author.identity_class == "organization"
    assert converter.author.name == "Malanta.ai"


def test_intrusion_set_id_is_deterministic():
    """Same actor name must always produce the same id.

    This is what makes stream replay an upsert rather than a duplicate.
    """
    first = ConverterToStix(author_name="Malanta.ai").create_intrusion_set("APT44")
    second = ConverterToStix(author_name="Malanta.ai").create_intrusion_set("APT44")
    assert first.id == second.id


def test_different_actors_get_different_ids(converter):
    assert (
        converter.create_intrusion_set("APT44").id
        != converter.create_intrusion_set("APT28").id
    )


def test_relationship_id_is_deterministic(converter):
    intrusion_set = converter.create_intrusion_set("APT44")
    first = converter.create_indicates_relationship(INDICATOR_ID, intrusion_set.id)
    second = converter.create_indicates_relationship(INDICATOR_ID, intrusion_set.id)
    assert first.id == second.id


def test_relationship_direction_is_indicator_to_intrusion_set(converter):
    """Direction is fixed and must never be reversed."""
    intrusion_set = converter.create_intrusion_set("APT44")
    relationship = converter.create_indicates_relationship(
        INDICATOR_ID, intrusion_set.id
    )

    assert relationship.relationship_type == "indicates"
    assert relationship.source_ref == INDICATOR_ID
    assert relationship.target_ref == intrusion_set.id
    assert relationship.source_ref.startswith("indicator--")
    assert relationship.target_ref.startswith("intrusion-set--")


def test_build_attribution_objects_for_single_actor(converter, indicator):
    objects = converter.build_attribution_objects(indicator, ["APT38"])

    types = [obj.type for obj in objects]
    assert types.count("identity") == 1
    assert types.count("intrusion-set") == 1
    assert types.count("relationship") == 1


def test_build_attribution_objects_for_multiple_actors(converter, indicator):
    """Three actors yield three Intrusion Sets and three relationships."""
    objects = converter.build_attribution_objects(
        indicator, ["APT28", "APT29", "Fox Kitten"]
    )

    intrusion_sets = [o for o in objects if o.type == "intrusion-set"]
    relationships = [o for o in objects if o.type == "relationship"]

    assert len(intrusion_sets) == 3
    assert len(relationships) == 3
    assert {i.name for i in intrusion_sets} == {"APT28", "APT29", "Fox Kitten"}
    # Every relationship starts from the same Indicator.
    assert {r.source_ref for r in relationships} == {INDICATOR_ID}
    # And each points at a distinct Intrusion Set.
    assert {r.target_ref for r in relationships} == {i.id for i in intrusion_sets}


def test_derived_objects_inherit_markings_and_confidence(converter, indicator):
    """Derived objects must never be less restricted than their source."""
    objects = converter.build_attribution_objects(indicator, ["APT38"])

    for obj in objects:
        if obj.type in ("intrusion-set", "relationship"):
            assert TLP_AMBER in obj.object_marking_refs
            assert obj.confidence == 73


def test_build_attribution_objects_without_actors_returns_nothing(converter, indicator):
    assert converter.build_attribution_objects(indicator, []) == []


def test_build_attribution_objects_without_indicator_id_returns_nothing(converter):
    assert converter.build_attribution_objects({"type": "indicator"}, ["APT44"]) == []


def test_create_intrusion_sets_disabled_emits_relationships_only(converter, indicator):
    objects = converter.build_attribution_objects(
        indicator, ["APT38"], create_intrusion_sets=False
    )

    types = [obj.type for obj in objects]
    assert "intrusion-set" not in types
    assert types.count("relationship") == 1


def test_actor_names_with_spaces_are_preserved(converter):
    """`Earth Lusca` must stay one entity, not be split or mangled."""
    intrusion_set = converter.create_intrusion_set("Earth Lusca")
    assert intrusion_set.name == "Earth Lusca"


def test_indicator_without_markings_produces_unmarked_objects(converter):
    """Absent markings must not raise; they are simply omitted."""
    indicator = {"id": INDICATOR_ID, "type": "indicator", "confidence": 50}
    objects = converter.build_attribution_objects(indicator, ["APT44"])
    assert len(objects) == 3

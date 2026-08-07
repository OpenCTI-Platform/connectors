from connector.merge_split import (
    analyze_intrusion_set_merge_split,
    opencti_alias_count,
    pick_opencti_merge_survivor,
)


def test_merge_split_detects_duplicate_opencti_entities_for_single_upstream_survivor():
    api_items = [
        {
            "standard_id": "intrusion-set--aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            "name": "Flax Typhoon",
            "aliases": ["Earth Naga"],
        }
    ]
    opencti_entities = [
        {
            "standard_id": "intrusion-set--bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
            "name": "Earth Naga",
            "aliases": [],
        },
        {
            "standard_id": "intrusion-set--aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            "name": "Flax Typhoon",
            "aliases": [],
        },
    ]

    plan = analyze_intrusion_set_merge_split(api_items, opencti_entities)

    assert len(plan.merges) == 1
    assert plan.merges[0].target_api_item["standard_id"] == api_items[0]["standard_id"]
    assert len(plan.merges[0].opencti_entities_to_merge) == 1


def test_merge_split_detects_alias_conflict_for_split_candidate():
    api_items = [
        {
            "standard_id": "intrusion-set--11111111-1111-4111-8111-111111111111",
            "name": "Group A",
            "aliases": [],
        },
        {
            "standard_id": "intrusion-set--22222222-2222-4222-8222-222222222222",
            "name": "Group B",
            "aliases": ["Shared Alias"],
        },
    ]
    opencti_entities = [
        {
            "standard_id": "intrusion-set--11111111-1111-4111-8111-111111111111",
            "name": "Group A",
            "aliases": ["Shared Alias"],
        }
    ]

    plan = analyze_intrusion_set_merge_split(api_items, opencti_entities)

    assert len(plan.splits) == 1
    assert "Shared Alias" in plan.splits[0].aliases_to_remove


def test_pick_opencti_merge_survivor_prefers_more_aliases():
    """UNC3313-style internal names lose to established names with many aliases."""
    unc = {
        "standard_id": "intrusion-set--unc3313-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        "name": "UNC3313",
        "aliases": ["unc3313_group"],
    }
    muddy = {
        "standard_id": "intrusion-set--muddywa-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
        "name": "MuddyWater",
        "aliases": [
            "Muddy Water",
            "TEMP.Zagros",
            "Static Kitten",
            "Seedworm",
            "COBALT MIRAGE",
        ],
    }

    survivor = pick_opencti_merge_survivor(unc["standard_id"], [unc, muddy])

    assert survivor is not None
    assert survivor["standard_id"] == muddy["standard_id"]
    assert opencti_alias_count(muddy) > opencti_alias_count(unc)


def test_pick_opencti_merge_survivor_ties_break_to_api_standard_id():
    api_sid = "intrusion-set--aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    other_sid = "intrusion-set--bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
    api_entity = {
        "standard_id": api_sid,
        "name": "Flax Typhoon",
        "aliases": ["Earth Naga"],
    }
    other = {
        "standard_id": other_sid,
        "name": "Earth Naga",
        "aliases": ["Flax Typhoon"],
    }

    survivor = pick_opencti_merge_survivor(api_sid, [other, api_entity])

    assert survivor is not None
    assert survivor["standard_id"] == api_sid

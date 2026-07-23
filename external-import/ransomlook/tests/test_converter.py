# pylint: disable=protected-access

from datetime import datetime, timezone

import pytest
import stix2
from connector.converter import RansomLookConverter
from pycti import Infrastructure

POST = {
    "group_name": "akira",
    "post_title": "Example Corp",
    "discovered": "2026-01-02T03:04:05Z",
    "description": "Claim description",
}


def converter():
    return RansomLookConverter(
        "https://www.ransomlook.io/api", ["ransomware", "ransomlook"], "TLP:CLEAR"
    )


def test_post_graph_ids_are_deterministic():
    first = converter()
    second = converter()
    assert first.create_group("akira", {}).id == second.create_group("akira", {}).id
    assert (
        first.create_victim("Example Corp").id
        == second.create_victim("Example Corp").id
    )
    assert first.create_incident(POST).id == second.create_incident(POST).id


def test_claim_modified_times_follow_observed_claim_and_relative_source_links_resolve():
    conv = converter()
    post = {**POST, "link": "/post/sanitized-id"}
    incident = conv.create_incident(post)
    report = conv.create_report(post, [incident.id])

    observed = conv.parse_timestamp(POST["discovered"])
    assert incident.modified == observed
    assert report.modified == observed
    assert incident.created_by_ref == conv.author.id
    assert report.created_by_ref == conv.author.id
    assert conv.normalize_source_url("/post/sanitized-id") == (
        "https://www.ransomlook.io/post/sanitized-id"
    )
    assert any(
        reference.url == "https://www.ransomlook.io/post/sanitized-id"
        for reference in incident.external_references
    )


def test_claim_occurrence_identity_ignores_aliases_and_uses_persisted_corrections():
    conv = converter()
    variants = [
        dict(POST),
        {**POST, "id": "one"},
        {**POST, "post_id": "two"},
    ]

    assert len({conv.claim_identity(post) for post in variants}) == 1
    assert len({conv.create_incident(post).id for post in variants}) == 1
    reports = [
        conv.create_report(post, [conv.create_incident(post).id]) for post in variants
    ]
    assert len({item.id for item in reports}) == 1
    corrected = {
        **POST,
        "uuid": "three",
        "discovered": "2026-01-03T03:04:05Z",
        "_ransomlook_identity_discovered": POST["discovered"],
    }
    recurrence = {**corrected}
    recurrence.pop("_ransomlook_identity_discovered")
    assert conv.create_incident(corrected).id == conv.create_incident(POST).id
    assert conv.create_incident(recurrence).id != conv.create_incident(POST).id
    assert (
        conv.create_report(corrected, [conv.create_incident(corrected).id]).published
        != reports[0].published
    )
    assert not hasattr(conv.create_incident(variants[1]), "x_opencti_stix_ids")
    assert not hasattr(reports[1], "x_opencti_stix_ids")


def test_claim_route_identity_is_collision_safe():
    conv = converter()
    first = {
        "group_name": "a:b",
        "post_title": "c",
        "discovered": "2026-01-02T00:00:00Z",
    }
    second = {
        "group_name": "a",
        "post_title": "b:c",
        "discovered": "2026-01-02T00:00:00Z",
    }

    assert conv.claim_route_identity(first) != conv.claim_route_identity(second)
    assert conv.create_incident(first).id != conv.create_incident(second).id

    recurrence = {**first, "discovered": "2026-02-02T00:00:00Z"}
    assert conv.create_incident(first).id != conv.create_incident(recurrence).id


def test_named_actor_is_distinct_from_group_and_uses_only_explicit_fields():
    conv = converter()
    actor = conv.create_named_actor(
        {
            "name": "Akira",
            "aliases": [" Alias ", "alias", 42],
            "roles": ["affiliate"],
            "contacts": {"telegram": "handle", "invalid": 42},
            "has_wanted": True,
            "profile": ["javascript:bad", "https://example.test/profile"],
        }
    )
    group = conv.create_group("Akira", {})
    assert actor.type == "threat-actor"
    assert actor.id != group.id
    assert actor.resource_level == "individual"
    assert list(actor.aliases) == ["Alias"]
    assert list(actor.roles) == ["affiliate"]
    assert actor.x_ransomlook_contacts == {"telegram": "handle"}
    assert actor.x_ransomlook_wanted_sources == ["upstream-summary"]
    assert [ref.url for ref in actor.external_references] == [
        "https://www.ransomlook.io/api/actors/Akira",
        "https://example.test/profile",
    ]
    assert conv.create_named_actor({"name": " "}) is None


def test_explicit_collective_actor_and_relation_helpers():
    conv = converter()
    collective = conv.create_named_actor({"name": "Crew", "kind": "collective"})
    individual = conv.create_named_actor({"name": "Crew"})
    assert collective.id != individual.id
    assert "resource_level" not in collective
    assert conv.actor_relation_names(
        {"relations": {"groups": [" Akira ", "akira", 42]}}, "groups"
    ) == ["Akira"]
    assert conv.actor_relation_names({"relations": []}, "groups") == []
    assert conv.actor_name({"name": 42}) is None


def test_actor_forum_and_profile_relationship_are_attributed_and_stable():
    conv = converter()
    actor = conv.create_named_actor({"name": "Alice"})
    forum = conv.create_actor_forum("Example Forum")
    relation = conv.create_profile_relationship(actor.id, forum.id, "forum-or-market")
    assert forum.x_ransomlook_profile_role == "forum-or-market"
    assert relation.relationship_type == "related-to"
    assert relation.x_ransomlook_relation == "forum-or-market"
    assert relation.x_ransomlook_source == "RansomLook actor profile"
    assert conv.create_actor_forum(" ") is None


def test_sdo_and_relationship_serialization_is_fully_stable():
    first = converter()
    second = converter()
    first_group = first.create_group("akira", {})
    second_group = second.create_group("akira", {})
    first_objects = [
        first.author,
        first.marking,
        first_group,
        first.create_victim("Example Corp"),
        first.create_incident(POST),
        first.create_report(POST, [first_group.id]),
        first.create_relationship(first_group.id, "targets", first_group.id),
        first.create_note({"id": "one", "content": "Pay"}, first_group.id),
    ]
    second_objects = [
        second.author,
        second.marking,
        second_group,
        second.create_victim("Example Corp"),
        second.create_incident(POST),
        second.create_report(POST, [second_group.id]),
        second.create_relationship(second_group.id, "targets", second_group.id),
        second.create_note({"id": "one", "content": "Pay"}, second_group.id),
    ]
    assert [obj.serialize(sort_keys=True) for obj in first_objects] == [
        obj.serialize(sort_keys=True) for obj in second_objects
    ]


def test_website_creates_domain_and_url_observables():
    objects = converter().create_website_observables("https://example.com/path")
    assert [obj.type for obj in objects] == ["domain-name", "url"]
    assert objects[0].value == "example.com"


def test_note_id_is_stable_when_content_changes():
    conv = converter()
    first = conv.create_note(
        {"id": "note-1", "content": "old"}, conv.create_group("x", {}).id
    )
    second = conv.create_note(
        {"id": "note-1", "content": "new"}, conv.create_group("x", {}).id
    )
    assert first.id == second.id
    other_group = conv.create_group("y", {}).id
    assert (
        first.id != conv.create_note({"id": "note-1", "content": "old"}, other_group).id
    )


def test_magnet_identity_and_content_are_immutable_for_one_infohash():
    conv = converter()
    first = conv.create_magnet_observable(
        {
            "infohash": "A" * 40,
            "name": "first name",
            "seeders": 4,
            "leechers": 2,
            "updated": "2026-01-01T00:00:00Z",
        }
    )
    changed = conv.create_magnet_observable(
        {"infohash": "a" * 40, "name": "renamed", "seeders": 9}
    )
    assert first.id == changed.id
    assert first.value == "magnet:?xt=urn:btih:" + "a" * 40
    assert "&dn=" not in first.value
    assert first.serialize() == changed.serialize()
    assert conv.create_magnet_observable({"infohash": "not-a-hash"}) is None
    assert conv.normalize_infohash("a2345672a2345672a2345672a2345672") == (
        "A2345672A2345672A2345672A2345672"
    )
    assert conv.normalize_infohash(None) is None
    assert conv.create_magnet_observable({"info_hash": "c" * 40}).id


def test_leak_and_peer_context_never_create_indicators():
    conv = converter()
    incident = conv.create_incident(POST)
    leak = conv.create_leak_note(
        {"id": 7, "name": "Exact record", "domain": "victim.example"},
        incident.id,
    )
    relation = conv.create_direct_leak_relationship(leak.id, incident.id, "leak")
    peer = conv.create_torrent_peer("192.0.2.4")
    assert leak.object_refs == [incident.id]
    assert leak.x_ransomlook_relation_basis == "explicit-upstream-identifier"
    assert relation.x_ransomlook_relation == "direct-leak"
    assert peer.type == "ipv4-addr"
    assert peer.x_ransomlook_peer_telemetry is True
    assert conv.create_torrent_peer("not-an-ip") is None
    assert conv.create_torrent_peer("2001:db8::1").type == "ipv6-addr"
    assert conv.create_torrent_peer(None) is None
    assert not any(obj.type == "indicator" for obj in (leak, relation, peer))
    assert conv.create_leak_note({"name": "missing id"}, incident.id) is None
    anonymous = conv.create_leak_note({"uuid": "u-1", "title": 42}, incident.id)
    assert anonymous.abstract == "Data leak record"


def test_marking_timestamp_and_description_variants():
    conv = converter()
    assert conv._marking("TLP:GREEN").id == stix2.TLP_GREEN.id
    assert (
        conv._marking("TLP:AMBER+STRICT")["x_opencti_definition"] == "TLP:AMBER+STRICT"
    )
    assert conv.parse_timestamp("2026-01-01 12:00:00").tzinfo is not None
    with pytest.raises(ValueError, match="no discovery timestamp"):
        conv.parse_timestamp(None)
    with pytest.raises(ValueError, match="no discovery timestamp"):
        conv.parse_timestamp(123)
    assert conv.clean_description(None) is None
    assert conv.clean_description(123) is None
    assert conv.clean_description("<b>Hello</b><br>&amp; world") == "Hello\n& world"
    assert conv.clean_description("<br>") is None


def test_incident_includes_optional_source_link():
    incident = converter().create_incident(
        {**POST, "link": "http://example.onion/victim"}
    )
    assert len(incident.external_references) == 2

    invalid = converter().create_incident({**POST, "link": "javascript:alert(1)"})
    assert len(invalid.external_references) == 1


def test_claim_descriptions_preserve_observed_unverified_semantics():
    conv = converter()
    incident = conv.create_incident(
        {**POST, "description": "We encrypted and published the victim data"}
    )
    report = conv.create_report(POST, [incident.id])
    for obj in (incident, report):
        assert (
            "RansomLook observed akira publishing a ransomware claim" in obj.description
        )
        assert "does not independently confirm intrusion" in obj.description
        assert "Upstream claim text:" in obj.description


@pytest.mark.parametrize("value", [None, "", "   "])
def test_empty_websites_are_ignored(value):
    assert not converter().create_website_observables(value)


def test_url_without_hostname_only_creates_url():
    objects = converter().create_website_observables("http:///victim")
    assert not objects


def test_empty_note_is_ignored_and_fallback_fields_are_used():
    conv = converter()
    group_id = conv.create_group("x", {}).id
    assert conv.create_note({"content": " "}, group_id) is None
    assert conv.create_note({"content": 123}, group_id) is None
    note = conv.create_note({"content": "Pay us"}, group_id)
    assert note.abstract == "Ransom note"


def test_wallet_uses_pinned_chain_aware_contract_and_stable_identity():
    conv = converter()
    ethereum = conv.create_wallet(
        {"blockchain": "ETH", "address": " 0xAbC ", "tx_count": 3}, "ignored"
    )
    replay = conv.create_wallet({"address": "0xabc"}, "ethereum")
    bitcoin = conv.create_wallet({"address": "0xabc"}, "bitcoin")
    assert ethereum.type == "cryptocurrency-wallet"
    assert ethereum.value == "0xabc"
    assert ethereum.x_ransomlook_chain == "ethereum"
    assert "x_ransomlook_transaction_count" not in ethereum
    assert ethereum.serialize() == replay.serialize()
    assert ethereum.id == replay.id
    assert ethereum.id != bitcoin.id
    assert conv.create_wallet({"address": "bad address"}, "bitcoin") is None
    assert conv.create_wallet({"address": "x"}, "unknown chain!") is None


@pytest.mark.parametrize(
    ("chain", "address", "expected"),
    [
        (None, "x", None),
        ("bitcoin", None, None),
        ("", "x", None),
        ("x" * 65, "x", None),
        ("bitcoin", "", None),
        ("bitcoin", "x" * 513, None),
        ("bitcoin", "bad\taddress", None),
        ("XMR", "CaseSensitive", ("monero", "CaseSensitive")),
        ("XBT", "tb1UPPER", ("bitcoin", "tb1upper")),
    ],
)
def test_wallet_normalization_rejects_ambiguous_values(chain, address, expected):
    assert converter().normalize_wallet(chain, address) == expected


def test_group_profiles_are_normalized_deduplicated_and_bounded():
    profiles = ["javascript:bad", "HTTPS://EXAMPLE.COM:443"]
    profiles.extend(f"https://profile-{index}.example" for index in range(30))
    profiles.append("https://example.com/")
    group = converter().create_group("akira", {"profile": profiles})
    profile_refs = [
        reference
        for reference in group.external_references
        if reference.source_name == "RansomLook group profile"
    ]
    assert len(profile_refs) == converter().MAX_PROFILE_REFERENCES
    assert profile_refs[0].url == "https://example.com/"


def test_timestamps_reference_deduplication_and_limits():
    conv = RansomLookConverter("https://www.ransomlook.io/api", ["test"], "TLP:CLEAR")
    group = conv.create_group("akira", {"meta": "x" * 100_001})
    victim = conv.create_victim("Example Corp")
    timestamp = datetime(2026, 1, 2, tzinfo=timezone.utc)
    relationship = conv.create_relationship(group.id, "targets", victim.id, timestamp)
    report = conv.create_report(POST, [group.id, group.id, victim.id])
    note = conv.create_note(
        {"id": "large", "name": "n" * 300, "content": "x" * 1_000_001},
        group.id,
    )
    assert relationship.created == timestamp
    assert len(group.description) == conv.MAX_DESCRIPTION_LENGTH
    assert list(report.object_refs) == [group.id, victim.id]
    assert len(note.abstract) == 256
    assert len(note.content) == conv.MAX_NOTE_CONTENT_LENGTH


@pytest.mark.parametrize(
    "value",
    [
        "ftp://example.com",
        "https://user:pass@example.com",
        "https://example.com/a b",
        "https://example.com:invalid",
        "https://" + "a" * 254,
        "https://_bad.example",
        "https://-bad.example",
        "https://bad-.example",
        "https://localhost",
        "https://ftp",
        123,
    ],
)
def test_invalid_or_unsafe_urls_are_rejected(value):
    assert not converter().create_website_observables(value)


def test_url_normalization_handles_idna_ip_and_default_ports():
    conv = converter()
    unicode_objects = conv.create_website_observables("HTTPS://BÜCHER.example:443")
    assert unicode_objects[0].value == "xn--bcher-kva.example"
    assert unicode_objects[1].value == "https://xn--bcher-kva.example/"
    ip_objects = conv.create_website_observables("http://192.0.2.1:80")
    assert [obj.type for obj in ip_objects] == ["url"]
    assert ip_objects[0].value == "http://192.0.2.1/"


def test_location_infrastructure_preserves_roles_lifecycle_and_stable_identity():
    conv = converter()
    location = {
        "slug": "HTTP://PROFILE.EXAMPLE:80/path",
        "private": True,
        "fs": True,
        "chat": "true",
        "admin": True,
        "relay": True,
        "available": True,
        "firstseen": "2025-01-01T00:00:00Z",
        "lastscrape": "2026-01-01T00:00:00Z",
        "updated": "2026-01-02T00:00:00Z",
    }
    objects = conv.create_location_infrastructure("Akira", location)
    infrastructure = objects[0]
    assert infrastructure.type == "infrastructure"
    assert list(infrastructure["x_ransomlook_roles"]) == [
        "private",
        "file-server",
        "chat",
        "admin",
        "relay",
    ]
    assert infrastructure["x_ransomlook_access"] == "private"
    assert infrastructure["x_ransomlook_available"] is True
    assert infrastructure.first_seen == datetime(2025, 1, 1, tzinfo=timezone.utc)
    assert infrastructure.last_seen == datetime(2026, 1, 1, tzinfo=timezone.utc)
    assert infrastructure.modified == datetime(2026, 1, 2, tzinfo=timezone.utc)
    assert (
        infrastructure["x_ransomlook_last_scrape"]
        != infrastructure["x_ransomlook_upstream_updated"]
    )
    assert [obj.type for obj in objects] == [
        "infrastructure",
        "domain-name",
        "relationship",
        "url",
        "relationship",
    ]
    assert all(
        relationship.relationship_type == "consists-of"
        and relationship.source_ref == infrastructure.id
        for relationship in objects
        if relationship.type == "relationship"
    )

    down = conv.create_location_infrastructure(
        " akira ", {**location, "available": False, "updated": "2026-02-01T00:00:00Z"}
    )[0]
    assert down.id == infrastructure.id
    assert down["x_ransomlook_available"] is False
    assert not down.get("revoked", False)


def test_same_role_locations_have_collision_free_non_sensitive_names():
    conv = converter()
    first = conv.create_location_infrastructure(
        "Example Group", {"slug": "https://one.example/path", "dls": True}
    )[0]
    second = conv.create_location_infrastructure(
        "Example Group", {"slug": "https://two.example/path", "dls": True}
    )[0]
    replay = conv.create_location_infrastructure(
        " example group ",
        {
            "slug": "HTTPS://ONE.EXAMPLE:443/path",
            "dls": False,
            "relay": True,
            "available": False,
        },
    )[0]

    assert first.id != second.id
    assert first.name != second.name
    assert first.id == replay.id
    assert first.name == replay.name
    assert "one.example" not in first.name
    assert first.id == Infrastructure.generate_id(first.name)


def test_non_http_location_remains_infrastructure_context_without_url():
    objects = converter().create_location_infrastructure(
        "akira", {"slug": "xmpp:operator@example.com", "chat": True}
    )
    assert [obj.type for obj in objects] == ["infrastructure"]
    assert objects[0]["x_ransomlook_location"] == "xmpp:operator@example.com"
    assert list(objects[0]["x_ransomlook_roles"]) == ["public", "chat"]


def test_inconsistent_source_lifecycle_is_preserved_without_invalid_stix_interval():
    infrastructure = converter().create_location_infrastructure(
        "akira",
        {
            "slug": "historic.example",
            "firstseen": "2026-02-01T00:00:00Z",
            "lastscrape": "2026-01-01T00:00:00Z",
            "updated": "2020-01-01T00:00:00Z",
        },
    )[0]
    assert infrastructure.first_seen == datetime(2026, 2, 1, tzinfo=timezone.utc)
    assert "last_seen" not in infrastructure
    assert infrastructure["x_ransomlook_last_scrape"].startswith("2026-01-01")
    assert infrastructure.modified == converter().SOURCE_EPOCH


@pytest.mark.parametrize("value", [None, "", "   ", "bad\x00value", "x" * 4097])
def test_invalid_location_identity_is_rejected(value):
    assert not converter().create_location_infrastructure("akira", {"slug": value})

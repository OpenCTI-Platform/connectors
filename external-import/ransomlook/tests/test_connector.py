# pylint: disable=duplicate-code,no-member,protected-access,too-few-public-methods,wrong-import-order

import base64
import json
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from typing import cast
from unittest.mock import MagicMock

import pytest
import stix2
from connector.api_client import (
    DeferredPostWindow,
    PostBatch,
    RansomLookAPIClient,
    RansomLookAPIError,
    RansomLookCapabilityUnavailable,
    RansomLookCycleBudgetExhausted,
)
from connector.connector import CollectionCycle, GroupEnrichment, RansomLookConnector
from connector.settings import ConnectorSettings, RansomLookConfig
from connectors_sdk.settings.exceptions import ConfigValidationError
from pycti import OpenCTIConnectorHelper, OpenCTIStix2Splitter
from pydantic import ValidationError


class StubSettings(ConnectorSettings):
    @classmethod
    def _load_config_dict(cls, _, handler):
        return handler(
            {
                "opencti": {"url": "http://localhost:8080", "token": "token"},
                "connector": {
                    "id": "connector-id",
                    "name": "RansomLook test",
                    "scope": "identity,intrusion-set,incident,report,note,domain-name,url,relationship",
                    "duration_period": "PT1H",
                },
                "ransomlook": {
                    "api_base_url": "https://www.ransomlook.io/api",
                    "labels": "ransomware,test",
                    "marking_definition": "TLP:CLEAR",
                    "initial_history_days": 7,
                    "import_notes": True,
                    "import_infrastructure": True,
                    "import_victim_websites": True,
                },
            }
        )


class MissingRequiredSettings(ConnectorSettings):
    @classmethod
    def _load_config_dict(cls, _, handler):
        return handler({})


@pytest.fixture(autouse=True)
def isolate_optional_actor_enumeration(monkeypatch):
    """Keep existing connector unit tests isolated from the live optional API."""
    monkeypatch.setattr(RansomLookAPIClient, "get_actors", lambda _self: [])
    monkeypatch.setattr(
        RansomLookAPIClient, "get_group_crypto", lambda _self, _name: {"by_chain": {}}
    )
    monkeypatch.setattr(RansomLookAPIClient, "get_note", lambda _self, _note_id: {})
    monkeypatch.setattr(
        RansomLookAPIClient, "get_torrents", lambda _self, _group=None: []
    )
    monkeypatch.setattr(RansomLookAPIClient, "get_leaks", lambda _self: [])


def test_settings_reject_missing_opencti_credentials():
    with pytest.raises(ConfigValidationError):
        MissingRequiredSettings()


def test_source_settings_defaults():
    settings = RansomLookConfig()
    assert str(settings.api_base_url) == "https://www.ransomlook.io/api"
    assert settings.api_key is None
    assert settings.initial_history_days == 7
    assert settings.max_response_size_mb == 32
    assert settings.max_records_per_endpoint == 1000
    assert settings.max_pages_per_endpoint == 10
    assert settings.max_requests_per_run == 2000
    assert settings.max_run_duration_seconds == 2700
    assert settings.work_reconciliation_timeout_seconds == 900
    assert settings.max_objects_per_bundle == 500
    assert settings.max_objects_per_run == 20000
    assert settings.max_bundle_size_mb == 64
    assert settings.replay_window_days == 1
    assert settings.max_artifact_size_mb == 5
    assert settings.max_artifacts_per_claim == 2
    assert settings.max_artifacts_per_location == 2
    assert settings.max_artifacts_per_run == 300
    assert settings.max_artifact_bytes_per_run_mb == 200
    assert settings.max_evidence_serialized_bytes_per_run_mb == 800
    assert settings.max_pending_claims == 5000
    assert settings.max_claim_retries == 5
    assert settings.max_pending_groups == 1000
    assert settings.max_enrichment_retries == 5
    assert settings.retry_max_age_days == 30
    assert settings.enrich_actor_profiles is True
    assert settings.import_infrastructure is True
    assert settings.import_sensitive_infrastructure is False
    assert settings.import_post_evidence is True
    assert settings.import_location_evidence is False
    assert settings.import_notes is True
    assert settings.import_wallets is True
    assert settings.import_torrents is True
    assert settings.import_torrent_peers is False
    assert settings.import_leaks is True
    assert settings.import_analyses is True
    assert settings.import_victim_websites is True
    assert settings.create_indicators is False


def test_named_actors_are_bounded_deduplicated_and_profile_scoped():
    helper = MagicMock()
    connector = RansomLookConnector(StubSettings(), helper)
    connector.client.get_actors = MagicMock(
        return_value=[
            {"name": "Alice", "relations": {"groups": ["Akira"]}},
            {"name": " alice ", "relations": {"groups": ["Akira"]}},
            {"name": "Unrelated", "relations": {"groups": ["Other"]}},
        ]
    )
    connector.client.get_actor = MagicMock(
        side_effect=lambda name: {
            "name": name,
            "aliases": ["A", "A"],
            "roles": ["affiliate"],
            "contacts": {"telegram": "alice-contact"},
            "wanted": {"authority": {"url": "https://example.test/wanted"}},
            "profile": ["https://example.test/profile"],
            "relations": {
                "groups": ["Akira"] if name == "Alice" else ["Other"],
                "peers": ["Bob"],
                "forums": ["Example Forum"],
            },
        }
    )

    objects, complete = connector._try_create_named_actor_profiles({"akira"})

    assert complete is True
    assert connector.client.get_actor.call_count == 2
    profile = objects["akira"]
    actor = next(
        obj for obj in profile if obj.type == "threat-actor" and obj.name == "Alice"
    )
    assert actor.resource_level == "individual"
    assert list(actor.aliases) == ["A"]
    assert list(actor.roles) == ["affiliate"]
    assert actor.x_ransomlook_contacts == {"telegram": "alice-contact"}
    assert actor.x_ransomlook_wanted is True
    assert any(obj.type == "threat-actor" and obj.name == "Bob" for obj in profile)
    assert any(
        obj.type == "infrastructure" and obj.name == "Example Forum" for obj in profile
    )
    relations = [obj for obj in profile if obj.type == "relationship"]
    assert {obj.x_ransomlook_relation for obj in relations} == {
        "group",
        "peer",
        "forum-or-market",
    }
    assert all(
        obj.x_ransomlook_source == "RansomLook actor profile" for obj in relations
    )
    assert connector.converter.create_group("Akira", {}).id != actor.id


def test_unavailable_named_actor_capability_isolated_from_claims():
    helper = MagicMock()
    connector = RansomLookConnector(StubSettings(), helper)
    connector.client.get_actors = MagicMock(
        side_effect=RansomLookCapabilityUnavailable("actors", 401)
    )

    objects, complete = connector._try_create_named_actor_profiles({"akira"})

    assert objects == {"akira": []}
    assert complete is True
    helper.connector_logger.info.assert_called_once()


def test_named_actor_enumeration_failure_is_retryable_optional_incomplete():
    connector = make_connector()
    connector.client.get_actors = MagicMock(side_effect=RansomLookAPIError("down"))

    objects, complete = connector._try_create_named_actor_profiles({"akira"})

    assert objects == {"akira": []}
    assert complete is False


def test_optional_capabilities_return_incomplete_on_request_budget_exhaustion():
    connector = make_connector()
    connector.client.get_actors = MagicMock(
        side_effect=RansomLookCycleBudgetExhausted("budget")
    )
    connector.client.get_group_notes = MagicMock(
        side_effect=RansomLookCycleBudgetExhausted("budget")
    )
    connector.client.get_group_crypto = MagicMock(
        side_effect=RansomLookCycleBudgetExhausted("budget")
    )
    connector.client.get_torrents = MagicMock(
        side_effect=RansomLookCycleBudgetExhausted("budget")
    )
    connector.client.get_leaks = MagicMock(
        side_effect=RansomLookCycleBudgetExhausted("budget")
    )
    connector.client.get_group_analyses = MagicMock(
        side_effect=RansomLookCycleBudgetExhausted("budget")
    )
    group = connector.converter.create_group("Akira", {})
    posts = [
        {
            "id": "p-1",
            "group_name": "Akira",
            "post_title": "Victim",
            "discovered": "2026-01-02T00:00:00Z",
        }
    ]

    assert connector._try_create_named_actor_profiles({"akira"}) == (
        {"akira": []},
        False,
    )
    assert connector._try_create_group_notes("Akira", group.id) == ([], False)
    assert connector._try_create_group_wallets("Akira", group.id) == ([], False)
    assert connector._try_create_group_leak_intelligence("Akira", group.id, posts) == (
        [],
        {connector.converter.claim_identity(posts[0]): []},
        False,
    )
    assert connector._try_create_group_analysis_intelligence(
        "Akira", group.id, posts
    ) == ([], {connector.converter.claim_identity(posts[0]): []}, False)


def test_optional_detail_budget_exhaustion_returns_incomplete_without_abort():
    connector = make_connector()
    group = connector.converter.create_group("Akira", {})
    connector.client.get_actors = MagicMock(
        return_value=[{"name": "Alice", "relations": {"groups": ["Akira"]}}]
    )
    connector.client.get_actor = MagicMock(
        side_effect=RansomLookCycleBudgetExhausted("budget")
    )
    connector.client.get_group_notes = MagicMock(
        return_value=[{"id": "note-1", "content": "summary"}]
    )
    connector.client.get_note = MagicMock(
        side_effect=RansomLookCycleBudgetExhausted("budget")
    )
    connector.client.get_leaks = MagicMock(return_value=[{"id": "leak-1"}])
    connector.client.get_leak = MagicMock(
        side_effect=RansomLookCycleBudgetExhausted("budget")
    )

    assert connector._try_create_named_actor_profiles({"akira"}) == (
        {"akira": []},
        False,
    )
    assert connector._try_create_group_notes("Akira", group.id) == ([], False)
    assert connector._try_get_leak_details() == ([], False)


def test_disabled_actor_profiles_do_not_enumerate_named_actors():
    helper = MagicMock()
    settings = StubSettings()
    object.__setattr__(
        settings,
        "ransomlook",
        settings.ransomlook.model_copy(update={"enrich_actor_profiles": False}),
    )
    connector = RansomLookConnector(settings, helper)
    connector.client.get_posts = MagicMock(return_value=[])
    connector.client.get_actors = MagicMock(side_effect=AssertionError("not called"))

    cycle = connector._collect_cycle(
        datetime(2026, 1, 1, tzinfo=timezone.utc),
        datetime(2026, 1, 2, tzinfo=timezone.utc),
        {},
    )

    assert cycle.enrichments == []
    connector.client.get_actors.assert_not_called()


def test_torrents_and_leaks_use_only_explicit_claim_or_group_relations():
    helper = MagicMock()
    connector = RansomLookConnector(StubSettings(), helper)
    posts = [
        {
            "id": "p-1",
            "group_name": "akira",
            "post_title": "Victim One",
            "discovered": "2026-01-02T03:04:05Z",
        },
        {
            "id": "p-2",
            "group_name": "akira",
            "post_title": "Victim Two",
            "discovered": "2026-01-02T03:04:05Z",
        },
    ]
    connector.client.get_torrents = MagicMock(
        return_value=[
            {
                "infohash": "1" * 40,
                "post_id": "p-1",
                "groups": ["akira"],
                "webseeds": ["https://seed.example/file"],
                "peers": ["192.0.2.9"],
                "torrent": "ZDM6Zm9vZQ==",  # b"d3:fooe"
            },
            {"infohash": "2" * 40, "groups": ["Akira"]},
            {"infohash": "3" * 40, "name": "Victim One"},
        ]
    )
    connector.client.get_leaks = MagicMock(
        return_value=[
            {"id": 10, "name": "Victim One"},
            {"id": 11, "name": "Victim Two", "domain": "victim.example"},
        ]
    )
    connector.client.get_leak = MagicMock(
        side_effect=lambda leak_id: (
            {"id": 10, "post_id": "p-1", "description": "Explicit relation"}
            if leak_id == 10
            else {"id": 11, "domain": "victim.example"}
        )
    )
    group = connector.converter.create_group("akira", {})

    profile, claims, complete = connector._try_create_group_leak_intelligence(
        "akira", group.id, posts
    )

    assert complete is True
    profile_magnets = [
        obj for obj in profile if obj.type == "url" and obj.value.startswith("magnet:")
    ]
    assert [obj.x_ransomlook_infohash for obj in profile_magnets] == ["2" * 40]
    first = claims[connector.converter.claim_identity(posts[0])]
    second = claims[connector.converter.claim_identity(posts[1])]
    assert any(obj.type == "url" and obj.value.startswith("magnet:") for obj in first)
    assert any(
        obj.type == "artifact" and obj.mime_type == "application/x-bittorrent"
        for obj in first
    )
    assert any(
        obj.type == "url" and obj.value == "https://seed.example/file" for obj in first
    )
    assert any(obj.type == "note" and obj.x_ransomlook_leak_id == "10" for obj in first)
    assert not any(obj.type in {"ipv4-addr", "ipv6-addr"} for obj in first)
    assert second == []  # name/domain-only corpus similarity is not a direct relation
    assert not any(
        obj.type == "url" and getattr(obj, "x_ransomlook_infohash", None) == "3" * 40
        for obj in [*profile, *first, *second]
    )
    assert not any(obj.type == "indicator" for obj in [*profile, *first, *second])


def test_torrent_peer_telemetry_is_opt_in_and_never_an_indicator():
    helper = MagicMock()
    settings = StubSettings()
    object.__setattr__(
        settings,
        "ransomlook",
        settings.ransomlook.model_copy(update={"import_torrent_peers": True}),
    )
    connector = RansomLookConnector(settings, helper)
    connector.client.get_torrents = MagicMock(
        return_value=[
            {"infohash": "a" * 40, "groups": ["akira"], "peers": ["192.0.2.8"]}
        ]
    )
    connector.client.get_leaks = MagicMock(return_value=[])
    group = connector.converter.create_group("akira", {})
    profile, _, _ = connector._try_create_group_leak_intelligence("akira", group.id, [])
    assert any(obj.type == "ipv4-addr" for obj in profile)
    assert not any(obj.type == "indicator" for obj in profile)


def test_nested_torrent_context_has_one_bounded_group_budget():
    helper = MagicMock()
    settings = StubSettings()
    object.__setattr__(
        settings,
        "ransomlook",
        settings.ransomlook.model_copy(
            update={"max_records_per_endpoint": 2, "import_torrent_peers": True}
        ),
    )
    connector = RansomLookConnector(settings, helper)
    connector.client.get_torrents = MagicMock(
        return_value=[
            {
                "infohash": "a" * 40,
                "groups": ["akira"],
                "webseeds": [
                    "https://seed.example/1",
                    "https://seed.example/2",
                    "https://seed.example/3",
                ],
                "peers": ["192.0.2.1", "192.0.2.2"],
            },
            {
                "infohash": "b" * 40,
                "groups": ["akira"],
                "webseeds": ["https://seed.example/4"],
            },
        ]
    )
    connector.client.get_leaks = MagicMock(return_value=[])
    group = connector.converter.create_group("akira", {})

    profile, _, complete = connector._try_create_group_leak_intelligence(
        "akira", group.id, []
    )

    assert complete is True
    assert len([obj for obj in profile if obj.type == "ipv4-addr"]) == 0
    assert {
        obj.value
        for obj in profile
        if obj.type == "url" and obj.value.startswith("https://")
    } == {"https://seed.example/1", "https://seed.example/2"}
    helper.connector_logger.warning.assert_called_once_with(
        "Skipping excess nested RansomLook torrent context",
        {"group_sha256": "8d8f469ed2ef36f5", "limit": 2, "skipped": 4},
    )


def test_disabled_torrent_and_leak_features_make_no_api_calls():
    helper = MagicMock()
    settings = StubSettings()
    object.__setattr__(
        settings,
        "ransomlook",
        settings.ransomlook.model_copy(
            update={"import_torrents": False, "import_leaks": False}
        ),
    )
    connector = RansomLookConnector(settings, helper)
    connector.client.get_torrents = MagicMock(side_effect=AssertionError("not called"))
    connector.client.get_leaks = MagicMock(side_effect=AssertionError("not called"))
    group = connector.converter.create_group("akira", {})
    assert connector._try_create_group_leak_intelligence("akira", group.id, []) == (
        [],
        {},
        True,
    )
    connector.client.get_torrents.assert_not_called()
    connector.client.get_leaks.assert_not_called()


def test_explicit_relation_shape_helpers_ignore_names_and_malformed_values():
    record = {
        "posts": [
            {"id": "one", "name": "not-an-identifier"},
            {"uuid": 2},
            {"post_id": "three"},
            {"claim_id": "four"},
            {"id": " "},
            {"id": None},
            42,
            None,
        ]
    }
    assert RansomLookConnector._explicit_post_ids(record) == {
        "one",
        "2",
        "three",
        "four",
        "42",
    }
    assert RansomLookConnector._post_ids({"id": "one", "post_id": 2, "uuid": None}) == {
        "one",
        "2",
    }


@pytest.mark.parametrize(
    ("method", "error", "logged_method"),
    [
        (
            "get_torrents",
            RansomLookCapabilityUnavailable("torrents", 401),
            "info",
        ),
        ("get_torrents", RansomLookAPIError("torrent failed"), "warning"),
        ("get_leaks", RansomLookCapabilityUnavailable("leaks", 403), "info"),
        ("get_leaks", RansomLookAPIError("leak failed"), "warning"),
    ],
)
def test_optional_torrent_and_leak_failures_are_isolated(method, error, logged_method):
    helper = MagicMock()
    connector = RansomLookConnector(StubSettings(), helper)
    connector.client.get_torrents = MagicMock(return_value=[])
    connector.client.get_leaks = MagicMock(return_value=[])
    setattr(connector.client, method, MagicMock(side_effect=error))
    group = connector.converter.create_group("akira", {})
    profile, claims, complete = connector._try_create_group_leak_intelligence(
        "akira", group.id, []
    )
    assert profile == []
    assert claims == {}
    assert complete is isinstance(error, RansomLookCapabilityUnavailable)
    assert getattr(helper.connector_logger, logged_method).called


def test_leak_details_are_cached_and_individual_failure_isolated():
    helper = MagicMock()
    connector = RansomLookConnector(StubSettings(), helper)
    connector.client.get_leaks = MagicMock(
        return_value=[{"id": 1}, {"uuid": "two"}, {"name": "no-id"}]
    )
    connector.client.get_leak = MagicMock(
        side_effect=[{"id": 1, "groups": ["akira"]}, RansomLookAPIError("detail")]
    )
    first, complete = connector._try_get_leak_details()
    second, cached_complete = connector._try_get_leak_details()
    assert first == second
    assert complete is cached_complete is False
    assert first[-1] == {"name": "no-id"}
    connector.client.get_leaks.assert_called_once()
    assert connector.client.get_leak.call_count == 2


def test_named_actor_detail_failure_does_not_erase_other_profiles():
    helper = MagicMock()
    connector = RansomLookConnector(StubSettings(), helper)
    connector.client.get_actors = MagicMock(
        return_value=[
            {"name": "Broken", "relations": {"groups": ["Akira"]}},
            {"name": "Alice", "relations": {"groups": ["Akira"]}},
        ]
    )
    connector.client.get_actor = MagicMock(
        side_effect=[
            RansomLookAPIError("bad detail"),
            {"name": "Alice", "relations": {"groups": ["Akira"]}},
        ]
    )

    objects, complete = connector._try_create_named_actor_profiles({"akira"})

    assert complete is False
    assert any(obj.type == "threat-actor" for obj in objects["akira"])
    helper.connector_logger.warning.assert_called_once()


def test_named_actor_malformed_and_unavailable_records_are_terminal_skips():
    connector = make_connector()
    connector.client.get_actors = MagicMock(
        return_value=[{}, {"name": "Unavailable"}, {"name": "Malformed"}]
    )
    connector.client.get_actor = MagicMock(
        side_effect=[
            RansomLookCapabilityUnavailable("actors", 404),
            {"name": "Malformed", "relations": {"groups": ["Akira"]}},
        ]
    )
    connector._create_named_actor_graph = MagicMock(
        side_effect=ValueError("bad actor shape")
    )

    objects, complete = connector._try_create_named_actor_profiles({"akira"})

    assert objects == {"akira": []}
    assert complete is True
    assert connector.metrics.optional_skips == 2


@pytest.mark.parametrize(
    "values",
    [
        {"api_base_url": "not-a-url"},
        {"marking_definition": "TLP:INVALID"},
        {"initial_history_days": 0},
        {"initial_history_days": 3651},
        {"max_response_size_mb": 0},
        {"max_records_per_endpoint": 0},
        {"max_pages_per_endpoint": 0},
        {"max_requests_per_run": 9},
        {"max_run_duration_seconds": 59},
        {"work_reconciliation_timeout_seconds": 9},
        {"max_objects_per_bundle": 31},
        {"max_objects_per_bundle": 5001},
        {"max_bundle_size_mb": 0},
        {"max_bundle_size_mb": 257},
        {"replay_window_days": -1},
        {"replay_window_days": 7},
        {"max_artifact_size_mb": 0},
        {"max_artifact_size_mb": 33},
        {"max_artifacts_per_claim": 0},
        {"max_artifacts_per_location": 0},
        {"max_artifacts_per_run": 0},
        {"max_artifact_bytes_per_run_mb": 0},
        {"max_evidence_serialized_bytes_per_run_mb": 0},
        {"max_pending_claims": 0},
        {"max_claim_retries": 0},
        {"max_pending_groups": 0},
        {"max_enrichment_retries": 0},
        {"retry_max_age_days": 0},
        {"labels": " , "},
        {"api_base_url": "https://user:pass@example.test/api"},
        {"api_base_url": "https://example.test/api?token=secret"},
        {"api_base_url": "http://example.test/api", "api_key": "secret"},
    ],
)
def test_source_settings_reject_invalid_values(values):
    with pytest.raises(ValidationError):
        RansomLookConfig(**values)


def test_source_settings_reject_incompatible_evidence_and_bundle_limits():
    with pytest.raises(ValidationError, match="too small.*post-evidence size"):
        RansomLookConfig(max_artifact_size_mb=10, max_bundle_size_mb=64)


@pytest.mark.parametrize(
    "producer",
    [
        "import_post_evidence",
        "import_location_evidence",
        "import_notes",
        "import_torrents",
        "import_analyses",
    ],
)
def test_every_artifact_producer_requires_a_deliverable_bundle(producer):
    values = {
        "import_post_evidence": False,
        "import_location_evidence": False,
        "import_notes": False,
        "import_torrents": False,
        "import_analyses": False,
        "max_artifact_size_mb": 32,
        "max_bundle_size_mb": 10,
        producer: True,
    }
    with pytest.raises(ValidationError, match="configured Artifact size"):
        RansomLookConfig(**values)


def test_unknown_source_settings_are_ignored_but_env_typos_are_rejected_without_values(
    monkeypatch,
):
    settings = RansomLookConfig(max_artificat_size_mb=7)
    assert settings.max_artifact_size_mb == 5
    assert not hasattr(settings, "max_artificat_size_mb")

    monkeypatch.setenv("RANSOMLOOK_MAX_ARTIFACT_SZE_MB", "TOPSECRET")
    with pytest.raises(ValueError) as error:
        StubSettings()
    assert "RANSOMLOOK_MAX_ARTIFACT_SZE_MB" in str(error.value)
    assert "TOPSECRET" not in str(error.value)


def test_source_settings_normalize_labels_and_protect_secret():
    settings = RansomLookConfig(
        labels=" ransomware, ransomware, test ", api_key="secret"
    )
    assert settings.labels == ["ransomware", "test"]
    assert settings.api_key.get_secret_value() == "secret"
    assert "secret" not in repr(settings)

    with pytest.raises(ValidationError) as error:
        RansomLookConfig(api_base_url="http://example.test/api", api_key="SUPERSECRET")
    assert "SUPERSECRET" not in str(error.value)


def test_collect_builds_expected_graph():
    helper = MagicMock()
    helper.get_state.return_value = None
    connector = RansomLookConnector(StubSettings(), helper)
    connector.client.get_posts = MagicMock(
        return_value=[
            {"group_name": "", "post_title": "Incomplete"},
            {
                "group_name": "akira",
                "post_title": "Bad Timestamp",
                "discovered": "not-a-date",
            },
            {
                "group_name": "akira",
                "post_title": "Example Corp",
                "discovered": "2026-01-02T03:04:05Z",
            },
            {
                "group_name": "akira",
                "post_title": "Second Corp",
                "discovered": "2026-01-02T04:04:05Z",
            },
        ]
    )
    connector.client.get_group = MagicMock(
        return_value=(
            {
                "meta": "Group description",
                "locations": [
                    {"slug": "http://example.onion/"},
                    {"slug": "http://private.onion/", "private": True},
                    "invalid",
                ],
            },
            [
                {
                    "post_title": "Example Corp",
                    "discovered": "2026-01-02T03:04:05Z",
                    "description": "Claim description",
                    "website": "example.com",
                },
                {
                    "post_title": "Second Corp",
                    "discovered": "2026-01-02 04:04:05",
                },
            ],
        )
    )
    connector.client.get_group_notes = MagicMock(
        return_value=[
            {"id": "note-1", "name": "Akira note", "content": "Pay us"},
            {"id": "empty", "content": ""},
        ]
    )

    objects = connector._collect(
        datetime(2026, 1, 1, tzinfo=timezone.utc),
        datetime(2026, 1, 3, tzinfo=timezone.utc),
    )
    types = {obj.type for obj in objects}
    assert {
        "identity",
        "intrusion-set",
        "incident",
        "report",
        "note",
        "domain-name",
        "url",
        "relationship",
    } <= types
    connector.client.get_group.assert_called_once_with("akira")
    assert helper.connector_logger.warning.call_count == 2


def make_connector(**ransomlook_updates):
    settings = StubSettings()
    if ransomlook_updates:
        source_settings = cast(RansomLookConfig, settings.ransomlook)
        settings = settings.model_copy(
            update={"ransomlook": source_settings.model_copy(update=ransomlook_updates)}
        )
    helper = MagicMock()
    helper.get_state.return_value = None
    helper.get_run_and_terminate.return_value = False
    helper.api.work.get_work.return_value = {
        "status": "complete",
        "errors": [],
        "tracking": {
            "import_expected_number": 100_000,
            "import_processed_number": 100_000,
        },
    }
    connector = RansomLookConnector(settings, helper)
    connector.client.get_post = MagicMock(return_value={})
    return connector


def test_deduplicate_and_import_windows():
    first = SimpleNamespace(id="same", value=1)
    second = SimpleNamespace(id="same", value=2)
    assert RansomLookConnector._deduplicate([first, second]) == [second]

    connector = make_connector()
    now = datetime(2026, 2, 10, tzinfo=timezone.utc)
    connector.helper.get_state.return_value = None
    assert connector._window(now) == (now - timedelta(days=7), now)
    connector.helper.get_state.return_value = {
        "state_version": 4,
        "claims": {"last_successful_run": "2026-02-09T10:00:00Z"},
    }
    assert connector._window(now) == (
        datetime(2026, 2, 8, 10, tzinfo=timezone.utc),
        now,
    )

    backfill_connector = make_connector(initial_history_days=30)
    assert backfill_connector._window(now) == (
        now - timedelta(days=30),
        now - timedelta(days=23),
    )


def test_revision_ledger_advances_changed_content_and_replays_stably():
    connector = make_connector()
    observed = datetime(2026, 8, 1, tzinfo=timezone.utc)
    baseline = connector.converter.create_group("Akira", {})
    first_objects, ledger = connector._version_objects([baseline], {}, observed)
    enriched = connector.converter.create_group("Akira", {"meta": "profile"})
    changed_objects, changed_ledger = connector._version_objects(
        [enriched], ledger, observed + timedelta(hours=1)
    )
    replay_objects, replay_ledger = connector._version_objects(
        [enriched], changed_ledger, observed + timedelta(hours=2)
    )

    assert changed_objects[0].modified > first_objects[0].modified
    assert replay_objects[0].serialize() == changed_objects[0].serialize()
    state_key = next(iter(changed_ledger))
    assert (
        replay_ledger[state_key]["fingerprint"]
        == changed_ledger[state_key]["fingerprint"]
    )
    assert replay_ledger[state_key]["modified"] == changed_ledger[state_key]["modified"]
    assert (
        replay_ledger[state_key]["last_seen"]
        == (observed + timedelta(hours=2)).isoformat()
    )


def test_revision_ledger_prunes_only_prunable_claim_history():
    connector = make_connector()
    connector.REVISION_LEDGER_MAX_ENTRIES = 3
    ledger = {
        "a"
        * 64: {
            "fingerprint": "1" * 64,
            "modified": "2026-01-01T00:00:00Z",
            "object_type": "intrusion-set",
            "last_seen": "2026-01-01T00:00:00Z",
            "prunable": "false",
        },
        "b"
        * 64: {
            "fingerprint": "2" * 64,
            "modified": "2026-01-01T00:00:00Z",
            "object_type": "report",
            "last_seen": "2026-01-01T00:00:00Z",
            "prunable": "true",
        },
        "c"
        * 64: {
            "fingerprint": "3" * 64,
            "modified": "2026-01-01T00:00:00Z",
            "object_type": "incident",
            "last_seen": "2026-01-02T00:00:00Z",
            "prunable": "true",
        },
        "d"
        * 64: {
            "fingerprint": "4" * 64,
            "modified": "2026-01-01T00:00:00Z",
            "object_type": "report",
            "last_seen": "2026-01-03T00:00:00Z",
            "prunable": "true",
        },
    }

    compacted = connector._compact_revision_ledger(ledger)

    assert set(compacted) == {"a" * 64, "d" * 64}
    assert connector.metrics.revision_ledger_evictions == 2


def test_revision_ledger_keeps_nonprunable_history_when_over_capacity():
    connector = make_connector()
    connector.REVISION_LEDGER_MAX_ENTRIES = 2
    ledger = {
        "a" * 64: {"prunable": "false", "last_seen": "2026-01-01T00:00:00Z"},
        "b" * 64: {"prunable": "false", "last_seen": "2026-01-02T00:00:00Z"},
        "c" * 64: {"prunable": "true", "last_seen": "2026-01-03T00:00:00Z"},
    }

    compacted = connector._compact_revision_ledger(ledger)

    assert set(compacted) == {"a" * 64, "b" * 64}
    assert connector.metrics.revision_ledger_evictions == 1


def test_revision_ledger_caps_oldest_nonprunable_history_when_required():
    connector = make_connector()
    connector.REVISION_LEDGER_MAX_ENTRIES = 2
    ledger = {
        "a" * 64: {"prunable": "false", "last_seen": "2026-01-01T00:00:00Z"},
        "b" * 64: {"prunable": "false", "last_seen": "2026-01-02T00:00:00Z"},
        "c" * 64: {"prunable": "false", "last_seen": "2026-01-03T00:00:00Z"},
        "d" * 64: {"prunable": "true", "last_seen": "2026-01-04T00:00:00Z"},
    }

    compacted = connector._compact_revision_ledger(ledger)

    assert set(compacted) == {"b" * 64, "c" * 64}
    assert connector.metrics.revision_ledger_evictions == 2


@pytest.mark.parametrize(
    "scope",
    ["claim", "deferred-window", "claim-state-load", "deferred-window-state-load"],
)
def test_retry_compaction_marks_claim_cursor_unsafe_for_pending_claim_overflow(scope):
    connector = make_connector()
    records = {
        "a": {
            "status": "pending",
            "first_failed_at": "2026-01-01T00:00:00Z",
        },
        "b": {
            "status": "pending",
            "first_failed_at": "2026-01-02T00:00:00Z",
        },
        "c": {
            "status": "blocked",
            "first_failed_at": "2026-01-03T00:00:00Z",
        },
    }

    compacted = connector._compact_retry_records(records, 1, scope)

    assert set(compacted) == {"a"}
    assert connector._unsafe_claim_cursor is True


def test_deduplicate_rejects_divergent_content_at_one_version():
    first = stix2.Identity(
        id="identity--00000000-0000-4000-8000-000000000001",
        name="one",
        identity_class="organization",
        created="2026-01-01T00:00:00Z",
        modified="2026-01-01T00:00:00Z",
    )
    second = stix2.Identity(
        id=first.id,
        name="two",
        identity_class="organization",
        created=first.created,
        modified=first.modified,
    )
    with pytest.raises(ValueError, match="divergent content"):
        RansomLookConnector._deduplicate([first, second])


@pytest.mark.parametrize("cursor", [123, "not-a-date", "2026-02-13T00:00:00Z"])
def test_import_window_recovers_from_invalid_or_future_state(cursor):
    connector = make_connector()
    now = datetime(2026, 2, 10, tzinfo=timezone.utc)
    connector.helper.get_state.return_value = {
        "state_version": 4,
        "claims": {"last_successful_run": cursor},
    }
    start, end = connector._window(now)
    assert end == now
    assert start <= now
    connector.helper.connector_logger.warning.assert_called_once()


def test_collect_can_disable_optional_imports():
    connector = make_connector(
        import_notes=False,
        import_infrastructure=False,
        import_victim_websites=False,
    )
    connector.client.get_posts = MagicMock(
        return_value=[
            {
                "group_name": "akira",
                "post_title": "Example Corp",
                "discovered": "2026-01-02T03:04:05Z",
            }
        ]
    )
    connector.client.get_group = MagicMock(return_value=({}, []))
    connector.client.get_group_notes = MagicMock()
    objects = connector._collect(
        datetime(2026, 1, 1, tzinfo=timezone.utc),
        datetime(2026, 1, 3, tzinfo=timezone.utc),
    )
    assert "note" not in {obj.type for obj in objects}
    assert "url" not in {obj.type for obj in objects}
    connector.client.get_group_notes.assert_not_called()


def test_collect_empty_feed_returns_empty_list():
    connector = make_connector()
    connector.client.get_posts = MagicMock(return_value=[])
    assert (
        connector._collect(
            datetime(2026, 1, 1, tzinfo=timezone.utc),
            datetime(2026, 1, 2, tzinfo=timezone.utc),
        )
        == []
    )


def test_collect_skips_future_and_oversized_claim_identities():
    connector = make_connector()
    connector.client.get_posts = MagicMock(
        return_value=[
            {
                "group_name": "akira",
                "post_title": "Future Corp",
                "discovered": "2026-01-04T00:00:00Z",
            },
            {
                "group_name": "g" * 513,
                "post_title": "Oversized",
                "discovered": "2026-01-02T00:00:00Z",
            },
        ]
    )
    connector.client.get_group = MagicMock()

    assert not connector._collect(
        datetime(2026, 1, 1, tzinfo=timezone.utc),
        datetime(2026, 1, 2, tzinfo=timezone.utc),
    )
    connector.client.get_group.assert_not_called()
    assert connector.helper.connector_logger.warning.call_count == 2


def test_group_infrastructure_respects_sensitive_policy_and_invalid_locations():
    connector = make_connector()
    group = connector.converter.create_group("akira", {})
    assert not connector._create_group_infrastructure(
        {
            "locations": [
                {"slug": "private.example", "private": "true"},
                {"slug": "files.example", "fs": True},
                {"slug": "chat.example", "chat": True},
                {"slug": "admin.example", "admin": True},
                "bad",
            ]
        },
        group.id,
        "akira",
    )
    assert not make_connector(import_infrastructure=False)._create_group_infrastructure(
        {"locations": [{"slug": "public.example"}]}, group.id, "akira"
    )

    enabled = make_connector(import_sensitive_infrastructure=True)
    objects = enabled._create_group_infrastructure(
        {
            "locations": [
                {
                    "slug": "http://profile.example/",
                    "private": True,
                    "fs": True,
                    "chat": True,
                    "admin": True,
                }
            ]
        },
        group.id,
        "akira",
    )
    infrastructure = next(obj for obj in objects if obj.type == "infrastructure")
    assert list(infrastructure["x_ransomlook_roles"]) == [
        "private",
        "file-server",
        "chat",
        "admin",
    ]
    assert any(
        obj.type == "relationship"
        and obj.relationship_type == "uses"
        and obj.source_ref == group.id
        and obj.target_ref == infrastructure.id
        for obj in objects
    )


def test_group_infrastructure_keeps_current_and_historical_locations():
    connector = make_connector()
    group = connector.converter.create_group("akira", {})
    locations = [
        {
            "slug": f"site-{index}.example",
            "updated": f"2026-01-{(index % 28) + 1:02d} 00:00:00",
            "available": index % 2 == 0,
        }
        for index in range(55)
    ]
    objects = connector._create_group_infrastructure(
        {"locations": locations}, group.id, "akira"
    )
    assert len([obj for obj in objects if obj.type == "infrastructure"]) == 55
    assert len([obj for obj in objects if obj.type == "url"]) == 55
    assert len([obj for obj in objects if obj.type == "relationship"]) == 165


def test_collect_tolerates_non_list_locations():
    connector = make_connector()
    connector.client.get_posts = MagicMock(
        return_value=[
            {
                "group_name": "akira",
                "post_title": "Example Corp",
                "discovered": "2026-01-02T03:04:05Z",
            }
        ]
    )
    connector.client.get_group = MagicMock(return_value=({"locations": "invalid"}, []))
    connector.client.get_group_notes = MagicMock(return_value=[])

    objects = connector._collect(
        datetime(2026, 1, 1, tzinfo=timezone.utc),
        datetime(2026, 1, 3, tzinfo=timezone.utc),
    )

    assert "report" in {obj.type for obj in objects}


def test_index_full_posts_skips_invalid_records_and_normalizes_titles():
    connector = make_connector()
    discovered = datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
    posts = [
        {"post_title": 123, "discovered": "2026-01-02T03:04:05Z"},
        {"post_title": "Different", "discovered": "2026-01-02T03:04:05Z"},
        {"post_title": "Example", "discovered": "invalid"},
        {"post_title": "Example", "discovered": "2026-01-03T03:04:05Z"},
    ]

    index = connector._index_full_posts(posts)
    assert ("Different", discovered) in index
    assert ("Example", discovered) not in index


def test_collect_detailed_post_cannot_override_normalized_identity():
    connector = make_connector(
        import_notes=False,
        import_infrastructure=False,
        import_victim_websites=False,
    )
    connector.client.get_posts = MagicMock(
        return_value=[
            {
                "group_name": " akira ",
                "post_title": " Example Corp ",
                "discovered": "2026-01-02T03:04:05Z",
            }
        ]
    )
    connector.client.get_group = MagicMock(
        return_value=(
            {},
            [
                {
                    "group_name": "wrong",
                    "post_title": "Example Corp",
                    "discovered": "2026-01-02T03:04:05Z",
                    "description": "Detailed description",
                }
            ],
        )
    )
    objects = connector._collect(
        datetime(2026, 1, 1, tzinfo=timezone.utc),
        datetime(2026, 1, 3, tzinfo=timezone.utc),
    )
    report = next(obj for obj in objects if obj.type == "report")
    assert report.name == "RansomLook: akira - Example Corp"
    assert "does not independently confirm intrusion" in report.description
    assert report.description.endswith("Upstream claim text:\nDetailed description")


@pytest.mark.parametrize("post_error", [False, True])
def test_collect_survives_oversized_group_and_optional_post_enrichment(post_error):
    connector = make_connector(
        import_notes=False,
        import_infrastructure=False,
        import_victim_websites=False,
    )
    connector.client.get_posts = MagicMock(
        return_value=[
            {
                "group_name": "interlock",
                "post_title": "Example Corp",
                "discovered": "2026-01-02T03:04:05Z",
            }
        ]
    )
    connector.client.get_group = MagicMock(
        side_effect=RansomLookAPIError("response exceeds size limit")
    )
    if post_error:
        connector.client.get_post.side_effect = RansomLookAPIError("post unavailable")
    else:
        connector.client.get_post.return_value = {
            "description": "Dedicated post detail"
        }

    objects = connector._collect(
        datetime(2026, 1, 1, tzinfo=timezone.utc),
        datetime(2026, 1, 3, tzinfo=timezone.utc),
    )
    report = next(obj for obj in objects if obj.type == "report")
    assert "does not independently confirm intrusion" in report.description
    assert ("Dedicated post detail" in report.description) is not post_error
    assert connector.helper.connector_logger.warning.call_count == 1 + int(post_error)


def test_magna_shaped_detail_enriches_existing_claim_without_generic_group_note():
    """Dedicated claim detail, not group summaries, carries the direct evidence."""
    connector = make_connector(
        import_infrastructure=False,
        import_victim_websites=False,
        import_wallets=False,
        import_torrents=False,
        import_leaks=False,
        import_analyses=False,
    )
    indexed = {
        "group_name": "lockbit5",
        "post_title": "sample.example",
        "discovered": "2026-06-30T12:00:00Z",
        # Empty summary values must not erase dedicated endpoint values.
        "description": "",
        "screen": None,
        "source": "",
    }
    connector.client.get_posts = MagicMock(return_value=[indexed])
    connector.client.get_group = MagicMock(
        return_value=(
            {},
            [
                {
                    "post_title": "sample.example",
                    "discovered": "2026-06-30T12:00:00Z",
                }
            ],
        )
    )
    connector.client.get_post = MagicMock(
        return_value={
            "description": "Sanitized upstream victim-claim description.",
            "link": "/post/sanitized-claim-id",
            "screen": "iVBORw0KGgo=",
            "source": "PGh0bWw+PGJvZHk+ZXZpZGVuY2U8L2JvZHk+PC9odG1sPg==",
        }
    )
    connector.client.get_group_notes = MagicMock(
        return_value=[
            {
                "id": "generic-lockbit-note",
                "name": "Generic operation ransom note",
                "content": "Generic actor-profile text",
            }
        ]
    )

    objects = connector._collect(
        datetime(2026, 6, 29, tzinfo=timezone.utc),
        datetime(2026, 7, 1, tzinfo=timezone.utc),
    )

    connector.client.get_post.assert_called_once_with("lockbit5", "sample.example")
    report = next(obj for obj in objects if obj.type == "report")
    incident = next(obj for obj in objects if obj.type == "incident")
    artifacts = [
        obj
        for obj in objects
        if obj.type == "artifact"
        and obj.x_ransomlook_evidence_kind in {"screen", "source"}
    ]
    note = next(obj for obj in objects if obj.type == "note")
    claim_url = next(
        obj
        for obj in objects
        if obj.type == "url"
        and obj.value == "https://www.ransomlook.io/post/sanitized-claim-id"
    )

    assert "Sanitized upstream victim-claim description." in report.description
    assert "Sanitized upstream victim-claim description." in incident.description
    assert {artifact.mime_type for artifact in artifacts} >= {"image/png", "text/html"}
    assert {artifact.id for artifact in artifacts} <= set(report.object_refs)
    assert claim_url.id in report.object_refs
    assert note.id not in report.object_refs
    assert note.object_refs == [connector.converter.create_group("lockbit5", {}).id]
    assert connector.converter.parse_timestamp(str(report.modified)) == (
        connector.converter.parse_timestamp("2026-06-30T12:00:00Z")
    )


def test_claim_reports_contain_only_direct_context_and_stay_separate():
    # Even an enabled explicit-IOC policy must not promote victim context by
    # association alone.
    connector = make_connector(create_indicators=True)
    connector.client.get_posts = MagicMock(
        return_value=[
            {
                "group_name": "akira",
                "post_title": "First Victim",
                "discovered": "2026-01-02T03:04:05Z",
            },
            {
                "group_name": "akira",
                "post_title": "Second Victim",
                "discovered": "2026-01-02T04:04:05Z",
            },
        ]
    )
    connector.client.get_group = MagicMock(
        return_value=(
            {
                "locations": [{"slug": "http://historic-profile.onion/"}],
            },
            [
                {
                    "post_title": "First Victim",
                    "discovered": "2026-01-02T03:04:05Z",
                    "link": "http://first-claim.onion/post",
                    "website": "https://first-victim.example/",
                },
                {
                    "post_title": "Second Victim",
                    "discovered": "2026-01-02T04:04:05Z",
                    "link": "http://second-claim.onion/post",
                    "website": "https://second-victim.example/",
                },
            ],
        )
    )
    connector.client.get_group_notes = MagicMock(
        return_value=[{"id": "profile-note", "content": "actor profile context"}]
    )

    cycle = connector._collect_cycle(
        datetime(2026, 1, 1, tzinfo=timezone.utc),
        datetime(2026, 1, 3, tzinfo=timezone.utc),
        {},
    )
    claims_by_id = {obj.id: obj for obj in cycle.claims}
    reports = [obj for obj in cycle.claims if obj.type == "report"]
    group = next(obj for obj in cycle.claims if obj.type == "intrusion-set")
    assert len(reports) == 2
    assert len({report.id for report in reports}) == 2
    assert all(group.id in report.object_refs for report in reports)
    assert "indicator" not in {obj.type for obj in cycle.claims}

    enrichment_ids = {
        obj.id for enrichment in cycle.enrichments for obj in enrichment.objects
    }
    assert enrichment_ids
    shared_profile_ids = {
        group.id,
        connector.converter.author.id,
        connector.converter.marking.id,
    }
    profile_only_ids = enrichment_ids - shared_profile_ids
    assert profile_only_ids
    assert all(not (set(report.object_refs) & profile_only_ids) for report in reports)

    report_context = []
    for report in reports:
        refs = [claims_by_id[ref] for ref in report.object_refs]
        assert len([obj for obj in refs if obj.type == "incident"]) == 1
        assert len([obj for obj in refs if obj.type == "identity"]) == 1
        assert len([obj for obj in refs if obj.type == "intrusion-set"]) == 1
        report_context.append(
            {obj.value for obj in refs if obj.type in {"domain-name", "url"}}
        )
    assert {
        "first-claim.onion",
        "http://first-claim.onion/post",
        "first-victim.example",
        "https://first-victim.example/",
    } in report_context
    assert {
        "second-claim.onion",
        "http://second-claim.onion/post",
        "second-victim.example",
        "https://second-victim.example/",
    } in report_context

    # An observed claim supports Incident attribution and targeting, but does not
    # assert that the operation itself confirmed an attack against the victim.
    relationships = [obj for obj in cycle.claims if obj.type == "relationship"]
    assert not any(
        relationship.source_ref == group.id
        and relationship.relationship_type == "targets"
        for relationship in relationships
    )


def test_collect_survives_optional_note_enrichment_failure():
    connector = make_connector(import_notes=True, import_infrastructure=False)
    connector.client.get_posts = MagicMock(
        return_value=[
            {
                "group_name": "akira",
                "post_title": "Example Corp",
                "discovered": "2026-01-02T03:04:05Z",
            }
        ]
    )
    connector.client.get_group = MagicMock(return_value=({}, []))
    connector.client.get_group_notes = MagicMock(
        side_effect=RansomLookAPIError("notes unavailable")
    )

    objects = connector._collect(
        datetime(2026, 1, 1, tzinfo=timezone.utc),
        datetime(2026, 1, 3, tzinfo=timezone.utc),
    )
    assert "report" in {obj.type for obj in objects}
    connector.helper.connector_logger.warning.assert_called_once_with(
        "Unable to import optional RansomLook notes",
        {
            "group_sha256": "8d8f469ed2ef36f5",
            "error_type": "RansomLookAPIError",
        },
    )


def test_notes_and_wallets_are_deterministic_bounded_and_profile_scoped():
    connector = make_connector(
        import_notes=True, import_wallets=True, import_infrastructure=False
    )
    connector.client.get_posts = MagicMock(
        return_value=[
            {
                "group_name": "akira",
                "post_title": "Example Corp",
                "discovered": "2026-01-02T03:04:05Z",
            }
        ]
    )
    connector.client.get_group = MagicMock(return_value=({}, []))
    connector.client.get_group_notes = MagicMock(
        return_value=[{"id": "n-1", "name": "note summary"}, {"id": "n-1"}]
    )
    connector.client.get_note = MagicMock(
        return_value={
            "id": "n-1",
            "title": "Akira original note",
            "content": "Pay the synthetic demand",
            "format": "txt",
            "updated_at": "2026-01-01T00:00:00Z",
        }
    )
    connector.client.get_group_crypto = MagicMock(
        return_value={
            "by_chain": {
                "ETH": [
                    {"blockchain": "ethereum", "address": " 0xABC ", "tx_count": 2},
                    {"blockchain": "ethereum", "address": "0xabc", "tx_count": 2},
                ],
                "bitcoin": [{"address": "bc1QEXAMPLE"}],
            }
        }
    )

    cycle = connector._collect_cycle(
        datetime(2026, 1, 1, tzinfo=timezone.utc),
        datetime(2026, 1, 3, tzinfo=timezone.utc),
        {},
    )
    profile = cycle.enrichments[0].objects
    wallets = [obj for obj in profile if obj.type == "cryptocurrency-wallet"]
    notes = [obj for obj in profile if obj.type == "note"]
    artifacts = [obj for obj in profile if obj.type == "artifact"]
    assert [wallet.value for wallet in wallets] == ["bc1qexample", "0xabc"]
    assert {wallet.x_ransomlook_chain for wallet in wallets} == {"bitcoin", "ethereum"}
    assert len(notes) == len(artifacts) == 1
    assert connector.client.get_note.call_count == 1
    assert not any(obj.type == "indicator" for obj in profile)
    report = next(obj for obj in cycle.claims if obj.type == "report")
    assert not set(report.object_refs) & {
        obj.id for obj in [*wallets, *notes, *artifacts]
    }


def test_notes_wallet_switches_and_failures_are_isolated():
    disabled = make_connector(
        import_notes=False, import_wallets=False, import_infrastructure=False
    )
    disabled.client.get_posts = MagicMock(
        return_value=[
            {
                "group_name": "akira",
                "post_title": "Example Corp",
                "discovered": "2026-01-02T03:04:05Z",
            }
        ]
    )
    disabled.client.get_group = MagicMock(return_value=({}, []))
    disabled.client.get_group_notes = MagicMock()
    disabled.client.get_group_crypto = MagicMock()
    disabled._collect_cycle(
        datetime(2026, 1, 1, tzinfo=timezone.utc),
        datetime(2026, 1, 3, tzinfo=timezone.utc),
        {},
    )
    disabled.client.get_group_notes.assert_not_called()
    disabled.client.get_group_crypto.assert_not_called()

    failing = make_connector(
        import_notes=True, import_wallets=True, import_infrastructure=False
    )
    failing.client.get_posts = disabled.client.get_posts
    failing.client.get_group = MagicMock(return_value=({}, []))
    failing.client.get_group_notes = MagicMock(
        side_effect=RansomLookCapabilityUnavailable("notes", 403)
    )
    failing.client.get_group_crypto = MagicMock(
        side_effect=RansomLookAPIError("crypto unavailable")
    )
    cycle = failing._collect_cycle(
        datetime(2026, 1, 1, tzinfo=timezone.utc),
        datetime(2026, 1, 3, tzinfo=timezone.utc),
        {},
    )
    assert any(obj.type == "report" for obj in cycle.claims)
    assert cycle.enrichments[0].complete is False


def test_note_detail_failure_keeps_summary_and_wallet_rejections_are_local():
    connector = make_connector(import_infrastructure=False)
    group = connector.converter.create_group("akira", {})
    connector.client.get_group_notes = MagicMock(
        return_value=[
            {"id": "n-1", "content": "summary text", "format": "txt"},
            {"content": "id-less text", "format": "txt"},
            {"id": "empty", "content": ""},
        ]
    )
    connector.client.get_note = MagicMock(
        side_effect=RansomLookCapabilityUnavailable("notes", 403)
    )
    notes, complete = connector._try_create_group_notes("akira", group.id)
    assert complete is True
    assert len([obj for obj in notes if obj.type == "note"]) == 2
    assert len([obj for obj in notes if obj.type == "artifact"]) == 2

    connector.client.get_group_crypto = MagicMock(
        return_value={"by_chain": {"bitcoin": [{"address": "bad address"}]}}
    )
    wallets, complete = connector._try_create_group_wallets("akira", group.id)
    assert wallets == []
    assert complete is True


def test_wallet_capability_absence_is_complete_and_content_free():
    connector = make_connector()
    group = connector.converter.create_group("akira", {})
    connector.client.get_group_crypto = MagicMock(
        side_effect=RansomLookCapabilityUnavailable("crypto", 401)
    )
    assert connector._try_create_group_wallets("akira", group.id) == ([], True)
    connector.helper.connector_logger.info.assert_called_once_with(
        "Skipping unavailable RansomLook cryptocurrency capability",
        {"capability": "crypto", "status_code": 401},
    )


def test_process_message_without_data_advances_state_without_empty_work():
    connector = make_connector()
    connector._collect_cycle = MagicMock(return_value=CollectionCycle([], [], {}))
    connector.process_message()
    assert connector.helper.set_state.call_count == 2
    connector.helper.api.work.initiate_work.assert_not_called()
    connector.helper.api.work.to_processed.assert_not_called()


def test_process_message_retains_claim_cursor_when_retry_overflows():
    connector = make_connector()
    connector._collect_cycle = MagicMock(return_value=CollectionCycle([], [], {}))
    original_next_pending = connector._next_pending_claims

    def unsafe_next_pending(*args):
        connector._unsafe_claim_cursor = True
        return original_next_pending(*args)

    connector._next_pending_claims = MagicMock(side_effect=unsafe_next_pending)

    connector.process_message()

    saved = connector.helper.set_state.call_args_list[0].args[0]
    assert "last_successful_run" not in saved["claims"]
    connector.helper.connector_logger.warning.assert_any_call(
        "Retaining RansomLook claims cursor because retry state overflowed",
        {"retry_state_evictions": 0},
    )


def test_process_message_retains_claim_cursor_when_load_compacts_pending_claims():
    connector = make_connector(max_pending_claims=1)
    cursor = "2026-02-09T10:00:00Z"
    connector.helper.get_state.return_value = {
        "state_version": 4,
        "claims": {
            "last_successful_run": cursor,
            "pending_claims": {
                "first": {
                    "group_name": "akira",
                    "post_title": "First retry",
                    "discovered": "2026-01-01T00:00:00Z",
                    "identity_discovered": "2026-01-01T00:00:00Z",
                    "context": {},
                    "reasons": ["detail"],
                    "attempts": 1,
                    "first_failed_at": "2026-01-01T00:00:00Z",
                    "status": "pending",
                },
                "second": {
                    "group_name": "akira",
                    "post_title": "Second retry",
                    "discovered": "2026-01-02T00:00:00Z",
                    "identity_discovered": "2026-01-02T00:00:00Z",
                    "context": {},
                    "reasons": ["detail"],
                    "attempts": 1,
                    "first_failed_at": "2026-01-02T00:00:00Z",
                    "status": "pending",
                },
            },
        },
    }
    connector._collect_cycle = MagicMock(return_value=CollectionCycle([], [], {}))

    connector.process_message()

    saved = connector.helper.set_state.call_args_list[0].args[0]
    assert saved["claims"]["last_successful_run"] == cursor
    assert len(saved["claims"]["pending_claims"]) == 1
    connector.helper.connector_logger.warning.assert_any_call(
        "Retaining RansomLook claims cursor because retry state overflowed",
        {"retry_state_evictions": 1},
    )


def test_process_message_retains_claim_cursor_when_load_compacts_deferred_windows():
    connector = make_connector(max_pending_claims=1)
    cursor = "2026-02-09T10:00:00Z"
    connector.helper.get_state.return_value = {
        "state_version": 4,
        "claims": {
            "last_successful_run": cursor,
            "deferred_windows": {
                "first": {
                    "start": "2026-01-01",
                    "end": "2026-01-01",
                    "reason": "record limit",
                    "attempts": 1,
                    "first_failed_at": "2026-01-01T00:00:00Z",
                    "status": "pending",
                },
                "second": {
                    "start": "2026-01-02",
                    "end": "2026-01-02",
                    "reason": "record limit",
                    "attempts": 1,
                    "first_failed_at": "2026-01-02T00:00:00Z",
                    "status": "pending",
                },
            },
        },
    }
    connector._collect_cycle = MagicMock(return_value=CollectionCycle([], [], {}))

    connector.process_message()

    saved = connector.helper.set_state.call_args_list[0].args[0]
    assert saved["claims"]["last_successful_run"] == cursor
    assert len(saved["claims"]["deferred_windows"]) == 1
    connector.helper.connector_logger.warning.assert_any_call(
        "Retaining RansomLook claims cursor because retry state overflowed",
        {"retry_state_evictions": 1},
    )


def test_process_message_sends_and_completes_work():
    connector = make_connector()
    connector._collect_cycle = MagicMock(
        return_value=CollectionCycle([SimpleNamespace(id="object--1")], [], {})
    )
    connector.helper.api.work.initiate_work.return_value = "work-1"
    connector._validated_delivery_bundles = MagicMock(return_value=["bundle"])
    connector.helper.send_stix2_bundle.return_value = ["sent"]

    connector.process_message()

    connector.helper.send_stix2_bundle.assert_called_once_with(
        "bundle",
        work_id="work-1",
        cleanup_inconsistent_bundle=True,
        no_split=True,
    )
    connector.helper.api.work.to_processed.assert_called_once()
    assert connector.helper.set_state.call_count == 2


def test_process_message_reports_failure_after_work_creation():
    connector = make_connector()
    connector._collect_cycle = MagicMock(
        return_value=CollectionCycle([SimpleNamespace(id="object--1")], [], {})
    )
    connector.helper.api.work.initiate_work.return_value = "work-1"
    connector._validated_delivery_bundles = MagicMock(return_value=["bundle"])
    connector.helper.send_stix2_bundle.side_effect = RuntimeError("send failed")

    with pytest.raises(RuntimeError, match="send failed"):
        connector.process_message()

    connector.helper.api.work.to_processed.assert_called_once_with(
        "work-1", "RansomLook bundle delivery failed", in_error=True
    )
    connector.helper.set_state.assert_not_called()


def test_process_message_failure_before_work_creation_has_no_work_to_close():
    connector = make_connector()
    connector._collect_cycle = MagicMock(
        return_value=CollectionCycle([SimpleNamespace(id="object--1")], [], {})
    )
    connector.helper.api.work.initiate_work.side_effect = RuntimeError("work failed")
    with pytest.raises(RuntimeError, match="work failed"):
        connector.process_message()
    connector.helper.api.work.to_processed.assert_not_called()


def test_process_message_collection_failure_and_interrupt_propagate_without_work():
    connector = make_connector()
    connector._collect_cycle = MagicMock(side_effect=RuntimeError("fetch failed"))
    with pytest.raises(RuntimeError, match="fetch failed"):
        connector.process_message()
    connector.helper.api.work.to_processed.assert_not_called()

    connector._collect_cycle.side_effect = KeyboardInterrupt()
    with pytest.raises(KeyboardInterrupt):
        connector.process_message()
    connector.helper.api.work.to_processed.assert_not_called()


def test_process_message_preserves_original_error_if_work_close_fails():
    connector = make_connector()
    connector.helper.api.work.initiate_work.return_value = "work-1"
    connector._collect_cycle = MagicMock(
        return_value=CollectionCycle([SimpleNamespace(id="object--1")], [], {})
    )
    connector._validated_delivery_bundles = MagicMock(return_value=["bundle"])
    connector.helper.send_stix2_bundle.side_effect = RuntimeError("send failed")
    connector.helper.api.work.to_processed.side_effect = RuntimeError("close failed")

    with pytest.raises(RuntimeError, match="send failed"):
        connector.process_message()
    connector.helper.connector_logger.error.assert_any_call(
        "Unable to close failed RansomLook work item",
        {"error_type": "RuntimeError"},
    )


def test_save_state_preserves_existing_keys_and_handles_invalid_state():
    connector = make_connector()
    end = datetime(2026, 1, 2, tzinfo=timezone.utc)
    connector.helper.get_state.return_value = {"future": "compatible"}
    connector._save_state(end)
    connector.helper.set_state.assert_called_once_with(
        {
            "future": "compatible",
            "state_version": 4,
            "claims": {
                "last_successful_run": end.isoformat(),
                "pending_claims": {},
                "deferred_windows": {},
                "revision_ledger": {},
                "route_registry": {},
            },
            "enrichment": {"pending_groups": {}},
        }
    )

    connector.helper.set_state.reset_mock()
    connector._working_state = None
    connector.helper.get_state.return_value = "invalid"
    connector._save_state(end)
    connector.helper.set_state.assert_called_once_with(
        {
            "state_version": 4,
            "claims": {
                "last_successful_run": end.isoformat(),
                "pending_claims": {},
                "deferred_windows": {},
                "revision_ledger": {},
                "route_registry": {},
            },
            "enrichment": {"pending_groups": {}},
        }
    )


def test_state_v4_preserves_unknown_keys():
    connector = make_connector()
    connector.helper.get_state.return_value = {
        "state_version": 4,
        "claims": {"last_successful_run": "2026-01-02T00:00:00Z"},
        "future": {"owned": "elsewhere"},
    }
    state = connector._load_state()
    assert state["state_version"] == 4
    assert state["claims"]["last_successful_run"] == "2026-01-02T00:00:00Z"
    assert state["future"] == {"owned": "elsewhere"}


def test_current_cursor_takes_precedence_over_changed_initial_history():
    connector = make_connector(initial_history_days=365)
    connector.helper.get_state.return_value = {
        "state_version": 4,
        "claims": {"last_successful_run": "2026-07-31T12:00:00Z"},
        "enrichment": {"pending_groups": {}},
    }
    now = datetime(2026, 8, 1, tzinfo=timezone.utc)

    assert connector._window(now) == (
        datetime(2026, 7, 30, 12, tzinfo=timezone.utc),
        now,
    )


def test_shuffled_replay_and_group_alias_casing_have_stable_membership():
    connector = make_connector(import_notes=False, import_infrastructure=False)
    posts = [
        {
            "group_name": " Akira ",
            "post_title": "Example Corp",
            "discovered": "2026-01-02T03:04:05Z",
        },
        {
            "group_name": "akira",
            "post_title": "Second Corp",
            "discovered": "2026-01-02T04:04:05Z",
        },
    ]
    connector.client.get_group = MagicMock(return_value=({}, []))
    connector.client.get_posts = MagicMock(return_value=posts)
    first = connector._collect_cycle(
        datetime(2026, 1, 1, tzinfo=timezone.utc),
        datetime(2026, 1, 3, tzinfo=timezone.utc),
        {},
    )
    connector.client.get_posts.return_value = list(reversed(posts))
    second = connector._collect_cycle(
        datetime(2026, 1, 1, tzinfo=timezone.utc),
        datetime(2026, 1, 3, tzinfo=timezone.utc),
        {},
    )
    assert {obj.id for obj in first.claims} == {obj.id for obj in second.claims}
    assert connector.client.get_group.call_count == 2
    assert len(first.enrichments) == 1


def test_optional_enrichment_failure_stays_pending_without_blocking_claim_cursor():
    connector = make_connector()
    claim = SimpleNamespace(id="incident--claim")
    enrichment = SimpleNamespace(id="intrusion-set--profile")
    connector._collect_cycle = MagicMock(
        return_value=CollectionCycle(
            [claim],
            [GroupEnrichment("akira", "Akira", [enrichment], True)],
            {"akira": "Akira"},
        )
    )
    connector.helper.api.work.initiate_work.side_effect = ["claims", "profile"]
    connector._validated_delivery_bundles = MagicMock(return_value=["bundle"])
    connector.helper.send_stix2_bundle.side_effect = [
        ["accepted"],
        RuntimeError("down"),
    ]

    connector.process_message()

    saved = [call.args[0] for call in connector.helper.set_state.call_args_list]
    assert saved[0]["claims"].get("last_successful_run") is not None
    assert saved[0]["enrichment"]["pending_groups"]["akira"]["name"] == "Akira"
    assert all(
        state["enrichment"].get("last_successful_run") is None for state in saved
    )
    connector.helper.connector_logger.warning.assert_called_with(
        "Unable to deliver optional RansomLook enrichment",
        {"group_sha256": "af1a2068f1e68daa", "error_type": "RuntimeError"},
    )


def test_run_schedules_process():
    connector = make_connector()
    connector.run()
    connector.helper.schedule_process.assert_called_once_with(
        message_callback=connector.process_message,
        duration_period=3600.0,
    )


def test_run_and_terminate_delegates_to_sdk_scheduler():
    connector = make_connector()
    connector.helper.get_run_and_terminate.return_value = True
    connector.process_message = MagicMock()
    connector.run()
    connector.process_message.assert_not_called()
    connector.helper.force_ping.assert_not_called()
    connector.helper.schedule_process.assert_called_once_with(
        message_callback=connector.process_message,
        duration_period=3600.0,
    )


def test_large_logical_delivery_uses_bounded_helper_sends_and_fails_atomically():
    connector = make_connector(max_objects_per_bundle=500)
    objects = [SimpleNamespace(id=f"object--{index}") for index in range(1441)]
    connector.helper.api.work.initiate_work.return_value = "work"
    connector._validated_delivery_bundles = MagicMock(
        return_value=["bundle-1", "bundle-2", "bundle-3"]
    )
    connector.helper.send_stix2_bundle.side_effect = [["one"], ["two"], ["three"]]

    work_id, sent = connector._deliver_objects(objects, "bounded")

    assert work_id == "work"
    assert sent == 3
    connector._validated_delivery_bundles.assert_called_once_with(objects)
    assert connector.helper.send_stix2_bundle.call_count == 3
    assert [
        call.args[0] for call in connector.helper.send_stix2_bundle.call_args_list
    ] == [
        "bundle-1",
        "bundle-2",
        "bundle-3",
    ]
    assert all(
        call.kwargs
        == {
            "work_id": "work",
            "cleanup_inconsistent_bundle": True,
            "no_split": True,
        }
        for call in connector.helper.send_stix2_bundle.call_args_list
    )
    connector.helper.api.work.initiate_work.assert_called_once_with(
        connector.helper.connect_id, "bounded", is_multipart=True
    )
    connector.helper.api.work.to_processed.assert_called_once_with(
        "work", "Imported 1441 STIX objects in 3 bundle(s)"
    )

    connector.helper.api.work.to_processed.reset_mock()
    connector.helper.send_stix2_bundle.reset_mock()
    connector.helper.send_stix2_bundle.side_effect = [
        ["one"],
        RuntimeError("private URL"),
    ]
    with pytest.raises(RuntimeError, match="private URL"):
        connector._deliver_objects(objects, "retryable")
    connector.helper.api.work.to_processed.assert_called_once_with(
        "work", "RansomLook bundle delivery failed", in_error=True
    )


def test_delivery_bundle_limit_is_real_for_a_high_cardinality_graph():
    connector = make_connector(max_objects_per_bundle=500)

    class SerializableObject:
        def __init__(self, index):
            self.id = f"identity--{index:032d}"

        def serialize(self):
            return json.dumps({"type": "identity", "id": self.id})

    objects = [SerializableObject(index) for index in range(1441)]
    connector.helper.stix2_create_bundle.side_effect = lambda chunk: json.dumps(
        {"objects": [item.id for item in chunk]}
    )

    bundle_iterator = connector._validated_delivery_bundles(objects)
    first_bundle = next(bundle_iterator)
    assert connector.helper.stix2_create_bundle.call_count == 1
    bundles = [first_bundle, *bundle_iterator]

    assert [len(json.loads(bundle)["objects"]) for bundle in bundles] == [
        500,
        500,
        441,
    ]


def test_bounded_claim_delivery_preserves_cross_bundle_graph_and_attribution():
    connector = make_connector(max_objects_per_bundle=20)
    connector.helper.api.work.initiate_work.return_value = "work"
    post = {
        "id": "bounded-claim",
        "group_name": "akira",
        "post_title": "Example Corp",
        "discovered": "2026-01-02T03:04:05Z",
        "link": "https://claim.example/post",
        "screen": base64.b64encode(b"\x89PNG\r\n\x1a\nimage").decode(),
        "source": base64.b64encode(b"<!doctype html><html></html>").decode(),
    }
    observed = datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
    group = connector.converter.create_group("akira", {})
    second_post = {
        **post,
        "id": "bounded-claim-two",
        "post_title": "Second Example Corp",
        "discovered": "2026-01-02T04:04:05Z",
    }
    graph = connector._with_attribution(
        [
            group,
            *connector._create_claim_graph(group, post, observed),
            *connector._create_claim_graph(
                group,
                second_post,
                datetime(2026, 1, 2, 4, 4, 5, tzinfo=timezone.utc),
            ),
        ]
    )
    reports = [obj for obj in graph if obj.type == "report"]
    artifact_ids = {obj.id for obj in graph if obj.type == "artifact"}
    relationship_ids = {obj.id for obj in graph if obj.type == "relationship"}
    emitted: dict[str, dict] = {}
    cleanup_values: list[bool] = []
    submitted_sizes: list[int] = []
    send_calls = 0

    connector.helper.stix2_create_bundle.side_effect = (
        OpenCTIConnectorHelper.stix2_create_bundle
    )

    def capture_bounded_bundle(bundle, **kwargs):
        nonlocal send_calls
        send_calls += 1
        cleanup_values.append(kwargs["cleanup_inconsistent_bundle"])
        assert kwargs["no_split"] is True
        data = json.loads(bundle)
        submitted_sizes.append(len(data["objects"]))
        (
            _,
            incompatible,
            _,
        ) = OpenCTIStix2Splitter().split_bundle_with_expectations(
            bundle=bundle,
            use_json=True,
            cleanup_inconsistent_bundle=kwargs["cleanup_inconsistent_bundle"],
        )
        assert incompatible == []
        for item in data["objects"]:
            emitted[item["id"]] = item
        return [bundle]

    connector.helper.send_stix2_bundle.side_effect = capture_bounded_bundle

    connector._deliver_objects(graph, "bounded graph")

    assert cleanup_values and all(cleanup_values)
    assert send_calls == 2
    assert submitted_sizes and max(submitted_sizes) <= 20
    assert relationship_ids <= emitted.keys()
    assert {report.id for report in reports} <= emitted.keys()
    assert all(
        set(emitted[report.id]["object_refs"]) == set(report.object_refs)
        for report in reports
    )
    assert artifact_ids <= {
        object_ref for report in reports for object_ref in report.object_refs
    }
    assert all(
        emitted[report.id]["created_by_ref"] == connector.converter.author.id
        for report in reports
    )
    assert all(
        emitted[artifact_id]["x_opencti_created_by_ref"]
        == connector.converter.author.id
        for artifact_id in artifact_ids
    )


def test_pending_actor_enrichment_is_self_contained_when_group_detail_fails():
    connector = make_connector(max_objects_per_bundle=20)
    connector.client.get_posts = MagicMock(return_value=[])
    connector.client.get_group = MagicMock(
        side_effect=RansomLookAPIError("group detail unavailable")
    )
    connector.client.get_actors = MagicMock(return_value=[{"name": "Alice"}])
    connector.client.get_actor = MagicMock(
        return_value={"name": "Alice", "relations": {"groups": ["Akira"]}}
    )

    cycle = connector._collect_cycle(
        datetime(2026, 1, 1, tzinfo=timezone.utc),
        datetime(2026, 1, 2, tzinfo=timezone.utc),
        {"akira": "Akira"},
    )

    assert cycle.claims == []
    assert len(cycle.enrichments) == 1
    enrichment = cycle.enrichments[0]
    group = connector.converter.create_group("Akira", {})
    assert group.id in {obj.id for obj in enrichment.objects}
    group_relationship = next(
        obj
        for obj in enrichment.objects
        if obj.type == "relationship"
        and getattr(obj, "x_ransomlook_relation", None) == "group"
    )
    assert group_relationship.target_ref == group.id

    connector.helper.stix2_create_bundle.side_effect = (
        OpenCTIConnectorHelper.stix2_create_bundle
    )
    bundles = list(connector._validated_delivery_bundles(enrichment.objects))
    emitted_ids = {
        item["id"] for bundle in bundles for item in json.loads(bundle)["objects"]
    }
    assert {obj.id for obj in enrichment.objects} == emitted_ids
    assert all(len(json.loads(bundle)["objects"]) <= 20 for bundle in bundles)


def test_delivery_bundle_validation_fails_before_delivery():
    connector = make_connector(max_objects_per_bundle=1)

    with pytest.raises(ValueError, match="contains no objects"):
        list(connector._validated_delivery_bundles([]))

    missing_ref = SimpleNamespace(
        id="report--00000000-0000-4000-8000-000000000000",
        serialize=lambda: json.dumps(
            {
                "type": "report",
                "id": "report--00000000-0000-4000-8000-000000000000",
                "created_by_ref": "identity--00000000-0000-4000-8000-000000000001",
            }
        ),
    )
    with pytest.raises(ValueError, match="unresolved STIX dependencies"):
        list(connector._validated_delivery_bundles([missing_ref]))

    duplicate = SimpleNamespace(
        id=missing_ref.id,
        serialize=lambda: json.dumps({"type": "report", "id": missing_ref.id}),
    )
    with pytest.raises(ValueError, match="invalid object IDs"):
        list(connector._validated_delivery_bundles([missing_ref, duplicate]))

    author = SimpleNamespace(
        id="identity--00000000-0000-4000-8000-000000000001",
        serialize=lambda: json.dumps(
            {
                "type": "identity",
                "id": "identity--00000000-0000-4000-8000-000000000001",
            }
        ),
    )
    with pytest.raises(ValueError, match="dependency closure exceeds"):
        list(connector._validated_delivery_bundles([author, missing_ref]))

    connector.helper.send_stix2_bundle.assert_not_called()


def test_oversized_direct_claim_context_is_dropped_before_core_or_evidence():
    connector = make_connector(max_objects_per_bundle=32)
    observed = datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
    group = connector.converter.create_group("akira", {})
    post = {
        "id": "oversized-context-claim",
        "group_name": "akira",
        "post_title": "Synthetic context-bound claim",
        "discovered": observed.isoformat(),
        "screen": base64.b64encode(b"\x89PNG\r\n\x1a\nimage").decode(),
        "source": base64.b64encode(b"<!doctype html><html></html>").decode(),
    }
    optional_context = [
        connector.converter.create_victim(f"Optional context {index}")
        for index in range(40)
    ]

    graph = connector._create_claim_graph(
        group, post, observed, direct_leak_objects=optional_context
    )

    graph_ids = {obj.id for obj in graph}
    assert not ({obj.id for obj in optional_context} & graph_ids)
    assert len([obj for obj in graph if obj.type == "artifact"]) == 2
    report = next(obj for obj in graph if obj.type == "report")
    assert not ({obj.id for obj in optional_context} & set(report.object_refs))
    assert getattr(report, "x_opencti_files")
    assert not hasattr(report, "x_opencti_content")
    connector.helper.connector_logger.warning.assert_any_call(
        "Skipping optional RansomLook claim context that exceeds delivery bounds",
        {
            "identity_sha256": connector._identity_hash(
                post["group_name"], post["post_title"]
            ),
            "objects_skipped": 40,
        },
    )


def test_large_report_evidence_exceeding_serialized_cap_fails_open():
    connector = make_connector(
        max_objects_per_bundle=500,
        max_bundle_size_mb=1,
        max_artifact_size_mb=1,
    )
    observed = datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
    group = connector.converter.create_group("akira", {})
    post = {
        "id": "oversized-serialized-claim",
        "group_name": "akira",
        "post_title": "Synthetic byte-bound claim",
        "discovered": observed.isoformat(),
        "screen": base64.b64encode(b"\x89PNG\r\n\x1a\n" + bytes(300_000)).decode(),
        "source": base64.b64encode(
            b"<!doctype html><html>" + (b"A" * 300_000) + b"</html>"
        ).decode(),
    }
    graph = connector._with_attribution(
        [group, *connector._create_claim_graph(group, post, observed)]
    )

    report = next(obj for obj in graph if obj.type == "report")
    assert not [obj for obj in graph if obj.type == "artifact"]
    assert not hasattr(report, "x_opencti_files")
    assert not hasattr(report, "x_opencti_content")
    connector.helper.connector_logger.warning.assert_any_call(
        "Skipping RansomLook claim evidence that exceeds delivery bounds",
        {
            "identity_sha256": connector._identity_hash(
                post["group_name"], post["post_title"]
            ),
            "artifacts_skipped": 2,
        },
    )
    connector.helper.stix2_create_bundle.side_effect = (
        OpenCTIConnectorHelper.stix2_create_bundle
    )
    bundles = list(connector._validated_delivery_bundles(graph))
    assert bundles
    assert all(len(bundle.encode("utf-8")) <= 1024 * 1024 for bundle in bundles)
    connector.helper.send_stix2_bundle.assert_not_called()


def test_run_metrics_are_content_free_and_cover_evidence_budget():
    connector = make_connector()
    connector._collect_cycle = MagicMock(
        return_value=CollectionCycle([SimpleNamespace(id="object--1")], [], {})
    )
    connector.helper.api.work.initiate_work.return_value = "work"
    connector._validated_delivery_bundles = MagicMock(return_value=["bundle"])
    connector.helper.send_stix2_bundle.return_value = ["accepted"]

    connector.process_message()

    metrics_call = next(
        call
        for call in connector.helper.connector_logger.info.call_args_list
        if call.args[0] == "RansomLook run metrics"
    )
    metrics = metrics_call.args[1]
    assert metrics["outcome"] == "success"
    assert metrics["objects_imported"] == 1
    assert metrics["bundles_delivered"] == 1
    assert metrics["artifacts_accepted"] == 0
    assert metrics["artifacts_rejected"] == 0
    assert "token" not in repr(metrics_call).casefold()
    assert ".onion" not in repr(metrics_call).casefold()


def test_worker_reconciliation_blocks_state_on_error_and_accepts_progress():
    connector = make_connector()
    connector._collect_cycle = MagicMock(
        return_value=CollectionCycle([SimpleNamespace(id="object--1")], [], {})
    )
    connector.helper.api.work.initiate_work.return_value = "work"
    connector._validated_delivery_bundles = MagicMock(return_value=["bundle"])
    connector.helper.api.work.get_work.side_effect = [
        {
            "status": "progress",
            "errors": [],
            "tracking": {
                "import_expected_number": 1,
                "import_processed_number": 0,
            },
        },
        {
            "status": "complete",
            "errors": [],
            "tracking": {
                "import_expected_number": 1,
                "import_processed_number": 1,
            },
        },
    ]

    connector.process_message()

    connector.helper.api.work.initiate_work.assert_called_once_with(
        connector.helper.connect_id,
        connector.helper.api.work.initiate_work.call_args.args[1],
        is_multipart=True,
    )
    assert connector.helper.set_state.called

    failed = make_connector()
    failed._collect_cycle = connector._collect_cycle
    failed.helper.api.work.initiate_work.return_value = "work"
    failed._validated_delivery_bundles = MagicMock(return_value=["bundle"])
    failed.helper.api.work.get_work.return_value = {
        "status": "complete",
        "errors": [{"message": "worker rejected input"}],
        "tracking": {
            "import_expected_number": 1,
            "import_processed_number": 1,
        },
    }
    with pytest.raises(RuntimeError, match="worker reported"):
        failed.process_message()
    failed.helper.set_state.assert_not_called()


def test_work_reconciliation_timeout_is_bounded(monkeypatch):
    connector = make_connector(work_reconciliation_timeout_seconds=10)
    connector.helper.api.work.get_work.return_value = {
        "status": "progress",
        "errors": [],
        "tracking": {
            "import_expected_number": 1,
            "import_processed_number": 0,
        },
    }
    monotonic = iter([0.0, 0.0, 11.0, 11.0])
    monkeypatch.setattr("connector.connector.time.monotonic", lambda: next(monotonic))
    monkeypatch.setattr("connector.connector.time.sleep", lambda _seconds: None)
    connector.client.run_deadline = 100.0

    with pytest.raises(TimeoutError, match="reconciliation"):
        connector._wait_for_work_completion("work", 1)


def test_work_reconciliation_uses_independent_opencti_deadline(monkeypatch):
    connector = make_connector(work_reconciliation_timeout_seconds=10)
    connector.client.run_deadline = 0.5
    connector.helper.api.work.get_work.side_effect = [
        {
            "status": "progress",
            "errors": [],
            "tracking": {
                "import_expected_number": 1,
                "import_processed_number": 0,
            },
        },
        {
            "status": "complete",
            "errors": [],
            "tracking": {
                "import_expected_number": 1,
                "import_processed_number": 1,
            },
        },
    ]
    monotonic = iter([0.0, 0.1, 0.2, 1.0])
    monkeypatch.setattr("connector.connector.time.monotonic", lambda: next(monotonic))
    monkeypatch.setattr("connector.connector.time.sleep", lambda _seconds: None)

    connector._wait_for_work_completion("work", 1)

    assert connector.helper.api.work.get_work.call_count == 2


@pytest.mark.parametrize(
    ("work", "message"),
    [
        (None, "invalid work state"),
        ({"status": "complete", "errors": []}, "no import tracking"),
        (
            {
                "status": "complete",
                "errors": [],
                "tracking": {
                    "import_expected_number": 2,
                    "import_processed_number": 1,
                },
            },
            "incomplete tracking",
        ),
        ({"status": "error", "errors": []}, "did not complete"),
    ],
)
def test_work_reconciliation_rejects_invalid_terminal_states(work, message):
    connector = make_connector()
    connector.helper.api.work.get_work.return_value = work
    with pytest.raises(RuntimeError, match=message):
        connector._wait_for_work_completion("work", 1)


def test_failed_claim_detail_is_retried_outside_the_replay_window():
    connector = make_connector(
        enrich_actor_profiles=False,
        import_post_evidence=False,
        import_torrents=False,
        import_leaks=False,
        import_analyses=False,
    )
    post = {
        "id": "source-id",
        "group_name": "akira",
        "post_title": "Retry Corp",
        "discovered": "2026-01-02T03:04:05Z",
    }
    connector.client.get_posts = MagicMock(return_value=[post])
    connector.client.get_group = MagicMock(return_value=({}, []))
    connector.client.get_post = MagicMock(side_effect=RansomLookAPIError("down"))
    first = connector._collect_cycle(
        datetime(2026, 1, 1, tzinfo=timezone.utc),
        datetime(2026, 1, 3, tzinfo=timezone.utc),
        {},
    )
    assert len(first.incomplete_claims) == 1
    retry_state = connector._next_pending_claims({}, first)
    assert next(iter(retry_state.values()))["reasons"] == ["detail"]

    connector.client.get_posts.return_value = []
    connector.client.get_post.side_effect = None
    connector.client.get_post.return_value = {"description": "recovered"}
    second = connector._collect_cycle(
        datetime(2026, 2, 1, tzinfo=timezone.utc),
        datetime(2026, 2, 2, tzinfo=timezone.utc),
        {},
        retry_state,
    )
    assert second.processed_claim_keys == set(retry_state)
    assert second.incomplete_claims == {}
    assert connector._next_pending_claims(retry_state, second) == {}
    report = next(obj for obj in second.claims if obj.type == "report")
    assert "recovered" in report.description


def test_same_route_recurrences_remain_distinct_and_do_not_share_aliases():
    connector = make_connector(
        enrich_actor_profiles=False,
        import_post_evidence=False,
        import_torrents=False,
        import_leaks=False,
        import_analyses=False,
    )
    posts = [
        {
            "group_name": "akira",
            "post_title": "Repeated Victim",
            "discovered": "2026-01-02T00:00:00Z",
        },
        {
            "group_name": "akira",
            "post_title": "Repeated Victim",
            "discovered": "2026-01-05T00:00:00Z",
        },
    ]
    connector.client.get_posts = MagicMock(return_value=posts)
    connector.client.get_group = MagicMock(return_value=({}, []))
    connector.client.get_post = MagicMock(return_value={"description": "detail"})

    cycle = connector._collect_cycle(
        datetime(2026, 1, 1, tzinfo=timezone.utc),
        datetime(2026, 1, 6, tzinfo=timezone.utc),
        {},
    )

    reports = [obj for obj in cycle.claims if obj.type == "report"]
    incidents = [obj for obj in cycle.claims if obj.type == "incident"]
    assert len(reports) == 2
    assert len({report.id for report in reports}) == 2
    assert len({incident.id for incident in incidents}) == 2
    assert not hasattr(reports[0], "x_opencti_stix_ids")
    assert not hasattr(reports[1], "x_opencti_stix_ids")


def test_route_registry_selection_handles_aliases_ids_and_corrections():
    connector = make_connector()
    old = "2026-01-02T00:00:00+00:00"
    alias = "2026-01-02T01:00:00+00:00"
    occurrence_key = connector._claim_state_key(old)
    occurrences = connector._route_registry_occurrences(
        {
            "last_seen": "2026-01-03T00:00:00Z",
            "occurrences": {
                occurrence_key: {
                    "identity_discovered": old,
                    "last_seen": "2026-01-03T00:00:00Z",
                    "aliases": [alias, "not-a-date", 7],
                    "source_ids": ["id:one", 8],
                },
                "bad": {"identity_discovered": "bad"},
            },
        }
    )

    assert set(occurrences) == {occurrence_key}
    assert occurrences[occurrence_key]["aliases"] == [old, alias]
    assert (
        connector._select_occurrence_identity(
            occurrences,
            datetime(2026, 1, 2, 1, tzinfo=timezone.utc),
            set(),
            1,
        )
        == old
    )
    assert (
        connector._select_occurrence_identity(
            occurrences,
            datetime(2026, 1, 10, tzinfo=timezone.utc),
            {"id:one"},
            1,
        )
        == old
    )
    assert (
        connector._select_occurrence_identity(
            occurrences,
            datetime(2026, 1, 2, 12, tzinfo=timezone.utc),
            set(),
            1,
        )
        == old
    )
    assert (
        connector._select_occurrence_identity(
            occurrences,
            datetime(2026, 1, 10, tzinfo=timezone.utc),
            set(),
            2,
        )
        == "2026-01-10T00:00:00+00:00"
    )

    assert connector._route_registry_occurrences(None) == {}
    assert connector._route_registry_occurrences({"identity_discovered": old}) == {}
    assert (
        connector._route_registry_occurrences({"occurrences": {"bad": "not-a-dict"}})
        == {}
    )


def test_timestamp_corrections_keep_ids_and_immutable_created_fields_stable():
    connector = make_connector(import_post_evidence=False)
    group = connector.converter.create_group("akira", {})
    original = {
        "group_name": "akira",
        "post_title": "Corrected Victim",
        "discovered": "2026-01-02T00:00:00Z",
    }
    corrected = {
        **original,
        "discovered": "2026-01-02T12:00:00Z",
        "_ransomlook_identity_discovered": original["discovered"],
    }

    first = connector._create_claim_graph(
        group, original, datetime(2026, 1, 2, tzinfo=timezone.utc)
    )
    second = connector._create_claim_graph(
        group, corrected, datetime(2026, 1, 2, 12, tzinfo=timezone.utc)
    )
    first_by_id = {obj.id: obj for obj in first}
    second_by_id = {obj.id: obj for obj in second}
    assert set(first_by_id) == set(second_by_id)
    for object_id, item in first_by_id.items():
        if hasattr(item, "created"):
            assert second_by_id[object_id].created == item.created
    report = next(obj for obj in second if obj.type == "report")
    assert report.published == datetime(2026, 1, 2, 12, tzinfo=timezone.utc)


def test_retry_helpers_normalize_context_and_invalid_timestamps():
    connector = make_connector(max_claim_retries=5, max_enrichment_retries=5)
    post = {
        "id": 123,
        "post_id": "post-1",
        "uuid": "uuid-1",
        "link": "https://claim.example",
        "website": "https://victim.example",
        "group_name": "akira",
        "post_title": "Context Victim",
        "discovered": "2026-01-02T00:00:00Z",
        "_ransomlook_identity_discovered": "2026-01-01T23:00:00Z",
    }

    record = connector._claim_retry_record(
        post,
        ["detail", "detail"],
        {"attempts": 1, "first_failed_at": "not-a-date"},
    )
    retry_post = connector._pending_claim_post(record)
    group_retry = connector._group_retry_record(
        "Akira",
        {"attempts": 1, "first_failed_at": "not-a-date"},
        failed=True,
        now=datetime(2026, 1, 3, tzinfo=timezone.utc),
    )

    assert retry_post["id"] == "123"
    assert retry_post["uuid"] == "uuid-1"
    assert retry_post["_ransomlook_identity_discovered"] == "2026-01-01T23:00:00+00:00"
    assert record["reasons"] == ["detail"]
    assert record["status"] == "pending"
    assert group_retry["first_failed_at"] == "2026-01-03T00:00:00+00:00"
    assert connector._clamped_attempts("bad", 5) is None
    assert connector._clamped_attempts(True, 5) is None
    assert connector._clamped_attempts(-1, 5) is None
    assert connector._clamped_attempts(9, 5) == 5


def test_blocked_claim_occurrence_is_not_refetched_from_normal_feed():
    connector = make_connector(
        enrich_actor_profiles=False,
        import_post_evidence=False,
        import_torrents=False,
        import_leaks=False,
        import_analyses=False,
    )
    blocked_post = {
        "group_name": "akira",
        "post_title": "Blocked Victim",
        "discovered": "2026-01-02T00:00:00Z",
    }
    new_recurrence = {
        **blocked_post,
        "discovered": "2026-01-05T00:00:00Z",
    }
    blocked_record = connector._claim_retry_record(blocked_post, ["detail"], None)
    blocked_record["status"] = "blocked"
    blocked_key = connector._claim_state_key_from_post(blocked_post)
    connector.client.get_posts = MagicMock(return_value=[blocked_post, new_recurrence])
    connector.client.get_group = MagicMock(return_value=({}, []))
    connector.client.get_post = MagicMock(return_value={"description": "detail"})

    cycle = connector._collect_cycle(
        datetime(2026, 1, 1, tzinfo=timezone.utc),
        datetime(2026, 1, 6, tzinfo=timezone.utc),
        {},
        {blocked_key: blocked_record},
    )

    reports = [obj for obj in cycle.claims if obj.type == "report"]
    assert len(reports) == 1
    assert reports[0].published == datetime(2026, 1, 5, tzinfo=timezone.utc)
    connector.client.get_post.assert_called_once_with("akira", "Blocked Victim")


def test_evidence_budget_exhaustion_creates_bounded_claim_retry():
    connector = make_connector(
        enrich_actor_profiles=False,
        max_artifacts_per_run=1,
        import_torrents=False,
        import_leaks=False,
        import_analyses=False,
    )
    posts = [
        {
            "group_name": "akira",
            "post_title": title,
            "discovered": f"2026-01-02T0{index}:04:05Z",
        }
        for index, title in enumerate(("One", "Two"), 1)
    ]
    connector.client.get_posts = MagicMock(return_value=posts)
    connector.client.get_group = MagicMock(return_value=({}, []))
    connector.client.get_post = MagicMock(
        return_value={"screen": base64.b64encode(b"\x89PNG\r\n\x1a\nimage").decode()}
    )

    cycle = connector._collect_cycle(
        datetime(2026, 1, 1, tzinfo=timezone.utc),
        datetime(2026, 1, 3, tzinfo=timezone.utc),
        {},
    )

    assert len(cycle.incomplete_claims) == 1
    assert next(iter(cycle.incomplete_claims.values()))["reasons"] == [
        "evidence-budget"
    ]


def test_claim_screenshot_budget_is_reserved_before_optional_torrent_artifact():
    connector = make_connector(
        enrich_actor_profiles=False,
        max_artifacts_per_run=1,
        import_leaks=False,
        import_analyses=False,
    )
    post = {
        "id": "post-1",
        "group_name": "akira",
        "post_title": "Budget Victim",
        "discovered": "2026-01-02T00:00:00Z",
    }
    connector.client.get_posts = MagicMock(return_value=[post])
    connector.client.get_group = MagicMock(return_value=({}, []))
    connector.client.get_post = MagicMock(
        return_value={
            "id": "post-1",
            "screen": base64.b64encode(b"\x89PNG\r\n\x1a\nclaim").decode(),
        }
    )
    connector.client.get_torrents = MagicMock(
        return_value=[
            {
                "infohash": "a" * 40,
                "post_id": "post-1",
                "torrent": "ZDM6Zm9vZQ==",
            }
        ]
    )

    cycle = connector._collect_cycle(
        datetime(2026, 1, 1, tzinfo=timezone.utc),
        datetime(2026, 1, 3, tzinfo=timezone.utc),
        {},
    )

    artifacts = [obj for obj in cycle.claims if obj.type == "artifact"]
    assert [artifact.mime_type for artifact in artifacts] == ["image/png"]
    assert cycle.incomplete_claims == {}


def test_optional_actor_enrichment_reserves_request_budget_for_claims():
    connector = make_connector(
        max_requests_per_run=4,
        import_post_evidence=False,
        import_torrents=False,
        import_leaks=False,
        import_analyses=False,
        import_notes=False,
        import_wallets=False,
    )
    post = {
        "group_name": "akira",
        "post_title": "Reserved Budget Victim",
        "discovered": "2026-01-02T00:00:00Z",
    }

    def consume_request() -> None:
        if connector.client.request_attempts >= connector.client.max_requests_per_run:
            raise RansomLookCycleBudgetExhausted("budget")
        connector.client.request_attempts += 1

    def get_posts(*_args, **_kwargs):
        consume_request()
        return [post]

    def get_actors():
        consume_request()
        return [
            {
                "name": f"Actor {index}",
                "relations": {"groups": ["akira"]},
            }
            for index in range(20)
        ]

    def get_actor(name):
        consume_request()
        return {"name": name, "relations": {"groups": ["akira"]}}

    def get_group(_name):
        consume_request()
        return {}, []

    def get_post(_group, _title):
        consume_request()
        return {"description": "detail"}

    connector.client.get_posts = MagicMock(side_effect=get_posts)
    connector.client.get_actors = MagicMock(side_effect=get_actors)
    connector.client.get_actor = MagicMock(side_effect=get_actor)
    connector.client.get_group = MagicMock(side_effect=get_group)
    connector.client.get_post = MagicMock(side_effect=get_post)

    cycle = connector._collect_cycle(
        datetime(2026, 1, 1, tzinfo=timezone.utc),
        datetime(2026, 1, 3, tzinfo=timezone.utc),
        {},
    )

    assert any(obj.type == "report" for obj in cycle.claims)
    assert cycle.incomplete_claims == {}
    connector.client.get_group.assert_called_once_with("akira")
    connector.client.get_post.assert_called_once_with("akira", "Reserved Budget Victim")
    connector.client.get_actor.assert_not_called()


def test_named_actor_enrichment_skips_enumeration_when_required_budget_reserved():
    connector = make_connector()
    connector.client.request_attempts = connector.client.max_requests_per_run - 1
    connector.client.get_actors = MagicMock(side_effect=AssertionError("not called"))

    actors, complete = connector._try_create_named_actor_profiles(
        {"akira"}, request_reserve=1
    )

    assert actors == {"akira": []}
    assert complete is False
    connector.client.get_actors.assert_not_called()


def test_request_budget_exhaustion_retains_claim_retry_work():
    connector = make_connector(
        enrich_actor_profiles=False,
        import_post_evidence=False,
        import_torrents=False,
        import_leaks=False,
        import_analyses=False,
    )
    post = {
        "group_name": "akira",
        "post_title": "Request Victim",
        "discovered": "2026-01-02T00:00:00Z",
    }

    def exhausted_posts(*_args, **_kwargs):
        connector.client.request_attempts = connector.client.max_requests_per_run
        return [post]

    connector.client.get_posts = MagicMock(side_effect=exhausted_posts)
    connector.client.get_group = MagicMock(side_effect=AssertionError("not called"))

    cycle = connector._collect_cycle(
        datetime(2026, 1, 1, tzinfo=timezone.utc),
        datetime(2026, 1, 3, tzinfo=timezone.utc),
        {},
    )

    assert cycle.claims == []
    assert list(cycle.incomplete_claims.values())[0]["reasons"] == ["request-budget"]
    connector.client.get_group.assert_not_called()


def test_request_budget_exception_during_group_fetch_retains_claim_retry_work():
    connector = make_connector(
        enrich_actor_profiles=False,
        import_post_evidence=False,
        import_torrents=False,
        import_leaks=False,
        import_analyses=False,
    )
    post = {
        "group_name": "akira",
        "post_title": "Group Budget Victim",
        "discovered": "2026-01-02T00:00:00Z",
    }
    connector.client.get_posts = MagicMock(return_value=[post])
    connector.client.get_group = MagicMock(
        side_effect=RansomLookCycleBudgetExhausted("budget")
    )
    connector.client.get_post = MagicMock(side_effect=AssertionError("not called"))

    cycle = connector._collect_cycle(
        datetime(2026, 1, 1, tzinfo=timezone.utc),
        datetime(2026, 1, 3, tzinfo=timezone.utc),
        {},
    )

    assert cycle.claims == []
    assert list(cycle.incomplete_claims.values())[0]["reasons"] == ["request-budget"]
    connector.client.get_post.assert_not_called()


def test_request_budget_exhaustion_after_one_detail_retains_remaining_claim():
    connector = make_connector(
        enrich_actor_profiles=False,
        import_post_evidence=False,
        import_torrents=False,
        import_leaks=False,
        import_analyses=False,
    )
    posts = [
        {
            "group_name": "akira",
            "post_title": "First",
            "discovered": "2026-01-02T00:00:00Z",
        },
        {
            "group_name": "akira",
            "post_title": "Second",
            "discovered": "2026-01-02T01:00:00Z",
        },
    ]
    connector.client.get_posts = MagicMock(return_value=posts)
    connector.client.get_group = MagicMock(return_value=({}, []))

    def one_detail(*_args):
        connector.client.request_attempts = connector.client.max_requests_per_run
        return {"description": "first detail"}

    connector.client.get_post = MagicMock(side_effect=one_detail)

    cycle = connector._collect_cycle(
        datetime(2026, 1, 1, tzinfo=timezone.utc),
        datetime(2026, 1, 3, tzinfo=timezone.utc),
        {},
    )

    assert len([obj for obj in cycle.claims if obj.type == "report"]) == 1
    assert list(cycle.incomplete_claims.values())[0]["post_title"] == "Second"
    assert list(cycle.incomplete_claims.values())[0]["reasons"] == ["request-budget"]


def test_request_budget_exception_during_required_detail_retains_remaining_claims():
    connector = make_connector(
        enrich_actor_profiles=False,
        import_post_evidence=False,
        import_torrents=False,
        import_leaks=False,
        import_analyses=False,
    )
    post = {
        "group_name": "akira",
        "post_title": "Budget Exception Victim",
        "discovered": "2026-01-02T00:00:00Z",
    }
    connector.client.get_posts = MagicMock(return_value=[post])
    connector.client.get_group = MagicMock(return_value=({}, []))
    connector.client.get_post = MagicMock(
        side_effect=RansomLookCycleBudgetExhausted("budget")
    )

    cycle = connector._collect_cycle(
        datetime(2026, 1, 1, tzinfo=timezone.utc),
        datetime(2026, 1, 3, tzinfo=timezone.utc),
        {},
    )

    assert cycle.claims == []
    assert list(cycle.incomplete_claims.values())[0]["reasons"] == ["request-budget"]


def test_run_object_budget_retains_overflow_claim_for_retry():
    connector = make_connector(
        enrich_actor_profiles=False,
        import_post_evidence=False,
        import_torrents=False,
        import_leaks=False,
        import_analyses=False,
        max_objects_per_run=1,
    )
    post = {
        "group_name": "akira",
        "post_title": "Object Victim",
        "discovered": "2026-01-02T00:00:00Z",
    }
    connector.client.get_posts = MagicMock(return_value=[post])
    connector.client.get_group = MagicMock(return_value=({}, []))
    connector.client.get_post = MagicMock(return_value={"description": "detail"})

    cycle = connector._collect_cycle(
        datetime(2026, 1, 1, tzinfo=timezone.utc),
        datetime(2026, 1, 3, tzinfo=timezone.utc),
        {},
    )

    assert "report" not in {obj.type for obj in cycle.claims}
    assert "incident" not in {obj.type for obj in cycle.claims}
    assert list(cycle.incomplete_claims.values())[0]["reasons"] == ["object-budget"]


def test_group_object_budget_retains_all_prepared_claims_for_retry():
    connector = make_connector(
        enrich_actor_profiles=False,
        import_post_evidence=False,
        import_torrents=False,
        import_leaks=False,
        import_analyses=False,
        max_objects_per_run=0,
    )
    post = {
        "group_name": "akira",
        "post_title": "Object Group Victim",
        "discovered": "2026-01-02T00:00:00Z",
    }
    connector.client.get_posts = MagicMock(return_value=[post])
    connector.client.get_group = MagicMock(return_value=({}, []))
    connector.client.get_post = MagicMock(return_value={"description": "detail"})

    cycle = connector._collect_cycle(
        datetime(2026, 1, 1, tzinfo=timezone.utc),
        datetime(2026, 1, 3, tzinfo=timezone.utc),
        {},
    )

    assert cycle.claims == []
    assert list(cycle.incomplete_claims.values())[0]["reasons"] == ["object-budget"]


@pytest.mark.parametrize("replay_days", [0, 1, 6])
def test_every_supported_replay_window_advances_cursor(replay_days):
    connector = make_connector(replay_window_days=replay_days)
    cursor = datetime(2026, 1, 1, tzinfo=timezone.utc)
    connector.helper.get_state.return_value = {
        "state_version": 4,
        "claims": {"last_successful_run": cursor.isoformat()},
        "enrichment": {"pending_groups": {}},
    }
    start, end = connector._window(datetime(2026, 2, 1, tzinfo=timezone.utc))
    assert start == cursor - timedelta(days=replay_days)
    assert end > cursor
    assert end - start == connector.MAX_COLLECTION_WINDOW


def test_disabled_enrichment_clears_dormant_backlog_without_fetching_it():
    connector = make_connector(enrich_actor_profiles=False)
    connector.helper.get_state.return_value = {
        "state_version": 4,
        "claims": {},
        "enrichment": {
            "pending_groups": {
                "akira": {
                    "name": "Akira",
                    "attempts": 1,
                    "first_failed_at": "2026-01-01T00:00:00Z",
                    "status": "pending",
                }
            }
        },
    }
    connector.client.get_posts = MagicMock(return_value=[])
    connector.client.get_group = MagicMock(side_effect=AssertionError("not called"))

    connector.process_message()

    connector.client.get_group.assert_not_called()
    assert (
        connector.helper.set_state.call_args.args[0]["enrichment"]["pending_groups"]
        == {}
    )


def test_retry_records_transition_to_blocked_instead_of_hot_looping():
    connector = make_connector(max_claim_retries=2, max_enrichment_retries=2)
    post = {
        "group_name": "akira",
        "post_title": "Blocked",
        "discovered": "2026-01-01T00:00:00Z",
    }
    previous = {
        "attempts": 1,
        "first_failed_at": datetime.now(timezone.utc).isoformat(),
    }
    claim = connector._claim_retry_record(post, ["detail"], previous)
    group = connector._group_retry_record(
        "Akira",
        previous,
        failed=True,
        now=datetime.now(timezone.utc),
    )
    assert claim["status"] == "blocked"
    assert group["status"] == "blocked"


def test_deferred_window_state_is_bounded_retried_and_resolved():
    connector = make_connector(max_claim_retries=2)
    now = datetime(2026, 1, 3, tzinfo=timezone.utc)
    deferred = DeferredPostWindow("2026-01-01", "2026-01-01", "record limit")
    first_cycle = CollectionCycle([], [], {}, deferred_windows=[deferred])
    first = connector._next_deferred_windows({}, first_cycle, now)
    key = next(iter(first))
    assert first[key]["status"] == "pending"

    second = connector._next_deferred_windows(first, first_cycle, now)
    assert second[key]["status"] == "blocked"

    resolved_cycle = CollectionCycle([], [], {}, resolved_deferred_keys={key})
    assert connector._next_deferred_windows(first, resolved_cycle, now) == {}


def test_deferred_window_children_inherit_parent_attempts_and_date_keys():
    connector = make_connector(max_claim_retries=3)
    now = datetime(2026, 1, 3, tzinfo=timezone.utc)
    parent_key = connector._deferred_window_key(
        "2026-01-01T00:00:00Z", "2026-01-02T23:59:59Z"
    )
    parent = {
        parent_key: {
            "status": "pending",
            "start": "2026-01-01T00:00:00Z",
            "end": "2026-01-02T23:59:59Z",
            "attempts": 1,
            "first_failed_at": "2026-01-01T00:00:00Z",
            "reason": "record limit",
        }
    }
    child = DeferredPostWindow("2026-01-01T12:00:00Z", "2026-01-01T12:00:00Z", "again")
    child_key = connector._deferred_window_key(child.start, child.end)
    cycle = CollectionCycle(
        [],
        [],
        {},
        deferred_windows=[child],
        resolved_deferred_keys={parent_key},
        deferred_window_metadata={child_key: parent[parent_key]},
    )

    result = connector._next_deferred_windows(parent, cycle, now)

    assert parent_key not in result
    assert result[child_key]["start"] == "2026-01-01"
    assert result[child_key]["end"] == "2026-01-01"
    assert result[child_key]["attempts"] == 2


def test_route_registry_prunes_invalid_old_and_excess_entries():
    connector = make_connector(retry_max_age_days=1)
    connector.ROUTE_REGISTRY_MAX_ENTRIES = 2
    now = datetime(2026, 1, 5, tzinfo=timezone.utc)
    current = {
        "a" * 64: {"last_seen": "bad"},
        "b" * 64: {"last_seen": "2026-01-01T00:00:00Z"},
        "c" * 64: {"last_seen": "2026-01-04T12:00:00Z"},
        "d" * 64: {"last_seen": "2026-01-04T13:00:00Z"},
    }
    cycle = CollectionCycle(
        [],
        [],
        {},
        route_registry_updates={"e" * 64: {"last_seen": "2026-01-04T14:00:00Z"}},
    )

    result = connector._next_route_registry(current, cycle, now)

    assert set(result) == {"d" * 64, "e" * 64}
    assert connector.metrics.retry_state_evictions == 1


def test_state_v4_prunes_malformed_retry_records_and_group_strings():
    connector = make_connector()
    route_key = "a" * 64
    occurrence_key = "b" * 64
    connector.helper.get_state.return_value = {
        "state_version": 4,
        "claims": {
            "pending_claims": {
                "bad": {"status": "pending"},
                "invalid-first-failed": {
                    "group_name": "akira",
                    "post_title": "Bad first failure",
                    "discovered": "2026-01-02T00:00:00Z",
                    "reasons": ["detail"],
                    "attempts": 1,
                    "first_failed_at": "not-a-date",
                    "status": "pending",
                },
                "invalid-reasons": {
                    "group_name": "akira",
                    "post_title": "Bad reasons",
                    "discovered": "2026-01-02T00:00:00Z",
                    "reasons": [42],
                    "attempts": 1,
                    "first_failed_at": None,
                    "status": "pending",
                },
                "context-sanitized": {
                    "group_name": "akira",
                    "post_title": "Context sanitized",
                    "discovered": "2026-01-02T00:00:00Z",
                    "reasons": ["detail"],
                    "attempts": 1,
                    "first_failed_at": None,
                    "context": "bad",
                    "status": "pending",
                },
            },
            "deferred_windows": {
                "bad": {"start": 1},
                "invalid-first-failed": {
                    "start": "2026-01-01",
                    "end": "2026-01-01",
                    "reason": "record limit",
                    "attempts": 1,
                    "first_failed_at": "not-a-date",
                    "status": "pending",
                },
            },
            "revision_ledger": {"bad": {"fingerprint": 1}},
            "route_registry": {
                route_key: {
                    "occurrences": {
                        occurrence_key: {
                            "identity_discovered": "2026-01-01T00:00:00Z",
                            "last_seen": "2026-01-02T00:00:00Z",
                            "aliases": [],
                            "source_ids": [],
                        }
                    }
                }
            },
        },
        "enrichment": {
            "pending_groups": {
                "akira": "Akira",
                7: {"name": "Ignored"},
                "invalid-first-failed": {
                    "name": "Bad actor",
                    "attempts": 1,
                    "first_failed_at": "not-a-date",
                    "status": "pending",
                },
            }
        },
    }
    state = connector._load_state()
    assert len(state["claims"]["pending_claims"]) == 1
    assert state["claims"]["deferred_windows"] == {}
    assert state["claims"]["revision_ledger"] == {}
    assert state["claims"]["route_registry"][route_key]["last_seen"] == (
        "2026-01-02T00:00:00+00:00"
    )
    assert state["enrichment"]["pending_groups"] == {}


def test_state_load_rekeys_pending_claims_and_clamps_lowered_retry_limits():
    connector = make_connector(max_claim_retries=2, max_enrichment_retries=2)
    claim_record = {
        "group_name": "akira",
        "post_title": "Retry Victim",
        "discovered": "2026-01-02T00:00:00Z",
        "identity_discovered": "2026-01-01T23:00:00Z",
        "context": {"id": "source-id"},
        "reasons": ["detail"],
        "attempts": 50,
        "first_failed_at": "2026-01-03T00:00:00Z",
        "status": "pending",
    }
    connector.helper.get_state.return_value = {
        "state_version": 4,
        "claims": {
            "pending_claims": {"f" * 64: claim_record},
            "deferred_windows": {
                "e"
                * 64: {
                    "start": "2026-01-04T00:00:00Z",
                    "end": "2026-01-04T23:59:59Z",
                    "reason": "record limit",
                    "attempts": 50,
                    "first_failed_at": "2026-01-04T00:00:00Z",
                    "status": "pending",
                }
            },
            "revision_ledger": {
                "d"
                * 64: {
                    "fingerprint": "c" * 64,
                    "modified": "2026-01-01T00:00:00Z",
                }
            },
        },
        "enrichment": {
            "pending_groups": {
                "akira": {
                    "name": "Akira",
                    "attempts": 50,
                    "first_failed_at": "2026-01-01T00:00:00Z",
                    "status": "pending",
                }
            }
        },
    }

    state = connector._load_state()

    retry_post = connector._pending_claim_post(claim_record)
    expected_key = connector._claim_state_key_from_post(retry_post)
    assert set(state["claims"]["pending_claims"]) == {expected_key}
    assert state["claims"]["pending_claims"][expected_key]["attempts"] == 2
    assert state["claims"]["pending_claims"][expected_key]["status"] == "blocked"
    deferred_key = connector._deferred_window_key("2026-01-04", "2026-01-04")
    assert set(state["claims"]["deferred_windows"]) == {deferred_key}
    assert state["claims"]["deferred_windows"][deferred_key]["start"] == "2026-01-04"
    assert state["claims"]["deferred_windows"][deferred_key]["status"] == "blocked"
    assert state["claims"]["revision_ledger"]["d" * 64]["object_type"] == "unknown"
    assert state["enrichment"]["pending_groups"]["akira"]["status"] == "blocked"


def test_collection_retries_deferred_windows_and_skips_invalid_or_blocked_state():
    connector = make_connector(
        enrich_actor_profiles=False,
        import_post_evidence=False,
        import_torrents=False,
        import_leaks=False,
        import_analyses=False,
    )
    recovered = {
        "group_name": "akira",
        "post_title": "Recovered",
        "discovered": "2026-01-02T00:00:00Z",
    }
    new_deferred = DeferredPostWindow("2026-01-03", "2026-01-03", "record limit")
    connector.client.get_posts = MagicMock(
        side_effect=[PostBatch([], [new_deferred]), PostBatch([recovered], [])]
    )
    connector.client.get_group = MagicMock(return_value=({}, []))
    connector.client.get_post = MagicMock(return_value={"description": "detail"})
    valid_key = "a" * 64
    cycle = connector._collect_cycle(
        datetime(2026, 1, 1, tzinfo=timezone.utc),
        datetime(2026, 1, 3, tzinfo=timezone.utc),
        {},
        {
            "bad": {"status": "blocked"},
            "invalid": {"status": "pending"},
        },
        {
            valid_key: {
                "status": "pending",
                "start": "2026-01-02",
                "end": "2026-01-02",
            },
            "blocked": {"status": "blocked"},
            "invalid": {"status": "pending", "start": 1, "end": 2},
        },
    )
    assert cycle.resolved_deferred_keys == {valid_key, "invalid"}
    assert cycle.deferred_windows == [new_deferred]
    assert any(item.type == "report" for item in cycle.claims)


def test_collection_preserves_deferred_metadata_and_merges_exact_duplicate_rows():
    connector = make_connector(
        enrich_actor_profiles=False,
        import_post_evidence=False,
        import_torrents=False,
        import_leaks=False,
        import_analyses=False,
    )
    parent_key = connector._deferred_window_key("2026-01-01", "2026-01-02")
    child = DeferredPostWindow("2026-01-01", "2026-01-01", "record limit")
    duplicate = {
        "group_name": "akira",
        "post_title": "Duplicate Victim",
        "discovered": "2026-01-02T00:00:00Z",
    }
    richer_duplicate = {**duplicate, "website": "https://victim.example"}
    connector.client.get_posts = MagicMock(
        side_effect=[
            PostBatch([], [child]),
            PostBatch([duplicate, richer_duplicate], []),
        ]
    )
    connector.client.get_group = MagicMock(return_value=({}, []))
    connector.client.get_post = MagicMock(return_value={"description": "detail"})

    cycle = connector._collect_cycle(
        datetime(2026, 1, 1, tzinfo=timezone.utc),
        datetime(2026, 1, 3, tzinfo=timezone.utc),
        {},
        {},
        {
            parent_key: {
                "status": "pending",
                "start": "2026-01-01",
                "end": "2026-01-02",
                "attempts": 1,
                "first_failed_at": "2026-01-01T00:00:00Z",
                "reason": "record limit",
            }
        },
    )

    child_key = connector._deferred_window_key("2026-01-01", "2026-01-01")
    assert cycle.resolved_deferred_keys == {parent_key}
    assert cycle.deferred_window_metadata[child_key]["attempts"] == 1
    assert len([obj for obj in cycle.claims if obj.type == "report"]) == 1
    assert any(
        obj.type == "url" and obj.value == "https://victim.example/"
        for obj in cycle.claims
    )


def test_optional_conversion_exception_is_bounded_to_enrichment():
    connector = make_connector(import_notes=False, import_wallets=False)
    post = {
        "group_name": "akira",
        "post_title": "Claim",
        "discovered": "2026-01-02T00:00:00Z",
    }
    connector.client.get_posts = MagicMock(return_value=[post])
    connector.client.get_group = MagicMock(return_value=({"meta": "profile"}, []))
    connector.client.get_post = MagicMock(return_value={"description": "detail"})
    connector._create_group_infrastructure = MagicMock(
        side_effect=ValueError("malformed optional profile")
    )
    cycle = connector._collect_cycle(
        datetime(2026, 1, 1, tzinfo=timezone.utc),
        datetime(2026, 1, 3, tzinfo=timezone.utc),
        {},
    )
    assert any(item.type == "report" for item in cycle.claims)
    assert cycle.enrichments[0].complete is False


def test_mixed_synthetic_cycle_keeps_claim_and_actor_profile_boundaries():
    connector = make_connector(
        import_sensitive_infrastructure=True,
        import_location_evidence=True,
    )
    indexed = {
        "id": "post-1",
        "group_name": "Akira",
        "post_title": "Synthetic Victim",
        "discovered": "2026-01-02T03:04:05Z",
    }
    full = {
        **indexed,
        "link": "http://claim.example.test/post-1",
        "website": "https://victim.example.test/",
        "screen": "iVBORw0KGgo=",
        "source": "PGh0bWw+PC9odG1sPg==",
    }
    connector.client.get_posts = MagicMock(return_value=[indexed])
    connector.client.get_group = MagicMock(
        return_value=(
            {
                "locations": [
                    {
                        "slug": "http://profile.example.test/",
                        "available": False,
                        "chat": True,
                        "screen": "iVBORw0KGgo=",
                    }
                ]
            },
            [full],
        )
    )
    connector.client.get_actors = MagicMock(return_value=[{"name": "Alice"}])
    connector.client.get_actor = MagicMock(
        return_value={"name": "Alice", "relations": {"groups": ["Akira"]}}
    )
    connector.client.get_group_notes = MagicMock(
        return_value=[{"id": "note-1", "content": "synthetic note"}]
    )
    connector.client.get_note = MagicMock(return_value={})
    connector.client.get_group_crypto = MagicMock(
        return_value={
            "by_chain": {"bitcoin": [{"address": "1BoatSLRHtKNngkdXEeobR76b53LETtpyT"}]}
        }
    )
    connector.client.get_torrents = MagicMock(
        return_value=[{"infohash": "a" * 40, "groups": ["Akira"]}]
    )
    connector.client.get_leaks = MagicMock(return_value=[])

    cycle = connector._collect_cycle(
        datetime(2026, 1, 1, tzinfo=timezone.utc),
        datetime(2026, 1, 3, tzinfo=timezone.utc),
        {},
    )

    claim_by_id = {obj.id: obj for obj in cycle.claims}
    report = next(obj for obj in cycle.claims if obj.type == "report")
    claim_artifacts = [
        claim_by_id[ref]
        for ref in report.object_refs
        if claim_by_id[ref].type == "artifact"
    ]
    assert {artifact.mime_type for artifact in claim_artifacts} == {
        "image/png",
        "text/html",
    }

    profile = cycle.enrichments[0].objects
    profile_types = {obj.type for obj in profile}
    assert {
        "infrastructure",
        "threat-actor",
        "note",
        "cryptocurrency-wallet",
        "url",
    } <= profile_types
    forbidden_profile_ids = {
        obj.id
        for obj in profile
        if obj.type
        in {"infrastructure", "threat-actor", "note", "cryptocurrency-wallet"}
    }
    assert not (set(report.object_refs) & forbidden_profile_ids)
    assert any(
        obj.type == "infrastructure" and obj.x_ransomlook_available is False
        for obj in profile
    )
    assert any(
        obj.type == "artifact" and obj.mime_type == "image/png" for obj in profile
    )
    assert "indicator" not in {obj.type for obj in [*cycle.claims, *profile]}

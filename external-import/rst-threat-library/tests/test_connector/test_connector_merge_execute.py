from unittest.mock import MagicMock, patch

import pytest
from connector.connector import RSTThreatLibrary, UpsertPrep
from connector.merge_split import MergeCandidate, MergeSplitPlan, SplitCandidate
from connector.settings import ConnectorSettings
from connector.utils import ThreatObjectType


class StubConnectorSettings(ConnectorSettings):
    @classmethod
    def _load_config_dict(cls, _, handler):
        return handler(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                "connector": {
                    "id": "connector-id",
                    "name": "RST Threat Library",
                    "scope": "intrusion-set,malware,tool,campaign",
                    "log_level": "error",
                    "duration_period": "PT5M",
                },
                "rst_threat_library": {
                    "baseurl": "http://test.com",
                    "apikey": "test-api-key",
                    "object_types": "malware",
                    "merge_split": True,
                    "respect_user_edits": True,
                    "sync_labels": "rst-threat-library",
                    "reconcile_exclude_labels": "do-not-touch",
                    "reconcile_allow_created_by": "identity--allowed",
                },
            }
        )


class StubConnectorSettingsNoRespect(ConnectorSettings):
    @classmethod
    def _load_config_dict(cls, _, handler):
        return handler(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                "connector": {
                    "id": "connector-id",
                    "name": "RST Threat Library",
                    "scope": "intrusion-set,malware",
                    "log_level": "error",
                    "duration_period": "PT5M",
                },
                "rst_threat_library": {
                    "baseurl": "http://test.com",
                    "apikey": "test-api-key",
                    "object_types": "malware",
                    "respect_user_edits": False,
                },
            }
        )


@pytest.fixture
def connector():
    settings = StubConnectorSettings()
    helper = MagicMock()
    helper.connector_logger = MagicMock()
    helper.connect_id = "connector-id"
    helper.api.work.initiate_work.return_value = "work-1"
    helper.stix2_create_bundle.return_value = '{"type":"bundle","objects":[]}'
    helper.send_stix2_bundle.return_value = ["bundle-sent"]
    return RSTThreatLibrary(config=settings, helper=helper)


def _split_candidate(**overrides):
    oc = {
        "id": "uuid-keep",
        "standard_id": "malware--keep",
        "name": "KeepMe",
        "aliases": ["SplitOff"],
        "confidence": 40,
    }
    data = dict(
        opencti_entity=oc,
        keep_api_item={
            "standard_id": "malware--keep",
            "name": "KeepMe",
            "confidence": 50,
        },
        aliases_to_remove=["SplitOff"],
        split_off_api_items=[
            {
                "standard_id": "malware--split-off",
                "name": "SplitOff",
                "confidence": 50,
            }
        ],
    )
    data.update(overrides)
    return SplitCandidate(**data)


def test_apply_merge_split_for_type_handles_catalogue_fetch_failure(connector):
    client = MagicMock()
    client.iter_all_items.side_effect = RuntimeError("catalogue down")

    connector._apply_merge_split_for_type(client, {}, 1, ThreatObjectType.MALWARE)

    connector.helper.connector_logger.error.assert_called()
    assert "catalogue fetch failed" in connector.helper.connector_logger.error.call_args.args[0]


def test_apply_merge_split_for_type_returns_when_no_candidates(connector):
    client = MagicMock()
    client.iter_all_items.return_value = iter(
        [{"standard_id": "malware--1", "name": "One"}]
    )
    connector._opencti_entities_for_merge_split = MagicMock(return_value=[])
    connector._execute_split = MagicMock()
    connector._execute_merge = MagicMock()

    with patch(
        "connector.connector.analyze_merge_split",
        return_value=MergeSplitPlan(),
    ):
        connector._apply_merge_split_for_type(client, {}, 1, ThreatObjectType.MALWARE)

    connector._execute_split.assert_not_called()
    connector._execute_merge.assert_not_called()
    info = " ".join(
        str(c.args[0])
        for c in connector.helper.connector_logger.info.call_args_list
        if c.args
    )
    assert "no candidates" in info


def test_apply_merge_split_for_type_dispatches_split_and_merge(connector):
    client = MagicMock()
    client.iter_all_items.return_value = iter([])
    connector._opencti_entities_for_merge_split = MagicMock(return_value=[])
    connector._execute_split = MagicMock()
    connector._execute_merge = MagicMock()
    split = _split_candidate()
    merge = MergeCandidate(
        target_api_item={"standard_id": "malware--target", "name": "Target"},
        opencti_entities_to_merge=[
            {"id": "uuid-a", "standard_id": "malware--a", "name": "A"}
        ],
    )

    with patch(
        "connector.connector.analyze_merge_split",
        return_value=MergeSplitPlan(splits=[split], merges=[merge]),
    ):
        connector._apply_merge_split_for_type(
            client, {}, 1_700_000_000, ThreatObjectType.MALWARE
        )

    connector._execute_split.assert_called_once()
    connector._execute_merge.assert_called_once()


def test_execute_split_happy_path_updates_aliases_and_pushes(connector):
    connector._analyst_locks_entity = MagicMock(return_value=False)
    connector._batch_send = MagicMock(return_value=True)
    connector._prepare_upsert_item = MagicMock(
        side_effect=lambda _t, item, _s: UpsertPrep(skip=False, api_item=item)
    )
    sdo = MagicMock()
    connector._upsert_sdo_from_prep = MagicMock(return_value=sdo)
    connector.converter.build_identity = MagicMock(return_value=None)

    split = _split_candidate()
    state: dict = {}
    connector._execute_split(
        split, timestamp=1, obj_type=ThreatObjectType.MALWARE, state=state
    )

    connector.helper.api.stix_domain_object.update_field.assert_called_once()
    connector._batch_send.assert_called_once()
    assert "malware--keep" in state["managed_ids"][ThreatObjectType.MALWARE]
    assert "malware--split-off" in state["managed_ids"][ThreatObjectType.MALWARE]
    assert ThreatObjectType.MALWARE not in (state.get("split_failures") or {})


def test_execute_split_records_failure_when_alias_update_fails(connector):
    connector._analyst_locks_entity = MagicMock(return_value=False)
    connector.helper.api.stix_domain_object.update_field.side_effect = RuntimeError(
        "alias boom"
    )
    connector._batch_send = MagicMock()

    split = _split_candidate()
    state: dict = {}
    connector._execute_split(
        split, timestamp=1, obj_type=ThreatObjectType.MALWARE, state=state
    )

    entry = state["split_failures"][ThreatObjectType.MALWARE]["malware--keep"]
    assert entry["count"] == 1
    info = " ".join(
        str(c.args[0])
        for c in connector.helper.connector_logger.info.call_args_list
        if c.args
    )
    assert "alias update failed" in info
    connector._batch_send.assert_not_called()


def test_execute_split_skips_when_missing_ids(connector):
    connector._batch_send = MagicMock()
    split = _split_candidate(
        opencti_entity={"name": "Broken", "aliases": ["X"]},
    )
    connector._execute_split(
        split, timestamp=1, obj_type=ThreatObjectType.MALWARE, state={}
    )
    connector._batch_send.assert_not_called()


def test_execute_split_records_failure_when_sdo_cannot_be_built(connector):
    connector._analyst_locks_entity = MagicMock(return_value=False)
    connector._batch_send = MagicMock()
    connector._prepare_upsert_item = MagicMock(
        side_effect=lambda _t, item, _s: UpsertPrep(skip=False, api_item=item)
    )
    connector._upsert_sdo_from_prep = MagicMock(return_value=None)

    split = _split_candidate()
    state: dict = {}
    connector._execute_split(
        split, timestamp=1, obj_type=ThreatObjectType.MALWARE, state=state
    )

    entry = state["split_failures"][ThreatObjectType.MALWARE]["malware--keep"]
    assert entry["count"] == 1
    connector._batch_send.assert_not_called()
    connector.helper.api.stix_domain_object.update_field.assert_called_once()
    error = " ".join(
        str(c.args[0])
        for c in connector.helper.connector_logger.error.call_args_list
        if c.args
    )
    assert "failed to build SDO" in error


def test_opencti_entities_for_merge_split_ignores_alias_overlap_alone(connector):
    connector._list_opencti_domain_objects = MagicMock(
        return_value=[
            {
                "standard_id": "malware--unrelated",
                "name": "Shared Alias",
                "aliases": ["keep"],
                "objectLabel": [],
            },
            {
                "standard_id": "malware--owned",
                "name": "Owned",
                "aliases": [],
                "objectLabel": [{"value": "rst-threat-library"}],
            },
        ]
    )

    entities = connector._opencti_entities_for_merge_split(
        ThreatObjectType.MALWARE,
        {"managed_ids": {}},
        api_items=[
            {
                "standard_id": "malware--api",
                "name": "API",
                "aliases": ["Shared Alias"],
            }
        ],
    )

    assert [e["standard_id"] for e in entities] == ["malware--owned"]


def test_opencti_entities_for_merge_split_includes_managed_ids(connector):
    connector._list_opencti_domain_objects = MagicMock(
        return_value=[
            {
                "standard_id": "malware--managed",
                "name": "Managed",
                "aliases": [],
                "objectLabel": [],
            }
        ]
    )

    entities = connector._opencti_entities_for_merge_split(
        ThreatObjectType.MALWARE,
        {"managed_ids": {ThreatObjectType.MALWARE: ["malware--managed"]}},
        api_items=[],
    )

    assert [e["standard_id"] for e in entities] == ["malware--managed"]


def test_execute_merge_skips_protected_target_as_survivor(connector, monkeypatch):
    monkeypatch.setattr("connector.connector.time.sleep", lambda _: None)
    connector._prepare_upsert_item = MagicMock(
        return_value=UpsertPrep(
            skip=False,
            api_item={"standard_id": "malware--api", "name": "API", "confidence": 40},
        )
    )
    connector._upsert_sdo_from_prep = MagicMock(return_value=MagicMock())
    connector._batch_send = MagicMock(return_value=True)
    connector._analyst_locks_entity = MagicMock(return_value=False)
    connector._opencti_fusion_merge = MagicMock(return_value=["malware--dup"])
    connector._should_allow_reconcile_delete = MagicMock(
        side_effect=lambda entity: entity.get("standard_id") != "malware--api"
    )

    protected_target = {
        "id": "uuid-api",
        "standard_id": "malware--api",
        "name": "API",
        "aliases": ["a", "b", "c"],
        "objectLabel": [{"value": "do-not-touch"}],
        "confidence": 40,
    }
    allowed_dup = {
        "id": "uuid-dup",
        "standard_id": "malware--dup",
        "name": "Dup",
        "aliases": ["a"],
        "confidence": 40,
    }
    connector._read_opencti_entity = MagicMock(
        side_effect=lambda _t, sid: {
            "malware--api": protected_target,
            "malware--dup": allowed_dup,
        }.get(sid)
    )

    merge = MergeCandidate(
        target_api_item={
            "standard_id": "malware--api",
            "name": "API",
            "confidence": 40,
        },
        opencti_entities_to_merge=[allowed_dup],
    )
    state: dict = {}
    connector._execute_merge(
        merge, timestamp=1, obj_type=ThreatObjectType.MALWARE, state=state
    )

    connector._opencti_fusion_merge.assert_called_once()
    fusion_target = connector._opencti_fusion_merge.call_args.args[0]
    assert fusion_target["standard_id"] == "malware--dup"


def test_execute_merge_aborts_when_only_fusion_target_is_protected(
    connector, monkeypatch
):
    monkeypatch.setattr("connector.connector.time.sleep", lambda _: None)
    connector._prepare_upsert_item = MagicMock(
        return_value=UpsertPrep(
            skip=False,
            api_item={"standard_id": "malware--api", "name": "API", "confidence": 40},
        )
    )
    connector._upsert_sdo_from_prep = MagicMock(return_value=MagicMock())
    connector._batch_send = MagicMock(return_value=True)
    connector._analyst_locks_entity = MagicMock(return_value=False)
    connector._opencti_fusion_merge = MagicMock()
    connector._should_allow_reconcile_delete = MagicMock(return_value=False)

    protected_target = {
        "id": "uuid-api",
        "standard_id": "malware--api",
        "name": "API",
        "aliases": ["a"],
        "confidence": 40,
    }
    connector._read_opencti_entity = MagicMock(return_value=protected_target)

    merge = MergeCandidate(
        target_api_item={
            "standard_id": "malware--api",
            "name": "API",
            "confidence": 40,
        },
        opencti_entities_to_merge=[protected_target],
    )
    connector._execute_merge(
        merge, timestamp=1, obj_type=ThreatObjectType.MALWARE, state={}
    )

    connector._opencti_fusion_merge.assert_not_called()


def test_opencti_fusion_merge_fuses_allowed_sources(connector):
    connector._should_allow_reconcile_delete = MagicMock(return_value=True)
    connector._is_entity_user_edited = MagicMock(return_value=False)

    target = {"id": "uuid-target", "standard_id": "malware--target", "name": "Target"}
    sources = [
        {"id": "uuid-a", "standard_id": "malware--a", "name": "A"},
        {"id": "uuid-b", "standard_id": "malware--b", "name": "B"},
    ]

    merged = connector._opencti_fusion_merge(
        target, sources, ThreatObjectType.MALWARE, {}
    )

    assert merged == ["malware--a", "malware--b"]
    connector.helper.api.stix.merge.assert_called_once_with(
        id="uuid-target", object_ids=["uuid-a", "uuid-b"]
    )


def test_opencti_fusion_merge_skips_protected_and_locked_sources(connector):
    connector._should_allow_reconcile_delete = MagicMock(side_effect=[False, True])
    connector._is_entity_user_edited = MagicMock(return_value=True)

    target = {"id": "uuid-target", "standard_id": "malware--target", "name": "Target"}
    sources = [
        {"id": "uuid-a", "standard_id": "malware--a", "name": "Protected"},
        {"id": "uuid-b", "standard_id": "malware--b", "name": "Locked"},
    ]

    merged = connector._opencti_fusion_merge(
        target, sources, ThreatObjectType.MALWARE, {}
    )

    assert merged == []
    connector.helper.api.stix.merge.assert_not_called()


def test_opencti_fusion_merge_handles_api_error(connector):
    connector._should_allow_reconcile_delete = MagicMock(return_value=True)
    connector._is_entity_user_edited = MagicMock(return_value=False)
    connector.helper.api.stix.merge.side_effect = RuntimeError("merge failed")

    merged = connector._opencti_fusion_merge(
        {"id": "uuid-target", "standard_id": "malware--target", "name": "Target"},
        [{"id": "uuid-a", "standard_id": "malware--a", "name": "A"}],
        ThreatObjectType.MALWARE,
        {},
    )

    assert merged == []
    connector.helper.connector_logger.error.assert_called()


def test_execute_merge_fuses_into_preferred_survivor(connector, monkeypatch):
    monkeypatch.setattr("connector.connector.time.sleep", lambda _: None)
    connector._prepare_upsert_item = MagicMock(
        return_value=UpsertPrep(
            skip=False,
            api_item={"standard_id": "malware--api", "name": "API", "confidence": 40},
        )
    )
    connector._upsert_sdo_from_prep = MagicMock(return_value=MagicMock())
    connector._batch_send = MagicMock(return_value=True)
    connector._analyst_locks_entity = MagicMock(return_value=False)
    connector._opencti_fusion_merge = MagicMock(return_value=["malware--dup"])

    preferred = {
        "id": "uuid-preferred",
        "standard_id": "malware--preferred",
        "name": "Preferred",
        "aliases": ["a", "b", "c"],
        "confidence": 40,
    }
    duplicate = {
        "id": "uuid-dup",
        "standard_id": "malware--dup",
        "name": "Dup",
        "aliases": [],
        "confidence": 40,
    }
    api_target = {
        "id": "uuid-api",
        "standard_id": "malware--api",
        "name": "API",
        "aliases": ["a"],
        "confidence": 40,
    }

    def read_side_effect(obj_type, sid):
        return {
            "malware--api": api_target,
            "malware--preferred": preferred,
        }.get(sid)

    connector._read_opencti_entity = MagicMock(side_effect=read_side_effect)

    merge = MergeCandidate(
        target_api_item={
            "standard_id": "malware--api",
            "name": "API",
            "confidence": 40,
        },
        opencti_entities_to_merge=[preferred, duplicate],
    )
    state: dict = {"managed_ids": {ThreatObjectType.MALWARE: ["malware--dup"]}}

    connector._execute_merge(
        merge, timestamp=1, obj_type=ThreatObjectType.MALWARE, state=state
    )

    connector._opencti_fusion_merge.assert_called_once()
    fusion_target = connector._opencti_fusion_merge.call_args.args[0]
    assert fusion_target["standard_id"] == "malware--preferred"
    assert "malware--dup" not in state["managed_ids"][ThreatObjectType.MALWARE]
    assert "malware--preferred" in state["managed_ids"][ThreatObjectType.MALWARE]


def test_execute_merge_skips_fusion_when_survivor_upsert_fails(connector):
    connector._prepare_upsert_item = MagicMock(
        return_value=UpsertPrep(
            skip=False,
            api_item={"standard_id": "malware--api", "name": "API"},
        )
    )
    connector._upsert_sdo_from_prep = MagicMock(return_value=MagicMock())
    connector._batch_send = MagicMock(return_value=False)
    connector._opencti_fusion_merge = MagicMock()

    merge = MergeCandidate(
        target_api_item={"standard_id": "malware--api", "name": "API"},
        opencti_entities_to_merge=[
            {"id": "uuid-a", "standard_id": "malware--a", "name": "A"}
        ],
    )
    connector._execute_merge(
        merge, timestamp=1, obj_type=ThreatObjectType.MALWARE, state={}
    )

    connector._opencti_fusion_merge.assert_not_called()


def test_entity_has_exclude_label_true_and_false(connector):
    assert connector._entity_has_exclude_label(
        {"objectLabel": [{"value": "do-not-touch"}]}
    )
    assert not connector._entity_has_exclude_label(
        {"objectLabel": [{"value": "other"}]}
    )
    assert not connector._entity_has_exclude_label({})


def test_should_allow_reconcile_delete_respects_exclude_and_allowlist(connector):
    assert not connector._should_allow_reconcile_delete(
        {
            "standard_id": "malware--1",
            "objectLabel": [{"value": "do-not-touch"}],
            "createdBy": {"standard_id": "identity--allowed"},
        }
    )
    assert not connector._should_allow_reconcile_delete(
        {
            "standard_id": "malware--2",
            "createdBy": {"standard_id": "identity--other"},
        }
    )
    assert connector._should_allow_reconcile_delete(
        {
            "standard_id": "malware--3",
            "createdBy": {"standard_id": "identity--allowed"},
        }
    )


def test_prepare_upsert_item_skips_when_respect_disabled():
    settings = StubConnectorSettingsNoRespect()
    helper = MagicMock()
    helper.connector_logger = MagicMock()
    connector = RSTThreatLibrary(config=settings, helper=helper)
    connector._read_opencti_entity = MagicMock(
        return_value={"standard_id": "malware--1", "confidence": 99}
    )

    prep = connector._prepare_upsert_item(
        ThreatObjectType.MALWARE,
        {"standard_id": "malware--1", "name": "X", "confidence": 10},
        {},
    )

    assert prep.skip is False
    connector._read_opencti_entity.assert_not_called()


def test_prepare_upsert_item_proceeds_when_entity_missing(connector):
    connector._read_opencti_entity = MagicMock(return_value=None)
    prep = connector._prepare_upsert_item(
        ThreatObjectType.MALWARE,
        {"standard_id": "malware--missing", "name": "X", "confidence": 10},
        {},
    )
    assert prep.skip is False


def test_prepare_upsert_item_skips_on_analyst_lock(connector):
    connector._read_opencti_entity = MagicMock(
        return_value={"standard_id": "malware--1", "confidence": 90}
    )
    prep = connector._prepare_upsert_item(
        ThreatObjectType.MALWARE,
        {"standard_id": "malware--1", "name": "X", "confidence": 40},
        {},
    )
    assert prep.skip is True
    assert "OpenCTI confidence" in prep.skip_reason


def test_read_opencti_entity_routes_by_type(connector):
    connector.helper.api.malware.read.return_value = {"standard_id": "malware--1"}
    connector.helper.api.tool.read.return_value = {"standard_id": "tool--1"}
    connector.helper.api.campaign.read.return_value = {"standard_id": "campaign--1"}
    connector.helper.api.intrusion_set.read.return_value = {
        "standard_id": "intrusion-set--1"
    }

    assert connector._read_opencti_entity(
        ThreatObjectType.MALWARE, "malware--1"
    ) == {"standard_id": "malware--1"}
    assert connector._read_opencti_entity(
        ThreatObjectType.TOOLS, "tool--1"
    ) == {"standard_id": "tool--1"}
    assert connector._read_opencti_entity(
        ThreatObjectType.CAMPAIGNS, "campaign--1"
    ) == {"standard_id": "campaign--1"}
    assert connector._read_opencti_entity(
        ThreatObjectType.INTRUSION_SETS, "intrusion-set--1"
    ) == {"standard_id": "intrusion-set--1"}


def test_read_opencti_entity_returns_none_on_exception(connector):
    connector.helper.api.malware.read.side_effect = RuntimeError("boom")
    assert (
        connector._read_opencti_entity(ThreatObjectType.MALWARE, "malware--1") is None
    )


def test_cycle_runs_merge_split_when_enabled(connector):
    connector.merge_split_enabled = True
    connector.object_types = [ThreatObjectType.MALWARE]
    connector._cycle_type = MagicMock()
    connector._apply_merge_split = MagicMock()

    with patch("connector.connector.ThreatLibraryClient") as client_cls:
        connector._cycle({}, timestamp=1)

    client_cls.assert_called_once()
    connector._cycle_type.assert_called_once()
    connector._apply_merge_split.assert_called_once()


def test_cycle_skips_merge_split_when_disabled(connector):
    connector.merge_split_enabled = False
    connector.object_types = [ThreatObjectType.MALWARE]
    connector._cycle_type = MagicMock()
    connector._apply_merge_split = MagicMock()

    with patch("connector.connector.ThreatLibraryClient"):
        connector._cycle({}, timestamp=1)

    connector._apply_merge_split.assert_not_called()


def test_cycle_type_fetch_exception_does_not_advance_cursor(connector):
    client = MagicMock()
    client.iter_new_items.side_effect = RuntimeError("fetch failed")
    state = {"cursor_malware": "2024-01-01T00:00:00.000Z"}

    ok = connector._cycle_type(
        client,
        ThreatObjectType.MALWARE,
        state,
        timestamp=1,
        seed="",
    )

    assert ok is False
    assert state["cursor_malware"] == "2024-01-01T00:00:00.000Z"
    connector.helper.connector_logger.error.assert_called()


def test_cycle_type_advances_cursor_when_all_items_skipped(connector):
    client = MagicMock()
    client.iter_new_items.return_value = iter(
        [
            {
                "standard_id": "malware--1",
                "name": "SkipMe",
                "modified": "2024-02-01T00:00:00.000Z",
                "confidence": 10,
            }
        ]
    )
    connector._prepare_upsert_item = MagicMock(
        return_value=UpsertPrep(
            skip=True,
            api_item={"standard_id": "malware--1"},
            skip_reason="analyst lock",
        )
    )
    connector._batch_send = MagicMock(return_value=True)
    state: dict = {}

    ok = connector._cycle_type(
        client,
        ThreatObjectType.MALWARE,
        state,
        timestamp=1,
        seed="",
    )

    assert ok is True
    assert state["cursor_malware"] == "2024-02-01T00:00:00.000Z"
    assert state["cursor_ids_malware"] == ["malware--1"]
    connector._batch_send.assert_not_called()


def test_run_schedules_process_message(connector):
    connector.run()
    connector.helper.schedule_process.assert_called_once()
    kwargs = connector.helper.schedule_process.call_args.kwargs
    assert kwargs["message_callback"] == connector.process_message

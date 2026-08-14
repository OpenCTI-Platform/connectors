from unittest.mock import MagicMock

import pytest
from connector.connector import RSTThreatLibrary
from connector.settings import ConnectorSettings


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
                },
            }
        )


class StubConnectorSettingsWithConfidenceOverride(ConnectorSettings):
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
                    "intrusion_set_default_confidence": 80,
                },
            }
        )


class StubConnectorSettingsWithConfidenceLock(ConnectorSettings):
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
                    "intrusion_set_default_confidence": 80,
                    "respect_user_edits": True,
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


def test_batch_send_stix_bundle_uses_helper_bundle_pattern(connector):
    stix_object = MagicMock()
    stix_object.serialize.return_value = '{"type":"malware","id":"malware--1"}'

    ok = connector._batch_send_stix_bundle(
        [stix_object], timestamp=1_700_000_000, obj_type="malware"
    )

    assert ok is True
    connector.helper.stix2_create_bundle.assert_called_once_with([stix_object])
    connector.helper.send_stix2_bundle.assert_called_once()
    kwargs = connector.helper.send_stix2_bundle.call_args.kwargs
    assert kwargs["cleanup_inconsistent_bundle"] is True
    assert kwargs["work_id"] == "work-1"


def test_batch_send_stix_bundle_retries_transient_failures(connector, monkeypatch):
    stix_object = MagicMock()
    connector.helper.send_stix2_bundle.side_effect = [
        ConnectionError("temporary"),
        ["bundle-sent"],
    ]
    monkeypatch.setattr("connector.connector.time.sleep", lambda _: None)

    ok = connector._batch_send_stix_bundle(
        [stix_object], timestamp=1_700_000_000, obj_type="malware"
    )

    assert ok is True
    assert connector.helper.send_stix2_bundle.call_count == 2


def test_batch_send_stix_bundle_returns_false_after_retry_budget(
    connector, monkeypatch
):
    stix_object = MagicMock()
    connector._max_retries = 2
    connector.helper.send_stix2_bundle.side_effect = ConnectionError("temporary")
    monkeypatch.setattr("connector.connector.time.sleep", lambda _: None)

    ok = connector._batch_send_stix_bundle(
        [stix_object], timestamp=1_700_000_000, obj_type="malware"
    )

    assert ok is False
    assert connector.helper.send_stix2_bundle.call_count == 2
    assert connector.helper.api.work.to_processed.call_count == 2
    for call in connector.helper.api.work.to_processed.call_args_list:
        assert call.kwargs.get("in_error") is True


def test_batch_send_stix_bundle_retries_requests_exceptions(connector, monkeypatch):
    import requests

    stix_object = MagicMock()
    connector.helper.send_stix2_bundle.side_effect = [
        requests.exceptions.Timeout("upstream timeout"),
        ["bundle-sent"],
    ]
    monkeypatch.setattr("connector.connector.time.sleep", lambda _: None)

    ok = connector._batch_send_stix_bundle(
        [stix_object], timestamp=1_700_000_000, obj_type="malware"
    )

    assert ok is True
    assert connector.helper.send_stix2_bundle.call_count == 2
    assert connector.helper.api.work.to_processed.call_count == 2
    first = connector.helper.api.work.to_processed.call_args_list[0]
    second = connector.helper.api.work.to_processed.call_args_list[1]
    assert first.kwargs.get("in_error") is True
    assert second.kwargs.get("in_error") is not True


def test_batch_send_stix_bundle_reraises_non_retryable_after_marking_work(connector):
    stix_object = MagicMock()
    connector.helper.send_stix2_bundle.side_effect = ValueError("bad payload")

    with pytest.raises(ValueError, match="bad payload"):
        connector._batch_send_stix_bundle(
            [stix_object], timestamp=1_700_000_000, obj_type="malware"
        )

    connector.helper.api.work.to_processed.assert_called_once()
    kwargs = connector.helper.api.work.to_processed.call_args.kwargs
    assert kwargs.get("in_error") is True


def test_batch_send_stix_bundle_performs_one_attempt_when_max_retries_zero(connector):
    connector._max_retries = 0
    stix_object = MagicMock()

    ok = connector._batch_send_stix_bundle(
        [stix_object], timestamp=1_700_000_000, obj_type="malware"
    )

    assert ok is True
    assert connector.helper.send_stix2_bundle.call_count == 1


def test_batch_send_via_api_imports_objects_and_marks_work_processed(connector):
    identity = MagicMock()
    identity.serialize.return_value = (
        '{"type":"identity","id":"identity--1","name":"Author"}'
    )
    malware = MagicMock()
    malware.serialize.return_value = '{"type":"malware","id":"malware--1","name":"x"}'

    ok = connector._batch_send_via_api(
        [malware, identity], timestamp=1_700_000_000, obj_type="malware"
    )

    assert ok is True
    assert connector.helper.api.stix2.import_object.call_count == 2
    first_payload = connector.helper.api.stix2.import_object.call_args_list[0].args[0]
    assert first_payload["type"] == "identity"
    connector.helper.api.work.to_processed.assert_called_once()
    assert (
        connector.helper.api.work.to_processed.call_args.kwargs.get("in_error")
        is not True
    )


def test_batch_send_via_api_retries_requests_exceptions(connector, monkeypatch):
    import requests

    stix_object = MagicMock()
    stix_object.serialize.return_value = '{"type":"malware","id":"malware--1"}'
    connector.helper.api.stix2.import_object.side_effect = [
        requests.exceptions.ConnectionError("temporary"),
        None,
    ]
    monkeypatch.setattr("connector.connector.time.sleep", lambda _: None)

    ok = connector._batch_send_via_api(
        [stix_object], timestamp=1_700_000_000, obj_type="malware"
    )

    assert ok is True
    assert connector.helper.api.stix2.import_object.call_count == 2
    assert connector.helper.api.work.to_processed.call_count == 2
    first = connector.helper.api.work.to_processed.call_args_list[0]
    second = connector.helper.api.work.to_processed.call_args_list[1]
    assert first.kwargs.get("in_error") is True
    assert second.kwargs.get("in_error") is not True


def test_batch_send_via_api_returns_false_after_retry_budget(connector, monkeypatch):
    stix_object = MagicMock()
    stix_object.serialize.return_value = '{"type":"malware","id":"malware--1"}'
    connector._max_retries = 2
    connector.helper.api.stix2.import_object.side_effect = ConnectionError("temporary")
    monkeypatch.setattr("connector.connector.time.sleep", lambda _: None)

    ok = connector._batch_send_via_api(
        [stix_object], timestamp=1_700_000_000, obj_type="malware"
    )

    assert ok is False
    assert connector.helper.api.stix2.import_object.call_count == 2
    for call in connector.helper.api.work.to_processed.call_args_list:
        assert call.kwargs.get("in_error") is True


def test_batch_send_via_api_reraises_non_retryable_after_marking_work(connector):
    stix_object = MagicMock()
    stix_object.serialize.return_value = '{"type":"malware","id":"malware--1"}'
    connector.helper.api.stix2.import_object.side_effect = ValueError("bad payload")

    with pytest.raises(ValueError, match="bad payload"):
        connector._batch_send_via_api(
            [stix_object], timestamp=1_700_000_000, obj_type="malware"
        )

    connector.helper.api.work.to_processed.assert_called_once()
    assert (
        connector.helper.api.work.to_processed.call_args.kwargs.get("in_error") is True
    )


def test_seed_cursor_warns_and_ignores_invalid_import_from_date(connector):
    connector.import_from_date = "not-a-date"

    assert connector._seed_cursor() == ""
    connector.helper.connector_logger.warning.assert_called()
    warning = connector.helper.connector_logger.warning.call_args.args[0]
    assert "Invalid import_from_date" in warning
    assert "not-a-date" in warning


def test_seed_cursor_formats_valid_import_from_date(connector):
    connector.import_from_date = "2024-01-01"

    assert connector._seed_cursor() == "2024-01-01T00:00:00.000Z"


def test_normalize_api_item_overrides_intrusion_set_confidence():
    settings = StubConnectorSettingsWithConfidenceOverride()
    helper = MagicMock()
    helper.connector_logger = MagicMock()
    connector = RSTThreatLibrary(config=settings, helper=helper)

    item = {"standard_id": "intrusion-set--1", "name": "APT", "confidence": 96}
    normalized = connector._normalize_api_item("intrusion-sets", item)

    assert normalized["confidence"] == 80
    assert item["confidence"] == 96


def test_normalize_api_item_leaves_other_types_unchanged():
    settings = StubConnectorSettingsWithConfidenceOverride()
    helper = MagicMock()
    helper.connector_logger = MagicMock()
    connector = RSTThreatLibrary(config=settings, helper=helper)

    item = {"standard_id": "malware--1", "name": "Evil", "confidence": 96}
    normalized = connector._normalize_api_item("malware", item)

    assert normalized is item
    assert normalized["confidence"] == 96


def test_prepare_upsert_item_respects_confidence_override_for_analyst_lock():
    settings = StubConnectorSettingsWithConfidenceLock()
    helper = MagicMock()
    helper.connector_logger = MagicMock()
    connector = RSTThreatLibrary(config=settings, helper=helper)
    connector._read_opencti_entity = MagicMock(
        return_value={
            "standard_id": "intrusion-set--1",
            "confidence": 85,
        }
    )

    prep = connector._prepare_upsert_item(
        "intrusion-sets",
        {"standard_id": "intrusion-set--1", "name": "APT", "confidence": 96},
        {},
    )

    assert prep.skip is True
    assert prep.api_item["confidence"] == 80


def test_analyst_lock_prefers_intrusion_set_default_confidence_over_stored_state():
    settings = StubConnectorSettingsWithConfidenceLock()
    helper = MagicMock()
    helper.connector_logger = MagicMock()
    connector = RSTThreatLibrary(config=settings, helper=helper)
    state = {
        "fingerprints": {
            "intrusion-sets": {
                "intrusion-set--1": {"upstream_confidence": 96},
            }
        }
    }

    locked = connector._analyst_locks_entity(
        {"standard_id": "intrusion-set--1", "confidence": 85},
        obj_type_path="intrusion-sets",
        state=state,
    )

    assert locked is True


def test_split_abandons_after_consecutive_analyst_lock_failures():
    from connector.connector import _SPLIT_FAILURE_SKIP_THRESHOLD
    from connector.merge_split import SplitCandidate

    settings = StubConnectorSettingsWithConfidenceLock()
    helper = MagicMock()
    helper.connector_logger = MagicMock()
    connector = RSTThreatLibrary(config=settings, helper=helper)
    connector._analyst_locks_entity = MagicMock(return_value=True)

    oc = {
        "id": "uuid-earth-lusca",
        "standard_id": "intrusion-set--8f8886ee-5773-597c-b532-f57efafbaa02",
        "name": "Earth Lusca",
        "aliases": ["RedHotel"],
        "confidence": 90,
    }
    split = SplitCandidate(
        opencti_entity=oc,
        keep_api_item={"standard_id": oc["standard_id"], "name": "Earth Lusca"},
        aliases_to_remove=["RedHotel"],
        split_off_api_items=[],
    )
    state: dict = {}

    for _ in range(_SPLIT_FAILURE_SKIP_THRESHOLD):
        connector._execute_intrusion_set_split(
            split, timestamp=1, obj_type="intrusion-sets", state=state
        )

    entry = state["split_failures"]["intrusion-sets"][oc["standard_id"]]
    assert entry["skipped"] is True
    assert entry["count"] == _SPLIT_FAILURE_SKIP_THRESHOLD

    helper.connector_logger.info.reset_mock()
    connector._execute_intrusion_set_split(
        split, timestamp=1, obj_type="intrusion-sets", state=state
    )
    info_msgs = " ".join(
        str(c.args[0]) for c in helper.connector_logger.info.call_args_list if c.args
    )
    assert "analyst lock" not in info_msgs
    assert connector._analyst_locks_entity.call_count == _SPLIT_FAILURE_SKIP_THRESHOLD


def test_split_records_failure_when_opencti_push_fails():
    from connector.connector import UpsertPrep, _SPLIT_FAILURE_SKIP_THRESHOLD
    from connector.merge_split import SplitCandidate

    settings = StubConnectorSettings()
    helper = MagicMock()
    helper.connector_logger = MagicMock()
    connector = RSTThreatLibrary(config=settings, helper=helper)
    connector._analyst_locks_entity = MagicMock(return_value=False)
    connector._batch_send = MagicMock(return_value=False)
    connector._prepare_upsert_item = MagicMock(
        side_effect=lambda _t, item, _s: UpsertPrep(skip=False, api_item=item)
    )
    connector._upsert_sdo_from_prep = MagicMock(return_value=MagicMock())

    oc = {
        "id": "uuid-earth-lusca",
        "standard_id": "intrusion-set--keep",
        "name": "Earth Lusca",
        "aliases": ["RedHotel"],
        "confidence": 50,
    }
    split = SplitCandidate(
        opencti_entity=oc,
        keep_api_item={"standard_id": oc["standard_id"], "name": "Earth Lusca"},
        aliases_to_remove=["RedHotel"],
        split_off_api_items=[
            {"standard_id": "intrusion-set--split-off", "name": "RedHotel"}
        ],
    )
    state: dict = {}

    for _ in range(_SPLIT_FAILURE_SKIP_THRESHOLD):
        connector._execute_intrusion_set_split(
            split, timestamp=1, obj_type="intrusion-sets", state=state
        )

    entry = state["split_failures"]["intrusion-sets"][oc["standard_id"]]
    assert entry["skipped"] is True
    assert entry["count"] == _SPLIT_FAILURE_SKIP_THRESHOLD
    assert connector._batch_send.call_count == _SPLIT_FAILURE_SKIP_THRESHOLD

    connector._execute_intrusion_set_split(
        split, timestamp=1, obj_type="intrusion-sets", state=state
    )
    assert connector._batch_send.call_count == _SPLIT_FAILURE_SKIP_THRESHOLD


def test_wait_for_opencti_entity_retries_until_readable(monkeypatch):
    settings = StubConnectorSettings()
    helper = MagicMock()
    helper.connector_logger = MagicMock()
    connector = RSTThreatLibrary(config=settings, helper=helper)

    sid = "intrusion-set--36319194-19e1-50ac-9163-778b56a1bf12"
    entity = {"id": "uuid-apt29", "standard_id": sid, "name": "APT29"}
    reads = [None, None, entity]
    connector._read_opencti_entity = MagicMock(side_effect=reads)
    monkeypatch.setattr("connector.connector.time.sleep", lambda _: None)

    found = connector._wait_for_opencti_entity(
        "intrusion-sets",
        sid,
        attempts=4,
        delay_s=0.01,
        context="merge",
    )

    assert found == entity
    assert connector._read_opencti_entity.call_count == 3
    info_msgs = [
        str(c.args[0]) for c in helper.connector_logger.info.call_args_list if c.args
    ]
    assert any("attempt 2/4" in msg for msg in info_msgs)
    assert any("attempt 3/4" in msg for msg in info_msgs)
    assert not any("attempt 1/3" in msg or "/3," in msg for msg in info_msgs)


def test_wait_for_opencti_entity_returns_none_after_retries(monkeypatch):
    settings = StubConnectorSettings()
    helper = MagicMock()
    helper.connector_logger = MagicMock()
    connector = RSTThreatLibrary(config=settings, helper=helper)
    connector._read_opencti_entity = MagicMock(return_value=None)
    monkeypatch.setattr("connector.connector.time.sleep", lambda _: None)

    found = connector._wait_for_opencti_entity(
        "intrusion-sets",
        "intrusion-set--missing",
        attempts=3,
        delay_s=0.01,
    )

    assert found is None
    assert connector._read_opencti_entity.call_count == 3
    info_msgs = [
        str(c.args[0])
        for c in helper.connector_logger.info.call_args_list
        if c.args
    ]
    assert any("attempt 2/3" in msg for msg in info_msgs)
    assert any("attempt 3/3" in msg for msg in info_msgs)


def test_batch_send_splits_oversized_lists_into_chunks(connector):
    connector._opencti_batch_size = 2
    objects = []
    for i in range(5):
        obj = MagicMock()
        obj.serialize.return_value = (
            f'{{"type":"malware","id":"malware--{i}","name":"m{i}"}}'
        )
        objects.append(obj)

    ok = connector._batch_send(objects, timestamp=1_700_000_000, obj_type="malware")

    assert ok is True
    assert connector.helper.send_stix2_bundle.call_count == 3
    assert connector.helper.api.work.initiate_work.call_count == 3


def test_batch_send_puts_identities_in_first_chunk_only(connector):
    connector._opencti_batch_size = 2
    identity = MagicMock()
    identity.serialize.return_value = (
        '{"type":"identity","id":"identity--1","name":"Author"}'
    )
    objects = [identity]
    for i in range(3):
        obj = MagicMock()
        obj.serialize.return_value = (
            f'{{"type":"malware","id":"malware--{i}","name":"m{i}"}}'
        )
        objects.append(obj)

    ok = connector._batch_send(objects, timestamp=1_700_000_000, obj_type="malware")

    assert ok is True
    assert connector.helper.stix2_create_bundle.call_count == 2
    first_chunk = connector.helper.stix2_create_bundle.call_args_list[0].args[0]
    second_chunk = connector.helper.stix2_create_bundle.call_args_list[1].args[0]
    assert first_chunk[0] is identity
    assert len(first_chunk) == 2
    assert identity not in second_chunk
    assert len(second_chunk) == 2
    assert all(
        len(call.args[0]) <= connector._opencti_batch_size
        for call in connector.helper.stix2_create_bundle.call_args_list
    )


def test_batch_send_chunks_identities_that_exceed_batch_size(connector):
    connector._opencti_batch_size = 2
    identities = []
    for i in range(3):
        identity = MagicMock()
        identity.serialize.return_value = (
            f'{{"type":"identity","id":"identity--{i}","name":"Author {i}"}}'
        )
        identities.append(identity)
    malware = MagicMock()
    malware.serialize.return_value = (
        '{"type":"malware","id":"malware--1","name":"m1"}'
    )
    objects = identities + [malware]

    ok = connector._batch_send(objects, timestamp=1_700_000_000, obj_type="malware")

    assert ok is True
    chunks = [
        call.args[0] for call in connector.helper.stix2_create_bundle.call_args_list
    ]
    assert len(chunks) == 2
    assert chunks[0] == identities[:2]
    assert chunks[1][0] is identities[2]
    assert chunks[1][1] is malware
    assert all(len(chunk) <= 2 for chunk in chunks)


def test_cycle_type_flushes_in_batches_and_advances_cursor(connector):
    connector._opencti_batch_size = 2
    connector._batch_send = MagicMock(return_value=True)
    connector.converter.build_identity = MagicMock(return_value=None)

    items = []
    for i in range(5):
        items.append(
            {
                "standard_id": f"malware--{i}",
                "name": f"m{i}",
                "modified": f"2024-01-0{i + 1}T00:00:00.000Z",
                "createdBy": {},
            }
        )

    client = MagicMock()
    client.iter_new_items.return_value = iter(items)
    connector._prepare_upsert_item = MagicMock(
        side_effect=lambda _t, item, _s: MagicMock(
            skip=False, api_item=item, skip_reason=None
        )
    )
    connector._upsert_sdo_from_prep = MagicMock(
        side_effect=lambda _t, prep: MagicMock(name=prep.api_item["name"])
    )

    state: dict = {}
    connector._cycle_type(client, "malware", state, timestamp=1, seed="")

    assert connector._batch_send.call_count == 3  # 2+2+1
    assert state["cursor_malware"] == "2024-01-05T00:00:00.000Z"
    assert set(state["managed_ids"]["malware"]) == {
        "malware--0",
        "malware--1",
        "malware--2",
        "malware--3",
        "malware--4",
    }


def test_cycle_type_does_not_advance_cursor_when_flush_fails(connector):
    connector._opencti_batch_size = 2
    connector._batch_send = MagicMock(side_effect=[True, False])
    connector.converter.build_identity = MagicMock(return_value=None)

    items = [
        {
            "standard_id": f"malware--{i}",
            "name": f"m{i}",
            "modified": f"2024-01-0{i + 1}T00:00:00.000Z",
            "createdBy": {},
        }
        for i in range(4)
    ]
    client = MagicMock()
    client.iter_new_items.return_value = iter(items)
    connector._prepare_upsert_item = MagicMock(
        side_effect=lambda _t, item, _s: MagicMock(
            skip=False, api_item=item, skip_reason=None
        )
    )
    connector._upsert_sdo_from_prep = MagicMock(
        side_effect=lambda _t, prep: MagicMock(name=prep.api_item["name"])
    )

    state: dict = {"cursor_malware": "2023-01-01T00:00:00.000Z"}
    connector._cycle_type(client, "malware", state, timestamp=1, seed="")

    assert connector._batch_send.call_count == 2
    assert state["cursor_malware"] == "2023-01-01T00:00:00.000Z"
    # First chunk's managed ids are still recorded (idempotent retry next cycle).
    assert set(state["managed_ids"]["malware"]) == {"malware--0", "malware--1"}


def test_process_message_marks_last_run_only_after_successful_cycle(
    connector, monkeypatch
):
    mark_last_run_calls: list[bool] = []

    def fake_publish(*, mark_last_run: bool) -> None:
        mark_last_run_calls.append(mark_last_run)

    monkeypatch.setattr(connector, "_publish_connector_info", fake_publish)
    monkeypatch.setattr(connector, "_cycle", MagicMock())
    connector.helper.get_state.return_value = {}
    connector.helper.connect_run_and_terminate = False

    connector.process_message()

    assert mark_last_run_calls == [False, True]
    connector._cycle.assert_called_once()


def test_process_message_does_not_mark_last_run_when_cycle_fails(
    connector, monkeypatch
):
    mark_last_run_calls: list[bool] = []

    def fake_publish(*, mark_last_run: bool) -> None:
        mark_last_run_calls.append(mark_last_run)

    monkeypatch.setattr(connector, "_publish_connector_info", fake_publish)
    monkeypatch.setattr(
        connector, "_cycle", MagicMock(side_effect=RuntimeError("cycle failed"))
    )
    connector.helper.get_state.return_value = {}
    connector.helper.connect_run_and_terminate = False

    with pytest.raises(RuntimeError, match="cycle failed"):
        connector.process_message()

    assert mark_last_run_calls == [False]

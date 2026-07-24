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


def test_analyst_lock_uses_confidence_override_from_stored_state():
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

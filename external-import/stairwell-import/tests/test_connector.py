"""The processor under the SDK's real run loop (ExternalImportConnector.callback).

Only the OpenCTI helper and the Stairwell API are mocked, so these prove the
lifecycle the processor relies on: a bundle is sent within a work and state is
saved only after a successful run.
"""

import json
from unittest.mock import MagicMock

import pytest
from connector import ConnectorSettings, ConnectorState
from connector.data_processors import MalEvalFilesProcessor
from connectors_sdk import ExternalImportConnector


@pytest.fixture
def env(monkeypatch):
    for key, value in {
        "OPENCTI_URL": "http://opencti:8080",
        "OPENCTI_TOKEN": "token",
        "CONNECTOR_ID": "22222222-2222-4222-8222-222222222222",
        "CONNECTOR_SCOPE": "stairwell",
        "STAIRWELL_API_TOKEN": "sw-token",
    }.items():
        monkeypatch.setenv(key, value)


def _connector(pages, saved_state=None):
    helper = MagicMock()
    helper.get_state.return_value = saved_state
    helper.api.work.initiate_work.return_value = "work-1"
    helper.stix2_create_bundle.side_effect = lambda objects: json.dumps(
        {"type": "bundle", "objects": objects}
    )
    processor = MalEvalFilesProcessor()
    state = ConnectorState()
    connector = ExternalImportConnector(
        settings=ConnectorSettings(), state=state, data_processors=[processor]
    )
    # What ExternalImportConnector._init_dependencies does, with our helper.
    connector._helper = helper
    connector.logger = MagicMock()
    state.inject_dependencies(helper)
    processor.inject_dependencies(
        settings=connector.settings, helper=helper, state=state
    )
    processor.post_init()
    processor.client.list_objects_metadata = MagicMock(side_effect=list(pages))
    return connector, helper


def _obj(sha):
    return {"sha256": sha, "malEval": {"probabilityBucket": "PROBABILITY_HIGH"}}


def test_successful_run_sends_in_a_work_and_saves_the_watermark(env):
    connector, helper = _connector(
        [(200, {"objectMetadatas": [_obj("a" * 64)], "nextPageToken": ""})]
    )
    connector.callback()
    helper.send_stix2_bundle.assert_called_once()
    assert helper.send_stix2_bundle.call_args.kwargs["work_id"] == "work-1"
    helper.set_state.assert_called_once()
    saved = helper.set_state.call_args.args[0]
    saved = json.loads(saved) if isinstance(saved, str) else saved
    assert saved["watermark"] is not None
    assert saved["pending_page_token"] is None


def test_failed_run_saves_no_state(env):
    connector, helper = _connector(
        [
            (200, {"objectMetadatas": [_obj("a" * 64)], "nextPageToken": "p2"}),
            (503, None),
        ],
        saved_state={"watermark": "2026-05-04T00:00:00Z"},
    )
    connector.callback()
    helper.send_stix2_bundle.assert_not_called()
    helper.set_state.assert_not_called()

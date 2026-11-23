import copy
from unittest.mock import MagicMock

import pytest
from crowdstrike_feeds_connector.actor.importer import ActorImporter
from crowdstrike_feeds_connector.connector import CrowdStrike
from crowdstrike_feeds_connector.malware.importer import MalwareImporter
from crowdstrike_feeds_connector.report.importer import ReportImporter
from crowdstrike_feeds_connector.vulnerability.importer import VulnerabilityImporter
from crowdstrike_feeds_services.client.actors import ActorsAPI
from crowdstrike_feeds_services.client.base_api import BaseCrowdstrikeClient
from crowdstrike_feeds_services.client.malware import MalwareAPI
from crowdstrike_feeds_services.client.reports import ReportsAPI
from crowdstrike_feeds_services.client.vulnerabilities import VulnerabilitiesAPI
from crowdstrike_feeds_services.utils import CrowdStrikeAPIError


def _client() -> BaseCrowdstrikeClient:
    # Bypass the falconpy ctor, which would try to authenticate.
    client = BaseCrowdstrikeClient.__new__(BaseCrowdstrikeClient)
    client.helper = MagicMock()
    return client


UNAUTHORIZED = {
    "status_code": 401,
    "body": {
        "errors": [{"code": 401, "message": "Unauthorized"}],
        "meta": {"trace_id": "test-trace-id"},
    },
}


def test_handle_api_error_raises_when_asked():
    with pytest.raises(CrowdStrikeAPIError, match=r"^Unauthorized \(401\)$"):
        _client().handle_api_error(dict(UNAUTHORIZED), raise_on_error=True)


def test_handle_api_error_only_logs_by_default():
    client = _client()

    client.handle_api_error(dict(UNAUTHORIZED))

    client.helper.connector_logger.error.assert_called_once()


def test_process_message_marks_api_error_as_failed_work_and_runs_next_importer():
    connector = CrowdStrike.__new__(CrowdStrike)

    connector.helper = MagicMock()
    connector.helper.connect_name = "CrowdStrike"

    connector._current_unix_timestamp = MagicMock(return_value=1234567890)
    connector._load_state = MagicMock(return_value={})
    connector._initiate_work = MagicMock(side_effect=["work-1", "work-2"])

    failing = MagicMock()
    failing.name = "Actor"

    def start(work_id, state):
        # what a paginated query does on a 401
        _client().handle_api_error(dict(UNAUTHORIZED), raise_on_error=True)

    failing.start.side_effect = start

    working = MagicMock()
    working.name = "Malware"
    working.start.return_value = {"malware_latest": 1}

    connector.importers = [failing, working]

    connector.process_message()

    to_processed = connector.helper.api.work.to_processed
    assert to_processed.call_count == 2
    to_processed.assert_any_call("work-1", "Unauthorized (401)", in_error=True)
    assert to_processed.call_args_list[1].args[0] == "work-2"
    assert "in_error" not in to_processed.call_args_list[1].kwargs

    # only the importer that ran stored its state
    stored_states = [c.args[0] for c in connector.helper.set_state.call_args_list]
    assert all("malware_latest" in state for state in stored_states)
    assert stored_states


class _UnauthorizedIntel:
    """Stands in for falconpy ``Intel``: every call returns a 401 envelope."""

    def __getattr__(self, name):
        return lambda *args, **kwargs: copy.deepcopy(UNAUTHORIZED)


@pytest.mark.parametrize(
    "importer_cls, api_attr, api_cls",
    [
        (ActorImporter, "actors_api_cs", ActorsAPI),
        (MalwareImporter, "malware_api_cs", MalwareAPI),
        (ReportImporter, "reports_api_cs", ReportsAPI),
        (VulnerabilityImporter, "vulnerabilities_api_cs", VulnerabilitiesAPI),
    ],
)
def test_paginated_importers_raise_api_error(importer_cls, api_attr, api_cls):
    api = api_cls.__new__(api_cls)
    api.helper = MagicMock()
    api.cs_intel = _UnauthorizedIntel()

    importer = importer_cls.__new__(importer_cls)
    importer.helper = MagicMock()
    importer.default_latest_timestamp = 0
    importer.include_types = None
    importer.target_industries = None
    setattr(importer, api_attr, api)

    with pytest.raises(CrowdStrikeAPIError, match=r"^Unauthorized \(401\)$"):
        importer.start("work-1", {})

    importer.helper.set_state.assert_not_called()

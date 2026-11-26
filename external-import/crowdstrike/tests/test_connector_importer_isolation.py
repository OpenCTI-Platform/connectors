from unittest.mock import MagicMock

from crowdstrike_feeds_connector.connector import CrowdStrike


def _connector(*importers: MagicMock) -> CrowdStrike:
    connector = CrowdStrike.__new__(CrowdStrike)
    connector.helper = MagicMock()
    connector.helper.connect_name = "CrowdStrike"
    connector._current_unix_timestamp = MagicMock(return_value=1234567890)
    connector._load_state = MagicMock(return_value={})
    connector.importers = list(importers)
    return connector


def _importer(name: str, **start_kwargs) -> MagicMock:
    importer = MagicMock()
    importer.name = name
    importer.start.configure_mock(**start_kwargs)
    return importer


def _stored_states(connector: CrowdStrike) -> list[dict]:
    return [c.args[0] for c in connector.helper.set_state.call_args_list]


def test_unexpected_importer_error_marks_work_failed_and_runs_next_importer():
    failing = _importer("Actor", side_effect=KeyError("name"))
    working = _importer("Malware", return_value={"malware_latest": 1})
    connector = _connector(failing, working)
    connector._initiate_work = MagicMock(side_effect=["work-1", "work-2"])

    connector.process_message()

    working.start.assert_called_once()
    to_processed = connector.helper.api.work.to_processed
    to_processed.assert_any_call("work-1", "'name'", in_error=True)
    assert to_processed.call_args_list[-1].args[0] == "work-2"
    assert "in_error" not in to_processed.call_args_list[-1].kwargs
    connector.helper.connector_logger.error.assert_called_once_with(
        "Importer failed, running the next one",
        {"importer": "Actor", "error": "'name'"},
    )
    assert all("malware_latest" in state for state in _stored_states(connector))
    assert "last_run" in _stored_states(connector)[-1]


def test_work_initiation_error_runs_next_importer():
    failing = _importer("Actor")
    working = _importer("Malware", return_value={"malware_latest": 1})
    connector = _connector(failing, working)
    connector._initiate_work = MagicMock(
        side_effect=[ConnectionError("platform unreachable"), "work-2"]
    )

    connector.process_message()

    failing.start.assert_not_called()
    working.start.assert_called_once()
    assert working.start.call_args.args[0] == "work-2"
    connector.helper.connector_logger.error.assert_called_once_with(
        "Importer failed, running the next one",
        {"importer": "Actor", "error": "platform unreachable"},
    )
    assert "last_run" in _stored_states(connector)[-1]


def test_failed_work_report_error_runs_next_importer():
    failing = _importer("Actor", side_effect=ConnectionError("queue unreachable"))
    working = _importer("Malware", return_value={"malware_latest": 1})
    connector = _connector(failing, working)
    connector._initiate_work = MagicMock(side_effect=["work-1", "work-2"])
    connector.helper.api.work.to_processed.side_effect = [
        ConnectionError("platform unreachable"),
        None,
    ]

    connector.process_message()

    working.start.assert_called_once()
    connector.helper.api.work.to_processed.assert_called_with(
        "work-2",
        "CrowdStrike Malware successfully run, storing last_run as 1234567890",
    )
    assert "last_run" in _stored_states(connector)[-1]

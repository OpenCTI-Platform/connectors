from unittest.mock import MagicMock, patch

import pytest
from connector.connector import AssetnoteImportConnector


def build_connector():
    config = MagicMock()
    config.assetnote_import.unresolved_status_name = None
    config.assetnote_import.triaged_status_name = None
    config.assetnote_import.resolved_status_name = None
    config.assetnote_import.ignored_status_name = None
    helper = MagicMock()
    with patch("connector.connector.AssetnoteImportClient"):
        with patch("connector.connector.ConverterToStix"):
            connector = AssetnoteImportConnector(config=config, helper=helper)
    return connector, helper


def test_resolve_status_mapping_maps_configured_name_to_id():
    """
    A configured status name should be resolved against the real Case-Incident
    workflow statuses and mapped to its status id.
    """
    connector, helper = build_connector()

    # add Unresolved as the name for a configured status template
    connector.config.assetnote_import.unresolved_status_name = "Unresolved"
    # Fake response from OpenCTI giving the statuses that exist for Incident Responses
    helper.api.query.return_value = {
        "data": {
            "subType": {
                "statuses": [{"id": "status-1", "template": {"name": "Unresolved"}}]
            }
        }
    }
    status_mapping = connector._resolve_status_mapping()
    # the status with id code status-1 is mapped to unresolved
    assert status_mapping == {"UNRESOLVED": "status-1"}


def test_resolve_status_mapping_raises_when_name_not_in_workflow():
    """
    Status Templates that exist but aren't yet assigned to the Incident Response
    object in the OpenCTI platform should raise an Exception so that we can warn
    users to configure the tempaltes correctly.
    """
    connector, helper = build_connector()
    connector.config.assetnote_import.unresolved_status_name = "Unresolved"
    helper.api.query.return_value = {"data": {"subType": {"statuses": []}}}
    with pytest.raises(ValueError, match="Unresolved"):
        connector._resolve_status_mapping()


def test_process_message_first_run_updates_state_on_success():
    """
    Where the connector completes a full cycle for the first time last_run
    should be set to the current time.
    """
    connector, helper = build_connector()
    helper.get_state.return_value = None
    connector._process_pages = MagicMock(return_value=(0, True))
    connector.process_message()
    helper.set_state.assert_called_once()
    assert "last_run" in helper.set_state.call_args.args[0]


def test_process_message_does_not_update_state_on_failure():
    """
    If either assets or exposures failed to fully retrieve, last_run must not
    be saved
    """
    connector, helper = build_connector()
    helper.get_state.return_value = None
    connector._process_pages = MagicMock(side_effect=[(0, True), (0, False)])
    connector.process_message()
    helper.set_state.assert_not_called()

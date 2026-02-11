from copy import deepcopy
from datetime import date, datetime, timezone
from typing import Any
from unittest.mock import patch

from api_client.models import EventRestSearchListItem
from connector import ConnectorSettings, Misp
from pycti import OpenCTIConnectorHelper

minimal_config_dict = {
    "opencti": {
        "url": "http://localhost:8080",
        "token": "test-token",
    },
    "connector": {},
    "misp": {
        "url": "http://test.com",
        "key": "test-api-key",
    },
}


def fake_misp_connector(config_dict: dict) -> Misp:
    class StubConnectorSettings(ConnectorSettings):
        """
        Subclass of `ConnectorSettings` (implementation of `BaseConnectorSettings`) for testing purpose.
        It overrides `BaseConnectorSettings._load_config_dict` to return a fake but valid config dict.
        """

        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(config_dict)

    settings = StubConnectorSettings()
    helper = OpenCTIConnectorHelper(config=settings.to_helper_config())

    return Misp(config=settings, helper=helper)


def test_get_event_datetime_with_timestamp(mock_opencti_connector_helper, mock_py_misp):
    """
    Test that _get_event_datetime correctly parses a UNIX timestamp when datetime_attribute is 'timestamp'.

    :param mock_opencti_connector_helper: `OpenCTIConnectorHelper` is mocked during this test to avoid any external calls to OpenCTI API
    :param mock_py_misp: `PyMISP` is mocked during this test to avoid any external calls to MISP API
    """
    config_dict = deepcopy(minimal_config_dict)
    config_dict["misp"]["datetime_attribute"] = "timestamp"

    connector = fake_misp_connector(config_dict)

    event = EventRestSearchListItem.model_validate(
        {
            "Event": {
                "timestamp": str(
                    int(datetime(2026, 1, 30, tzinfo=timezone.utc).timestamp())
                )
            }
        }
    )
    event_datetime = connector._get_event_datetime(event)
    assert (
        event_datetime.year == 2026
        and event_datetime.month == 1
        and event_datetime.day == 30
        and event_datetime.tzinfo == timezone.utc
    )


def test_get_event_datetime_with_publish_timestamp(
    mock_opencti_connector_helper, mock_py_misp
):
    """
    Test that _get_event_datetime correctly parses a UNIX timestamp when datetime_attribute is 'publish_timestamp'.

    :param mock_opencti_connector_helper: `OpenCTIConnectorHelper` is mocked during this test to avoid any external calls to OpenCTI API
    :param mock_py_misp: `PyMISP` is mocked during this test to avoid any external calls to MISP API
    """
    config_dict = deepcopy(minimal_config_dict)
    config_dict["misp"]["datetime_attribute"] = "publish_timestamp"

    connector = fake_misp_connector(config_dict)

    event = EventRestSearchListItem.model_validate(
        {
            "Event": {
                "publish_timestamp": str(
                    int(datetime(2026, 1, 30, tzinfo=timezone.utc).timestamp())
                )
            }
        }
    )
    event_datetime = connector._get_event_datetime(event)
    assert (
        event_datetime.year == 2026
        and event_datetime.month == 1
        and event_datetime.day == 30
        and event_datetime.tzinfo == timezone.utc
    )


def test_get_event_datetime_with_sighting_timestamp(
    mock_opencti_connector_helper, mock_py_misp
):
    """
    Test that _get_event_datetime correctly parses a UNIX timestamp when datetime_attribute is 'sighting_timestamp'.

    :param mock_opencti_connector_helper: `OpenCTIConnectorHelper` is mocked during this test to avoid any external calls to OpenCTI API
    :param mock_py_misp: `PyMISP` is mocked during this test to avoid any external calls to MISP API
    """
    config_dict = deepcopy(minimal_config_dict)
    config_dict["misp"]["datetime_attribute"] = "sighting_timestamp"

    connector = fake_misp_connector(config_dict)

    event = EventRestSearchListItem.model_validate(
        {
            "Event": {
                "sighting_timestamp": str(
                    int(datetime(2026, 1, 30, tzinfo=timezone.utc).timestamp())
                )
            }
        }
    )
    event_datetime = connector._get_event_datetime(event)
    assert (
        event_datetime.year == 2026
        and event_datetime.month == 1
        and event_datetime.day == 30
        and event_datetime.tzinfo == timezone.utc
    )


def test_get_event_datetime_with_date(mock_opencti_connector_helper, mock_py_misp):
    """
    Test that _get_event_datetime correctly parses an ISO date string when datetime_attribute is 'date'.

    :param mock_opencti_connector_helper: `OpenCTIConnectorHelper` is mocked during this test to avoid any external calls to OpenCTI API
    :param mock_py_misp: `PyMISP` is mocked during this test to avoid any external calls to MISP API
    """
    config_dict = deepcopy(minimal_config_dict)
    config_dict["misp"]["datetime_attribute"] = "date"

    connector = fake_misp_connector(config_dict)

    event = EventRestSearchListItem.model_validate(
        {"Event": {"date": date(2026, 1, 30).isoformat()}}
    )
    event_datetime = connector._get_event_datetime(event)
    assert (
        event_datetime.year == 2026
        and event_datetime.month == 1
        and event_datetime.day == 30
    )


def test_get_event_datetime_with_invalid_attribute(
    mock_opencti_connector_helper, mock_py_misp
):
    """
    Test that _get_event_datetime raises ValueError when datetime_attribute is not supported.

    :param mock_opencti_connector_helper: `OpenCTIConnectorHelper` is mocked during this test to avoid any external calls to OpenCTI API
    :param mock_py_misp: `PyMISP` is mocked during this test to avoid any external calls to MISP API
    """
    config_dict = deepcopy(minimal_config_dict)

    connector = fake_misp_connector(config_dict)

    with patch.object(connector, "config") as mock_invalid_config:
        mock_invalid_config.misp.datetime_attribute = "invalid"

        event = EventRestSearchListItem.model_validate({"Event": {"invalid": "foo"}})
        try:
            connector._get_event_datetime(event)
        except ValueError as error:
            assert "MISP_DATETIME_ATTRIBUTE" in str(error) or "must be either" in str(
                error
            )
        else:
            assert False, "Expected ValueError for invalid datetime_attribute"


def test_connector_validate_event_with_owner_org_in_import_owner_orgs_list(
    mock_opencti_connector_helper, mock_py_misp
):
    """
    Test that the connector validates an event when its owner org is in the list of allowed orgs.

    :param mock_opencti_connector_helper: `OpenCTIConnectorHelper` is mocked during this test to avoid any external calls to OpenCTI API
    :param mock_py_misp: `PyMISP` is mocked during this test to avoid any external calls to MISP API
    """
    config_dict = deepcopy(minimal_config_dict)
    config_dict["misp"]["import_owner_orgs"] = ["Test Org"]

    connector = fake_misp_connector(config_dict)
    event = EventRestSearchListItem.model_validate(
        {"Event": {"id": "42", "Org": {"name": "Test Org"}}}
    )

    assert connector._validate_event(event) is True


def test_connector_does_not_validate_event_with_owner_org_not_in_import_owner_orgs_list(
    mock_opencti_connector_helper, mock_py_misp
):
    """
    Test that the connector doesn't validate an event when its owner org is not in the list of allowed orgs.

    :param mock_opencti_connector_helper: `OpenCTIConnectorHelper` is mocked during this test to avoid any external calls to OpenCTI API
    :param mock_py_misp: `PyMISP` is mocked during this test to avoid any external calls to MISP API
    """
    config_dict = deepcopy(minimal_config_dict)
    config_dict["misp"]["import_owner_orgs"] = ["Test Org"]

    connector = fake_misp_connector(config_dict)
    event = EventRestSearchListItem.model_validate(
        {"Event": {"id": "42", "Org": {"name": "Another Org"}}}
    )

    assert connector._validate_event(event) is False


def test_connector_validates_event_when_no_import_owner_orgs_list(
    mock_opencti_connector_helper, mock_py_misp
):
    """
    Test that the connector validates an event when no allowed owner orgs are configured.

    :param mock_opencti_connector_helper: `OpenCTIConnectorHelper` is mocked during this test to avoid any external calls to OpenCTI API
    :param mock_py_misp: `PyMISP` is mocked during this test to avoid any external calls to MISP API
    """
    config_dict = deepcopy(minimal_config_dict)

    connector = fake_misp_connector(config_dict)
    event = EventRestSearchListItem.model_validate(
        {"Event": {"id": "42", "Org": {"name": "Any Org"}}}
    )

    assert connector._validate_event(event) is True


def test_connector_validates_event_with_owner_org_not_in_import_owner_orgs_not_list(
    mock_opencti_connector_helper, mock_py_misp
):
    """
    Test that the connector validates an event when its owner org is not in the list of excluded orgs.

    :param mock_opencti_connector_helper: `OpenCTIConnectorHelper` is mocked during this test to avoid any external calls to OpenCTI API
    :param mock_py_misp: `PyMISP` is mocked during this test to avoid any external calls to MISP API
    """
    config_dict = deepcopy(minimal_config_dict)
    config_dict["misp"]["import_owner_orgs_not"] = ["Excluded Org"]

    connector = fake_misp_connector(config_dict)
    event = EventRestSearchListItem.model_validate(
        {"Event": {"id": "42", "Org": {"name": "Allowed Org"}}}
    )

    assert connector._validate_event(event) is True


def test_connector_does_not_validate_event_with_owner_org_in_import_owner_orgs_not_list(
    mock_opencti_connector_helper, mock_py_misp
):
    """
    Test that the connector doesn't validate an event when its owner org is in the list of excluded orgs.

    :param mock_opencti_connector_helper: `OpenCTIConnectorHelper` is mocked during this test to avoid any external calls to OpenCTI API
    :param mock_py_misp: `PyMISP` is mocked during this test to avoid any external calls to MISP API
    """
    config_dict = deepcopy(minimal_config_dict)
    config_dict["misp"]["import_owner_orgs_not"] = ["Excluded Org"]

    connector = fake_misp_connector(config_dict)
    event = EventRestSearchListItem.model_validate(
        {"Event": {"id": "42", "Org": {"name": "Excluded Org"}}}
    )

    assert connector._validate_event(event) is False


def test_connector_validates_event_when_no_import_owner_orgs_not_list(
    mock_opencti_connector_helper, mock_py_misp
):
    """
    Test that the connector validates an event when no excluded owner orgs are configured.

    :param mock_opencti_connector_helper: `OpenCTIConnectorHelper` is mocked during this test to avoid any external calls to OpenCTI API
    :param mock_py_misp: `PyMISP` is mocked during this test to avoid any external calls to MISP API
    """
    config_dict = deepcopy(minimal_config_dict)

    connector = fake_misp_connector(config_dict)
    event = EventRestSearchListItem.model_validate(
        {"Event": {"id": "42", "Org": {"name": "Any Org"}}}
    )

    assert connector._validate_event(event) is True


def test_connector_validates_event_with_distribution_in_import_distribution_levels(
    mock_opencti_connector_helper, mock_py_misp
):
    """
    Test that the connector validates an event when its distribution level is in the list of allowed levels.

    :param mock_opencti_connector_helper: `OpenCTIConnectorHelper` is mocked during this test to avoid any external calls to OpenCTI API
    :param mock_py_misp: `PyMISP` is mocked during this test to avoid any external calls to MISP API
    """

    config_dict = deepcopy(minimal_config_dict)
    config_dict["misp"]["import_distribution_levels"] = ["2"]

    connector = fake_misp_connector(config_dict)
    event = EventRestSearchListItem.model_validate(
        {"Event": {"id": "42", "distribution": 2}}
    )

    assert connector._validate_event(event) is True


def test_connector_does_not_validate_event_with_distribution_not_in_import_distribution_levels(
    mock_opencti_connector_helper, mock_py_misp
):
    """
    Test that the connector doesn't validate an event when its distribution level is not in the list of allowed levels.

    :param mock_opencti_connector_helper: `OpenCTIConnectorHelper` is mocked during this test to avoid any external calls to OpenCTI API
    :param mock_py_misp: `PyMISP` is mocked during this test to avoid any external calls to MISP API
    """
    config_dict = deepcopy(minimal_config_dict)
    config_dict["misp"]["import_distribution_levels"] = ["0", "1"]

    connector = fake_misp_connector(config_dict)
    event = EventRestSearchListItem.model_validate(
        {"Event": {"id": "42", "distribution": 2}}
    )

    assert connector._validate_event(event) is False


def test_connector_validates_event_with_threat_level_in_import_threat_levels(
    mock_opencti_connector_helper, mock_py_misp
):
    """
    Test that the connector validates an event when its threat level is in the list of allowed levels.

    :param mock_opencti_connector_helper: `OpenCTIConnectorHelper` is mocked during this test to avoid any external calls to OpenCTI API
    :param mock_py_misp: `PyMISP` is mocked during this test to avoid any external calls to MISP API
    """
    config_dict = deepcopy(minimal_config_dict)
    config_dict["misp"]["import_threat_levels"] = ["3"]

    connector = fake_misp_connector(config_dict)
    event = EventRestSearchListItem.model_validate(
        {"Event": {"id": "42", "threat_level_id": 3}}
    )

    assert connector._validate_event(event) is True


def test_connector_does_not_validate_event_with_threat_level_not_in_import_threat_levels(
    mock_opencti_connector_helper, mock_py_misp
):
    """
    Test that the connector doesn't validate an event when its threat level is not in the list of allowed levels.

    :param mock_opencti_connector_helper: `OpenCTIConnectorHelper` is mocked during this test to avoid any external calls to OpenCTI API
    :param mock_py_misp: `PyMISP` is mocked during this test to avoid any external calls to MISP API
    """
    config_dict = deepcopy(minimal_config_dict)
    config_dict["misp"]["import_threat_levels"] = ["1", "2"]

    connector = fake_misp_connector(config_dict)
    event = EventRestSearchListItem.model_validate(
        {"Event": {"id": "42", "threat_level_id": 3}}
    )

    assert connector._validate_event(event) is False


def test_connector_validates_event_when_import_only_published_and_event_published(
    mock_opencti_connector_helper, mock_py_misp
):
    """
    Test that the connector validates an event when "import_only_published" is True and the event is published.

    :param mock_opencti_connector_helper: `OpenCTIConnectorHelper` is mocked during this test to avoid any external calls to OpenCTI API
    :param mock_py_misp: `PyMISP` is mocked during this test to
    """
    config_dict = deepcopy(minimal_config_dict)
    config_dict["misp"]["import_only_published"] = True

    connector = fake_misp_connector(config_dict)
    event = EventRestSearchListItem.model_validate(
        {"Event": {"id": "42", "published": True}}
    )

    assert connector._validate_event(event) is True


def test_connector_does_not_validate_event_when_import_only_published_and_event_not_published(
    mock_opencti_connector_helper, mock_py_misp
):
    """
    Test that the connector doesn't validate an event when "import_only_published" is True and the event is not published.

    :param mock_opencti_connector_helper: `OpenCTIConnectorHelper` is mocked during this test to avoid any external calls to OpenCTI API
    :param mock_py_misp: `PyMISP` is mocked during this test to
    """
    config_dict = deepcopy(minimal_config_dict)
    config_dict["misp"]["import_only_published"] = True

    connector = fake_misp_connector(config_dict)
    event = EventRestSearchListItem.model_validate(
        {"Event": {"id": "42", "published": False}}
    )

    assert connector._validate_event(event) is False


def test_connector_validates_event_not_yet_processed_by_creation_date(
    mock_opencti_connector_helper, mock_py_misp
):
    config_dict = deepcopy(minimal_config_dict)
    config_dict["misp"]["datetime_attribute"] = "date"

    connector = fake_misp_connector(config_dict)

    with patch.object(connector, "work_manager") as mock_work_manager:
        mock_work_manager.get_state.return_value = {
            "current_event_id": "1",
            "remaining_objects_count": 0,
        }
        event = EventRestSearchListItem.model_validate(
            {
                "Event": {
                    "id": "42",
                    "date": "2026-01-01",
                }
            }
        )
        assert connector._validate_event(event) is True


def test_connector_does_not_validate_event_already_processed_by_creation_date(
    mock_opencti_connector_helper, mock_py_misp
):
    config_dict = deepcopy(minimal_config_dict)
    config_dict["misp"]["datetime_attribute"] = "date"

    connector = fake_misp_connector(config_dict)

    with patch.object(connector, "work_manager") as mock_work_manager:
        mock_work_manager.get_state.return_value = {
            "current_event_id": "100",
            "remaining_objects_count": 0,
        }
        event = EventRestSearchListItem.model_validate(
            {
                "Event": {
                    "id": "42",
                    "date": "2026-01-01",
                }
            }
        )
        assert connector._validate_event(event) is False


def test_connector_validates_event_not_yet_processed_by_update_datetime(
    mock_opencti_connector_helper, mock_py_misp
):
    config_dict = deepcopy(minimal_config_dict)
    config_dict["misp"]["datetime_attribute"] = "timestamp"

    connector = fake_misp_connector(config_dict)

    with patch.object(connector, "work_manager") as mock_work_manager:
        mock_work_manager.get_state.return_value = {
            "last_event_date": "2026-01-01T00:00:00+00:00",
            "remaining_objects_count": 0,
        }
        event = EventRestSearchListItem.model_validate(
            {
                "Event": {
                    "id": "42",
                    "timestamp": str(
                        int(datetime(2026, 1, 2, tzinfo=timezone.utc).timestamp())
                    ),
                }
            }
        )
        assert connector._validate_event(event) is True


def test_connector_does_not_validate_event_already_processed_by_update_datetime(
    mock_opencti_connector_helper, mock_py_misp
):
    config_dict = deepcopy(minimal_config_dict)
    config_dict["misp"]["datetime_attribute"] = "timestamp"

    connector = fake_misp_connector(config_dict)

    with patch.object(connector, "work_manager") as mock_work_manager:
        mock_work_manager.get_state.return_value = {
            "last_event_date": "2026-01-02T00:00:00+00:00",
            "remaining_objects_count": 0,
        }
        event = EventRestSearchListItem.model_validate(
            {
                "Event": {
                    "id": "42",
                    "timestamp": str(
                        int(datetime(2026, 1, 2, tzinfo=timezone.utc).timestamp())
                    ),
                }
            }
        )
        # Timestamp is the same as the last event date, so the event should be validated
        assert connector._validate_event(event) is True

        event = EventRestSearchListItem.model_validate(
            {
                "Event": {
                    "id": "42",
                    "timestamp": str(
                        int(
                            datetime.fromisoformat(
                                "2026-01-01T23:59:59+00:00"
                            ).timestamp()
                        )
                    ),
                }
            }
        )
        # Timestamp is before the last event date, so the event should not be validated
        assert connector._validate_event(event) is False

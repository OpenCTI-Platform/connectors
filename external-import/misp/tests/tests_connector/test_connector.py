import time
from copy import deepcopy
from datetime import date, datetime, timedelta, timezone
from typing import Any
from unittest.mock import MagicMock, patch

import pycti
import stix2
from api_client.models import EventRestSearchListItem
from connector import ConnectorSettings, Misp
from connector.connector import ProcessingOutcome
from datasize import DataSize
from freezegun import freeze_time
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


def _make_identity(name: str, description: str | None = None) -> stix2.Identity:
    return stix2.Identity(
        id=pycti.Identity.generate_id(name=name, identity_class="organization"),
        name=name,
        identity_class="organization",
        description=description,
    )


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


def test_connector_creates_misp_client_with_request_timeout_from_config(
    mock_opencti_connector_helper, mock_py_misp
):
    """
    Test that MISPClient is instantiated with timeout from config.misp.request_timeout.
    """
    config_dict = deepcopy(minimal_config_dict)
    config_dict["misp"]["request_timeout"] = 90.0

    with patch("connector.connector.MISPClient") as mock_misp_client_class:
        fake_misp_connector(config_dict)
        mock_misp_client_class.assert_called_once()
        call_kwargs = mock_misp_client_class.call_args.kwargs
        assert call_kwargs["timeout"] == 90.0


def test_connector_creates_misp_client_with_request_timeout_none(
    mock_opencti_connector_helper, mock_py_misp
):
    """
    Test that MISPClient is instantiated with timeout=None when request_timeout is None.
    """
    config_dict = deepcopy(minimal_config_dict)
    config_dict["misp"]["request_timeout"] = None

    with patch("connector.connector.MISPClient") as mock_misp_client_class:
        fake_misp_connector(config_dict)
        mock_misp_client_class.assert_called_once()
        call_kwargs = mock_misp_client_class.call_args.kwargs
        assert call_kwargs["timeout"] is None


def test_check_and_add_entities_to_batch_flushes_existing_buffer_on_size_limit(
    mock_opencti_connector_helper, mock_py_misp
):
    config_dict = deepcopy(minimal_config_dict)
    config_dict["misp"]["batch_size_limit"] = "1KB"
    config_dict["misp"]["batch_count"] = 9999
    connector = fake_misp_connector(config_dict)

    buffered_object = _make_identity(name="buffered-object", description="X" * 10_000)
    connector.batch_processor.add_item(buffered_object)

    max_size_limit = DataSize(config_dict["misp"]["batch_size_limit"])
    assert connector.batch_processor.get_current_batch_size() >= max_size_limit

    author = _make_identity(name="author")
    entities = [_make_identity(name="entity-1"), _make_identity(name="entity-2")]

    with patch.object(
        connector.batch_processor,
        "flush",
        side_effect=lambda: connector.batch_processor.clear_current_batch(),
    ) as mock_flush:
        connector._check_and_add_entities_to_batch(
            all_entities=entities, author=author, markings=[]
        )

    assert mock_flush.call_count == 1
    assert connector.batch_processor.get_current_batch_length() == 1 + len(entities)


def test_check_and_add_entities_to_batch_flushes_on_projected_size_limit(
    mock_opencti_connector_helper, mock_py_misp
):
    config_dict = deepcopy(minimal_config_dict)
    config_dict["misp"]["batch_size_limit"] = "30KB"
    config_dict["misp"]["batch_count"] = 9999
    connector = fake_misp_connector(config_dict)

    connector.batch_processor.add_item(_make_identity(name="already-buffered"))

    max_size_limit = DataSize(config_dict["misp"]["batch_size_limit"])
    assert connector.batch_processor.get_current_batch_size() < max_size_limit

    author = _make_identity(name="author")
    entities = [
        _make_identity(name="entity-1", description="Y" * 50_000),
        _make_identity(name="entity-2"),
    ]

    with patch.object(
        connector.batch_processor,
        "flush",
        side_effect=lambda: connector.batch_processor.clear_current_batch(),
    ) as mock_flush:
        connector._check_and_add_entities_to_batch(
            all_entities=entities, author=author, markings=[]
        )

    assert mock_flush.call_count == 1
    assert connector.batch_processor.get_current_batch_length() == 1 + len(entities)


def test_check_and_add_entities_to_batch_keeps_count_based_flush_without_size_limit(
    mock_opencti_connector_helper, mock_py_misp
):
    config_dict = deepcopy(minimal_config_dict)
    config_dict["misp"]["batch_count"] = 2
    connector = fake_misp_connector(config_dict)

    connector.batch_processor.add_item(_make_identity(name="already-buffered-1"))
    connector.batch_processor.add_item(_make_identity(name="already-buffered-2"))

    author = _make_identity(name="author")
    entities = [_make_identity(name="entity-1"), _make_identity(name="entity-2")]

    with patch.object(
        connector.batch_processor,
        "flush",
        side_effect=lambda: connector.batch_processor.clear_current_batch(),
    ) as mock_flush:
        connector._check_and_add_entities_to_batch(
            all_entities=entities, author=author, markings=[]
        )

    assert mock_flush.call_count == 1
    assert connector.batch_processor.get_current_batch_length() == 1 + len(entities)


def test_check_batch_size_and_flush_does_not_flush_empty_batch_for_oversize_chunk(
    mock_opencti_connector_helper, mock_py_misp
):
    config_dict = deepcopy(minimal_config_dict)
    config_dict["misp"]["batch_size_limit"] = "1KB"
    connector = fake_misp_connector(config_dict)

    oversized_entities = [_make_identity(name="too-large", description="A" * 120_000)]

    with (
        patch.object(
            connector.batch_processor,
            "get_current_batch_length",
            return_value=0,
        ),
        patch.object(connector.batch_processor, "flush") as mock_flush,
    ):
        connector._check_batch_size_and_flush(oversized_entities)

    assert mock_flush.call_count == 0


def test_process_bundle_in_batch_sends_forced_oversize_single_entity_with_warning(
    mock_opencti_connector_helper, mock_py_misp
):
    config_dict = deepcopy(minimal_config_dict)
    config_dict["misp"]["batch_size_limit"] = "10KB"
    config_dict["misp"]["batch_count"] = 100
    config_dict["misp"]["datetime_attribute"] = "timestamp"
    connector = fake_misp_connector(config_dict)

    author = _make_identity(name="author")
    markings = []
    bundle_objects = [
        _make_identity(name="small-1"),
        _make_identity(name="huge", description="B" * 200_000),
        _make_identity(name="small-2"),
    ]
    event = EventRestSearchListItem.model_validate(
        {
            "Event": {
                "id": "1",
                "uuid": "event-1",
                "timestamp": str(
                    int(datetime(2026, 1, 2, tzinfo=timezone.utc).timestamp())
                ),
            }
        }
    )

    with (
        patch.object(
            connector.work_manager,
            "get_state",
            return_value={"remaining_objects_count": len(bundle_objects)},
        ),
        patch.object(
            connector.work_manager,
            "check_connector_run_and_terminate",
            return_value=True,
        ),
        patch.object(
            connector.work_manager,
            "check_connector_buffering",
            return_value=False,
        ),
        patch.object(connector.work_manager, "update_state") as mock_update_state,
        patch.object(
            connector,
            "_check_and_add_entities_to_batch",
        ) as mock_add_entities,
        patch.object(connector, "_flush_batch_processor"),
        patch.object(connector.logger, "warning") as mock_warning,
    ):
        outcome = connector._process_bundle_in_batch(
            event=event,
            bundle_objects=bundle_objects,
            author=author,
            markings=markings,
        )

    sent_entities_count = sum(
        len(call.args[0]) for call in mock_add_entities.call_args_list
    )
    assert outcome is ProcessingOutcome.COMPLETED
    assert sent_entities_count == len(bundle_objects)
    assert mock_warning.call_count >= 1
    assert mock_update_state.call_count >= 1


def test_process_bundle_in_batch_buffering_keeps_remaining_count_when_batch_empty(
    mock_opencti_connector_helper, mock_py_misp
):
    config_dict = deepcopy(minimal_config_dict)
    config_dict["misp"]["datetime_attribute"] = "timestamp"
    connector = fake_misp_connector(config_dict)

    author = _make_identity(name="author")
    markings = []
    bundle_objects = [
        _make_identity(name="entity-1"),
        _make_identity(name="entity-2"),
        _make_identity(name="entity-3"),
    ]
    initial_remaining = len(bundle_objects)
    event = EventRestSearchListItem.model_validate(
        {
            "Event": {
                "id": "42",
                "uuid": "event-42",
                "timestamp": str(
                    int(datetime(2026, 1, 2, tzinfo=timezone.utc).timestamp())
                ),
            }
        }
    )

    state_updates = []

    def track_update_state(state_update=None, **kwargs):
        if state_update:
            state_updates.append(state_update)

    with (
        patch.object(
            connector.work_manager,
            "get_state",
            return_value={"remaining_objects_count": initial_remaining},
        ),
        patch.object(
            connector.work_manager,
            "check_connector_run_and_terminate",
            return_value=False,
        ),
        patch.object(
            connector.work_manager,
            "check_connector_buffering",
            return_value=True,
        ),
        patch.object(
            connector.batch_processor,
            "get_current_batch_length",
            return_value=0,
        ),
        patch.object(connector.batch_processor, "clear_current_batch") as mock_clear,
        patch.object(
            connector.work_manager,
            "update_state",
            side_effect=track_update_state,
        ),
    ):
        outcome = connector._process_bundle_in_batch(
            event=event,
            bundle_objects=bundle_objects,
            author=author,
            markings=markings,
        )

    assert outcome is ProcessingOutcome.BUFFERING
    assert mock_clear.call_count == 1
    assert state_updates
    assert state_updates[-1]["remaining_objects_count"] == initial_remaining


def test_process_bundle_in_batch_sets_work_name_completion_to_100_on_last_chunk(
    mock_opencti_connector_helper, mock_py_misp
):
    config_dict = deepcopy(minimal_config_dict)
    config_dict["misp"]["datetime_attribute"] = "timestamp"
    config_dict["misp"]["batch_count"] = 10
    connector = fake_misp_connector(config_dict)

    author = _make_identity(name="author")
    markings = []
    bundle_objects = [
        _make_identity(name="entity-1"),
        _make_identity(name="entity-2"),
        _make_identity(name="entity-3"),
    ]
    event = EventRestSearchListItem.model_validate(
        {
            "Event": {
                "id": "12",
                "uuid": "event-12",
                "timestamp": str(
                    int(datetime(2026, 1, 2, tzinfo=timezone.utc).timestamp())
                ),
            }
        }
    )

    with (
        patch.object(
            connector.work_manager,
            "get_state",
            return_value={"remaining_objects_count": len(bundle_objects)},
        ),
        patch.object(
            connector.work_manager,
            "check_connector_run_and_terminate",
            return_value=True,
        ),
        patch.object(
            connector.work_manager,
            "check_connector_buffering",
            return_value=False,
        ),
        patch.object(connector.work_manager, "update_state"),
        patch.object(
            connector,
            "_check_and_add_entities_to_batch",
        ),
        patch.object(connector, "_flush_batch_processor"),
    ):
        outcome = connector._process_bundle_in_batch(
            event=event,
            bundle_objects=bundle_objects,
            author=author,
            markings=markings,
        )

    assert outcome is ProcessingOutcome.COMPLETED
    assert "Completion 100%" in connector.batch_processor.work_name_template


def test_process_bundle_in_batch_completion_progression_matches_processed_batches(
    mock_opencti_connector_helper, mock_py_misp
):
    config_dict = deepcopy(minimal_config_dict)
    config_dict["misp"]["datetime_attribute"] = "timestamp"
    config_dict["misp"]["batch_count"] = 2
    connector = fake_misp_connector(config_dict)

    author = _make_identity(name="author")
    markings = []
    bundle_objects = [
        _make_identity(name="entity-1"),
        _make_identity(name="entity-2"),
        _make_identity(name="entity-3"),
        _make_identity(name="entity-4"),
        _make_identity(name="entity-5"),
        _make_identity(name="entity-6"),
        _make_identity(name="entity-7"),
        _make_identity(name="entity-8"),
        _make_identity(name="entity-9"),
    ]
    event = EventRestSearchListItem.model_validate(
        {
            "Event": {
                "id": "13",
                "uuid": "event-13",
                "timestamp": str(
                    int(datetime(2026, 1, 2, tzinfo=timezone.utc).timestamp())
                ),
            }
        }
    )

    work_name_snapshots = []

    def capture_and_skip_add(*args, **kwargs):
        work_name_snapshots.append(connector.batch_processor.work_name_template)

    with (
        patch.object(
            connector.work_manager,
            "get_state",
            return_value={"remaining_objects_count": len(bundle_objects)},
        ),
        patch.object(
            connector.work_manager,
            "check_connector_run_and_terminate",
            return_value=True,
        ),
        patch.object(
            connector.work_manager,
            "check_connector_buffering",
            return_value=False,
        ),
        patch.object(connector.work_manager, "update_state"),
        patch.object(
            connector,
            "_check_and_add_entities_to_batch",
            side_effect=capture_and_skip_add,
        ),
        patch.object(connector, "_flush_batch_processor"),
    ):
        outcome = connector._process_bundle_in_batch(
            event=event,
            bundle_objects=bundle_objects,
            author=author,
            markings=markings,
        )

    assert outcome is ProcessingOutcome.COMPLETED
    assert len(work_name_snapshots) == 5
    assert "Completion 0%" in work_name_snapshots[0]
    assert "Completion 22%" in work_name_snapshots[1]
    assert "Completion 44%" in work_name_snapshots[2]
    assert "Completion 66%" in work_name_snapshots[3]
    assert "Completion 88%" in work_name_snapshots[4]


def test_process_bundle_in_batch_completion_starts_from_resume_object_index(
    mock_opencti_connector_helper, mock_py_misp
):
    config_dict = deepcopy(minimal_config_dict)
    config_dict["misp"]["datetime_attribute"] = "timestamp"
    config_dict["misp"]["batch_count"] = 2
    connector = fake_misp_connector(config_dict)

    author = _make_identity(name="author")
    markings = []
    bundle_objects = [
        _make_identity(name="entity-1"),
        _make_identity(name="entity-2"),
        _make_identity(name="entity-3"),
        _make_identity(name="entity-4"),
        _make_identity(name="entity-5"),
        _make_identity(name="entity-6"),
        _make_identity(name="entity-7"),
        _make_identity(name="entity-8"),
        _make_identity(name="entity-9"),
    ]
    event = EventRestSearchListItem.model_validate(
        {
            "Event": {
                "id": "14",
                "uuid": "event-14",
                "timestamp": str(
                    int(datetime(2026, 1, 2, tzinfo=timezone.utc).timestamp())
                ),
            }
        }
    )

    work_name_snapshots = []

    def capture_and_skip_add(*args, **kwargs):
        work_name_snapshots.append(connector.batch_processor.work_name_template)

    with (
        patch.object(
            connector.work_manager,
            "get_state",
            # Resume at object_index = 2 on bundle of 9
            return_value={"remaining_objects_count": 7},
        ),
        patch.object(
            connector.work_manager,
            "check_connector_run_and_terminate",
            return_value=True,
        ),
        patch.object(
            connector.work_manager,
            "check_connector_buffering",
            return_value=False,
        ),
        patch.object(connector.work_manager, "update_state"),
        patch.object(
            connector,
            "_check_and_add_entities_to_batch",
            side_effect=capture_and_skip_add,
        ),
        patch.object(connector, "_flush_batch_processor"),
    ):
        outcome = connector._process_bundle_in_batch(
            event=event,
            bundle_objects=bundle_objects,
            author=author,
            markings=markings,
        )

    assert outcome is ProcessingOutcome.COMPLETED
    # First visible progress should reflect resumed index (2/9 ~= 22%).
    assert "Completion 22%" in work_name_snapshots[0]


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


def _make_publish_timestamp_event(event_id: str, ts: int) -> EventRestSearchListItem:
    return EventRestSearchListItem.model_validate(
        {"Event": {"id": event_id, "publish_timestamp": str(ts)}}
    )


def _run_process_events(
    connector, events, buffering_at_event_index=None, initial_state=None
):
    """
    Run `process_events` with all external dependencies mocked.

    Args:
        buffering_at_event_index: 0-based index of the event call at which
            ``_process_bundle_in_batch`` should return
            ``ProcessingOutcome.BUFFERING``.  ``None`` means no buffering.

    Returns:
        (state dict, mock for _process_bundle_in_batch, process_events return value)
    """
    state = dict(initial_state or {})

    def track_update_state(state_update=None, **kwargs):
        if state_update:
            state.update(state_update)

    call_count = [0]

    def process_bundle_side_effect(event, bundle_objects, author, markings):
        idx = call_count[0]
        call_count[0] += 1
        if buffering_at_event_index is not None and idx == buffering_at_event_index:
            # Simulate what the real _process_bundle_in_batch does when it
            # detects buffering: persist the checkpoint state and signal the
            # caller to stop the event loop.
            state["last_event_date"] = connector._get_event_datetime(event).isoformat()
            state["remaining_objects_count"] = len(bundle_objects)
            return ProcessingOutcome.BUFFERING
        return ProcessingOutcome.COMPLETED

    with (
        patch.object(connector, "helper") as mock_helper,
        patch.object(connector, "work_manager") as mock_wm,
        patch.object(connector, "client_api") as mock_api,
        patch.object(connector, "converter") as mock_converter,
        patch.object(connector, "batch_processor"),
        patch.object(connector, "_process_bundle_in_batch") as mock_process,
    ):
        mock_helper.get_state.return_value = initial_state or {}
        mock_helper.metric = MagicMock()

        mock_wm.get_state.side_effect = lambda: dict(state)
        mock_wm.update_state.side_effect = track_update_state

        mock_process.side_effect = process_bundle_side_effect

        mock_api.search_events.return_value = iter(events)
        mock_converter.process.return_value = (MagicMock(), [], [MagicMock()])

        result = connector.process_events()

    return state, mock_process, result


@freeze_time("2026-01-01 00:00:00")
def test_process_events_state_set_to_buffered_event_date_on_buffering(
    mock_opencti_connector_helper, mock_py_misp
):
    """
    Test that when buffering is detected inside _process_bundle_in_batch for
    event B, ``last_event_date`` is saved to event B's timestamp so the next
    run restarts from that event.

    Scenario:
    - Event A (earlier timestamp): processed normally.
    - Event B (later timestamp): _process_bundle_in_batch detects buffering
      mid-chunk → returns ProcessingOutcome.BUFFERING → loop breaks.

    Expected: after the run, ``last_event_date`` equals event B's timestamp
    (not A's), so the next run re-processes event B from the saved chunk
    offset.
    """
    config_dict = deepcopy(minimal_config_dict)
    config_dict["misp"]["datetime_attribute"] = "publish_timestamp"
    connector = fake_misp_connector(config_dict)

    ts_a = int(time.time())
    ts_b = int(time.time() + 1)

    event_a = _make_publish_timestamp_event("1", ts_a)
    event_b = _make_publish_timestamp_event("2", ts_b)

    # Buffering triggers on the second _process_bundle_in_batch call (event B)
    state, _, result = _run_process_events(
        connector, [event_a, event_b], buffering_at_event_index=1
    )

    expected = datetime.fromtimestamp(ts_b, tz=timezone.utc).isoformat()
    assert state.get("last_event_date") == expected


@freeze_time("2026-01-01 00:00:00")
def test_process_events_buffering_breaks_event_loop(
    mock_opencti_connector_helper, mock_py_misp
):
    """
    Test that when ``_process_bundle_in_batch`` returns
    ``ProcessingOutcome.BUFFERING`` for event B, the event loop is broken
    immediately — event B itself IS passed to the method (buffering is
    detected inside it), but any subsequent events are not processed at all.

    Scenario:
    - Event A: _process_bundle_in_batch returns COMPLETED.
    - Event B: _process_bundle_in_batch returns BUFFERING → loop breaks.
    - Event C: never reached.
    """
    config_dict = deepcopy(minimal_config_dict)
    config_dict["misp"]["datetime_attribute"] = "publish_timestamp"
    connector = fake_misp_connector(config_dict)

    ts_a = int(time.time())
    ts_b = int(time.time() + 1)
    ts_c = int(time.time() + 2)

    event_a = _make_publish_timestamp_event("1", ts_a)
    event_b = _make_publish_timestamp_event("2", ts_b)
    event_c = _make_publish_timestamp_event("3", ts_c)

    state, mock_process, _ = _run_process_events(
        connector, [event_a, event_b, event_c], buffering_at_event_index=1
    )

    # Both event A and event B were passed to _process_bundle_in_batch;
    # event C was never reached because the loop broke after event B.
    assert mock_process.call_count == 2
    assert mock_process.call_args_list[0][1]["event"] == event_a
    assert mock_process.call_args_list[1][1]["event"] == event_b


def test_process_events_adds_one_second_after_loop_completion(
    mock_opencti_connector_helper, mock_py_misp
):
    """
    Test that after the event loop completes without interruption, `last_event_date`
    is advanced by 1 second. This prevents events at the exact boundary timestamp
    from being re-queried (and reprocessed) on the next run.
    """
    config_dict = deepcopy(minimal_config_dict)
    config_dict["misp"]["datetime_attribute"] = "publish_timestamp"
    connector = fake_misp_connector(config_dict)

    with freeze_time("2026-01-01 00:00:00") as frozen_time:
        ts = int(time.time())
        event = _make_publish_timestamp_event("1", ts)

        # No buffering — loop completes normally
        state, _, result = _run_process_events(connector, [event])

        # ts == Now: process_events does not update last_event_date (handled
        # by _process_bundle_in_batch, which is mocked here).
        assert state.get("last_event_date") is None
        assert result is None

        frozen_time.move_to("2026-01-01 00:00:01")
        state, _, result = _run_process_events(connector, [event])
        expected = (
            datetime.fromtimestamp(ts, tz=timezone.utc) + timedelta(seconds=1)
        ).isoformat()
        assert state.get("last_event_date") == expected
        assert result is None

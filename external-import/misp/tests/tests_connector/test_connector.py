import logging
import time
from copy import deepcopy
from datetime import date, datetime, timedelta, timezone
from typing import Any
from unittest.mock import MagicMock, patch

import pycti
import pytest
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
    helper.connector_logger = logging.getLogger("misp")

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
    connector,
    events,
    buffering_at_event_index=None,
    initial_state=None,
    event_already_ingested=True,
):
    """
    Run `process_events` with all external dependencies mocked.

    Args:
        buffering_at_event_index: 0-based index of the event call at which
            ``_process_bundle_in_batch`` should return
            ``ProcessingOutcome.BUFFERING``.  ``None`` means no buffering.
        event_already_ingested: If True (default), the ExternalReference
            lookup returns a match (simulating the event was already ingested
            into OpenCTI).  If False, returns no match (event never ingested).

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
        mock_helper.api.query.return_value = (
            {"data": {"externalReferences": {"edges": [{"node": {"id": "x"}}]}}}
            if event_already_ingested
            else {"data": {"externalReferences": {"edges": []}}}
        )

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


@pytest.mark.parametrize(
    "import_from_date, expected_logs",
    [
        (
            None,
            [
                "Retrieved state - {'prefix': '[Connector]', 'initial_state': {}}",
                "Starting MISP full ingestion... - {'prefix': '[Connector]'}",
                "Connector has never run - {'last_event_date': FakeDatetime(2025, 12, 22, 12, 0, tzinfo=datetime.timezone.utc)}",
                "Fetching MISP events with filters: - {'prefix': '[Connector]', 'date_field_filter': 'timestamp', 'date_value_filter': FakeDatetime(2025, 12, 22, 12, 0, tzinfo=datetime.timezone.utc), 'datetime_attribute': 'publish_timestamp', 'keyword': None, 'included_tags': [], 'excluded_tags': [], 'included_org_creators': [], 'excluded_org_creators': [], 'enforce_warning_list': False, 'with_attachments': False, 'limit': 10}",
                "MISP event found - Processing... - {'prefix': '[Connector]', 'event_id': '1', 'event_uuid': None}",
                "Converted to STIX entities - {'prefix': '[Connector]', 'entities_count': 2}",
                "Updating last event date (add 1 second) to avoid processing the same event again - {'prefix': '[Connector]', 'last_event_date': '2025-12-27T12:00:01+00:00'}",
                "Batch processor: Flushed remaining items - {'prefix': '[Connector]'}",
            ],
        ),
        (
            "2026-01-01",
            [
                "Retrieved state - {'prefix': '[Connector]', 'initial_state': {}}",
                "Starting MISP full ingestion... - {'prefix': '[Connector]'}",
                "Connector has never run - {'last_event_date': FakeDatetime(2026, 1, 1, 0, 0, tzinfo=datetime.timezone.utc)}",
                "Fetching MISP events with filters: - {'prefix': '[Connector]', 'date_field_filter': 'timestamp', 'date_value_filter': FakeDatetime(2026, 1, 1, 0, 0, tzinfo=datetime.timezone.utc), 'datetime_attribute': 'publish_timestamp', 'keyword': None, 'included_tags': [], 'excluded_tags': [], 'included_org_creators': [], 'excluded_org_creators': [], 'enforce_warning_list': False, 'with_attachments': False, 'limit': 10}",
                "MISP event found - Processing... - {'prefix': '[Connector]', 'event_id': '1', 'event_uuid': None}",
                "Converted to STIX entities - {'prefix': '[Connector]', 'entities_count': 2}",
                "Updating last event date (add 1 second) to avoid processing the same event again - {'prefix': '[Connector]', 'last_event_date': '2025-12-27T12:00:01+00:00'}",
                "Batch processor: Flushed remaining items - {'prefix': '[Connector]'}",
            ],
        ),
    ],
)
@freeze_time("2026-01-01 12:00:00")
def test_process_events_first_run(
    caplog, mock_opencti_connector_helper, mock_py_misp, import_from_date, expected_logs
):
    """
    Test that if import_from_date is not set, last_event_date will be 10 days
    before today. Else, use the import_from_date date.
    """
    caplog.set_level(logging.DEBUG)

    # Given import_from_date
    config_dict = deepcopy(minimal_config_dict)
    config_dict["misp"]["datetime_attribute"] = "publish_timestamp"
    config_dict["misp"]["import_from_date"] = import_from_date
    connector = fake_misp_connector(config_dict)

    # And an event
    ts = int((datetime.now(tz=timezone.utc) - timedelta(days=5)).timestamp())
    event = EventRestSearchListItem.model_validate(
        {"Event": {"id": "1", "publish_timestamp": str(ts)}}
    )

    # When we call process_events
    _run_process_events(connector, [event])

    # Then process_events should complete successfully with expected logs
    all_messages = [rec.getMessage() for rec in caplog.records]
    missing_messages = [
        msg
        for msg in expected_logs
        if not any(msg in log_msg for log_msg in all_messages)
    ]

    assert (  # noqa: S101
        not missing_messages
    ), f"Missing expected log messages: {missing_messages}"


# --------------------------------------------------------------------------- #
#  Attribute-level timestamp filtering tests
# --------------------------------------------------------------------------- #


def _make_event_with_attributes(
    event_id: str,
    event_ts: int,
    attributes: list[dict] | None = None,
    objects: list[dict] | None = None,
) -> EventRestSearchListItem:
    """Build an EventRestSearchListItem with explicit attributes and objects."""
    event_dict: dict = {
        "id": event_id,
        "uuid": f"00000000-0000-0000-0000-{event_id.zfill(12)}",
        "info": f"Test event {event_id}",
        "date": "2026-01-15",
        "timestamp": str(event_ts),
        "publish_timestamp": str(event_ts),
        "threat_level_id": "2",
        "Orgc": {"name": "TestOrg"},
    }
    if attributes is not None:
        event_dict["Attribute"] = attributes
    if objects is not None:
        event_dict["Object"] = objects
    return EventRestSearchListItem.model_validate({"Event": event_dict})


class TestEventAlreadyExistsInOpencti:
    """Tests for ``Misp._event_already_exists_in_opencti``."""

    @staticmethod
    def _mock_query_result(found: bool):
        """Return a mock GraphQL response for externalReferences query."""
        if found:
            return {"data": {"externalReferences": {"edges": [{"node": {"id": "x"}}]}}}
        return {"data": {"externalReferences": {"edges": []}}}

    def test_returns_true_when_external_ref_found(
        self, mock_opencti_connector_helper, mock_py_misp
    ):
        connector = fake_misp_connector(deepcopy(minimal_config_dict))
        event = _make_event_with_attributes("1", 1000, attributes=[])

        with patch.object(connector, "helper") as mock_helper:
            mock_helper.api.query.return_value = self._mock_query_result(True)
            assert connector._event_already_exists_in_opencti(event) is True
            mock_helper.api.query.assert_called_once()

    def test_returns_false_when_external_ref_not_found(
        self, mock_opencti_connector_helper, mock_py_misp
    ):
        connector = fake_misp_connector(deepcopy(minimal_config_dict))
        event = _make_event_with_attributes("1", 1000, attributes=[])

        with patch.object(connector, "helper") as mock_helper:
            mock_helper.api.query.return_value = self._mock_query_result(False)
            assert connector._event_already_exists_in_opencti(event) is False

    def test_queries_by_event_uuid(self, mock_opencti_connector_helper, mock_py_misp):
        """Verifies the query uses the MISP event UUID as external_id filter."""
        connector = fake_misp_connector(deepcopy(minimal_config_dict))
        event = _make_event_with_attributes("1", 1000, attributes=[])

        with patch.object(connector, "helper") as mock_helper:
            mock_helper.api.query.return_value = self._mock_query_result(False)
            connector._event_already_exists_in_opencti(event)

            call_args = mock_helper.api.query.call_args
            variables = call_args[0][1]
            filters = variables["filters"]["filters"]
            ext_id_filter = next(f for f in filters if f["key"] == "external_id")
            source_filter = next(f for f in filters if f["key"] == "source_name")
            assert ext_id_filter["values"] == [event.Event.uuid]
            assert source_filter["values"] == ["MISP"]


class TestFilterEventAttributesByTimestamp:
    """Tests for ``Misp._filter_event_attributes_by_timestamp``."""

    def test_filters_old_top_level_attributes(
        self, mock_opencti_connector_helper, mock_py_misp
    ):
        connector = fake_misp_connector(deepcopy(minimal_config_dict))
        event = _make_event_with_attributes(
            "1",
            100,
            attributes=[
                {"id": "1", "timestamp": "100", "value": "old"},
                {"id": "2", "timestamp": "200", "value": "new"},
                {"id": "3", "timestamp": "300", "value": "newest"},
            ],
        )

        before, after = connector._filter_event_attributes_by_timestamp(event, 200)

        assert before == 3
        assert after == 2
        assert len(event.Event.Attribute) == 2
        assert {a.value for a in event.Event.Attribute} == {"new", "newest"}

    def test_keeps_all_when_all_newer(
        self, mock_opencti_connector_helper, mock_py_misp
    ):
        connector = fake_misp_connector(deepcopy(minimal_config_dict))
        event = _make_event_with_attributes(
            "1",
            500,
            attributes=[
                {"id": "1", "timestamp": "500", "value": "a"},
                {"id": "2", "timestamp": "600", "value": "b"},
            ],
        )

        before, after = connector._filter_event_attributes_by_timestamp(event, 500)

        assert before == 2
        assert after == 2

    def test_filters_all_when_all_older(
        self, mock_opencti_connector_helper, mock_py_misp
    ):
        connector = fake_misp_connector(deepcopy(minimal_config_dict))
        event = _make_event_with_attributes(
            "1",
            100,
            attributes=[
                {"id": "1", "timestamp": "100", "value": "a"},
                {"id": "2", "timestamp": "200", "value": "b"},
            ],
        )

        before, after = connector._filter_event_attributes_by_timestamp(event, 300)

        assert before == 2
        assert after == 0  # no attributes passed the filter
        # First attribute kept as fallback for valid object_refs
        assert len(event.Event.Attribute) == 1
        assert event.Event.Attribute[0].value == "a"

    def test_filters_object_attributes_and_prunes_empty_objects(
        self, mock_opencti_connector_helper, mock_py_misp
    ):
        connector = fake_misp_connector(deepcopy(minimal_config_dict))
        event = _make_event_with_attributes(
            "1",
            100,
            objects=[
                {
                    "id": "10",
                    "name": "kept-obj",
                    "timestamp": "50",
                    "Attribute": [
                        {"id": "1", "timestamp": "300", "value": "new-attr"},
                    ],
                },
                {
                    "id": "20",
                    "name": "pruned-obj",
                    "timestamp": "50",
                    "Attribute": [
                        {"id": "2", "timestamp": "100", "value": "old-attr"},
                    ],
                },
            ],
        )

        before, after = connector._filter_event_attributes_by_timestamp(event, 200)

        assert before == 2
        assert after == 1
        assert len(event.Event.Object) == 1
        assert event.Event.Object[0].name == "kept-obj"

    def test_removes_object_without_attributes_even_if_recently_modified(
        self, mock_opencti_connector_helper, mock_py_misp
    ):
        """Objects with no attributes are always dropped — the converter requires
        at least one attribute (object.Attribute[0]) and would raise IndexError."""
        connector = fake_misp_connector(deepcopy(minimal_config_dict))
        event = _make_event_with_attributes(
            "1",
            100,
            objects=[
                {
                    "id": "10",
                    "name": "meta-changed",
                    "timestamp": "500",
                    # No Attribute key at all
                },
            ],
        )

        before, after = connector._filter_event_attributes_by_timestamp(event, 200)

        assert before == 0
        assert after == 0
        assert len(event.Event.Object) == 0

    def test_removes_object_when_all_attributes_filtered_out(
        self, mock_opencti_connector_helper, mock_py_misp
    ):
        """Regression test for IndexError: object.Attribute[0] in converter.
        An object whose attributes are all older than the threshold must be
        dropped entirely, not kept with an empty Attribute list.
        The first attribute is kept as a top-level fallback for valid object_refs."""
        connector = fake_misp_connector(deepcopy(minimal_config_dict))
        event = _make_event_with_attributes(
            "1",
            600,
            objects=[
                {
                    "id": "10",
                    "name": "obj-all-old",
                    "timestamp": "600",  # object itself is recent
                    "Attribute": [
                        {"id": "1", "timestamp": "100", "value": "old1"},
                        {"id": "2", "timestamp": "200", "value": "old2"},
                    ],
                },
            ],
        )

        before, after = connector._filter_event_attributes_by_timestamp(event, 500)

        assert before == 2
        assert after == 0  # no attributes passed the filter
        # Object must be dropped — keeping it with Attribute=[] would crash the converter
        assert len(event.Event.Object) == 0
        # First attribute promoted to top-level as fallback
        assert len(event.Event.Attribute) == 1
        assert event.Event.Attribute[0].value == "old1"

    def test_removes_object_without_attributes_if_old(
        self, mock_opencti_connector_helper, mock_py_misp
    ):
        connector = fake_misp_connector(deepcopy(minimal_config_dict))
        event = _make_event_with_attributes(
            "1",
            100,
            objects=[
                {"id": "10", "name": "old-meta", "timestamp": "50"},
            ],
        )

        connector._filter_event_attributes_by_timestamp(event, 200)

        assert len(event.Event.Object) == 0

    def test_handles_no_attributes_and_no_objects(
        self, mock_opencti_connector_helper, mock_py_misp
    ):
        connector = fake_misp_connector(deepcopy(minimal_config_dict))
        event = _make_event_with_attributes("1", 100)

        before, after = connector._filter_event_attributes_by_timestamp(event, 200)

        assert before == 0
        assert after == 0

    def test_mixed_top_level_and_object_attributes(
        self, mock_opencti_connector_helper, mock_py_misp
    ):
        connector = fake_misp_connector(deepcopy(minimal_config_dict))
        event = _make_event_with_attributes(
            "1",
            100,
            attributes=[
                {"id": "1", "timestamp": "100", "value": "old-top"},
                {"id": "2", "timestamp": "500", "value": "new-top"},
            ],
            objects=[
                {
                    "id": "10",
                    "name": "obj1",
                    "timestamp": "50",
                    "Attribute": [
                        {"id": "3", "timestamp": "400", "value": "new-obj-attr"},
                        {"id": "4", "timestamp": "100", "value": "old-obj-attr"},
                    ],
                },
            ],
        )

        before, after = connector._filter_event_attributes_by_timestamp(event, 300)

        assert before == 4
        assert after == 2
        assert len(event.Event.Attribute) == 1
        assert event.Event.Attribute[0].value == "new-top"
        assert len(event.Event.Object) == 1
        assert len(event.Event.Object[0].Attribute) == 1
        assert event.Event.Object[0].Attribute[0].value == "new-obj-attr"


class TestGetMaxAttributeTimestamp:
    """Tests for ``Misp._get_max_attribute_timestamp``."""

    def test_returns_max_from_top_level_attributes(
        self, mock_opencti_connector_helper, mock_py_misp
    ):
        connector = fake_misp_connector(deepcopy(minimal_config_dict))
        event = _make_event_with_attributes(
            "1",
            100,
            attributes=[
                {"id": "1", "timestamp": "100"},
                {"id": "2", "timestamp": "300"},
                {"id": "3", "timestamp": "200"},
            ],
        )

        assert connector._get_max_attribute_timestamp(event) == 300

    def test_returns_max_from_object_attributes(
        self, mock_opencti_connector_helper, mock_py_misp
    ):
        connector = fake_misp_connector(deepcopy(minimal_config_dict))
        event = _make_event_with_attributes(
            "1",
            100,
            attributes=[{"id": "1", "timestamp": "100"}],
            objects=[
                {
                    "id": "10",
                    "timestamp": "200",
                    "Attribute": [{"id": "2", "timestamp": "500"}],
                },
            ],
        )

        assert connector._get_max_attribute_timestamp(event) == 500

    def test_ignores_object_own_timestamp(
        self, mock_opencti_connector_helper, mock_py_misp
    ):
        """Object timestamps are not considered — only attribute timestamps matter."""
        connector = fake_misp_connector(deepcopy(minimal_config_dict))
        event = _make_event_with_attributes(
            "1",
            100,
            attributes=[{"id": "1", "timestamp": "100"}],
            objects=[
                {
                    "id": "10",
                    "timestamp": "999",
                    "Attribute": [{"id": "2", "timestamp": "50"}],
                },
            ],
        )

        assert connector._get_max_attribute_timestamp(event) == 100

    def test_returns_zero_when_no_attributes(
        self, mock_opencti_connector_helper, mock_py_misp
    ):
        connector = fake_misp_connector(deepcopy(minimal_config_dict))
        event = _make_event_with_attributes("1", 100)

        assert connector._get_max_attribute_timestamp(event) == 0


class TestProcessEventsAttributeTimestampFiltering:
    """Integration tests for attribute-level timestamp filtering in ``process_events``."""

    def test_first_run_no_filtering_applied_state_saved(
        self, mock_opencti_connector_helper, mock_py_misp
    ):
        """First run (no last_attribute_timestamp in state): all attributes processed,
        state is updated with the max attribute timestamp."""
        config_dict = deepcopy(minimal_config_dict)
        config_dict["misp"]["datetime_attribute"] = "publish_timestamp"
        config_dict["misp"]["attribute_timestamp_filtering"] = True
        connector = fake_misp_connector(config_dict)

        ts = int(datetime(2026, 1, 15, tzinfo=timezone.utc).timestamp())
        event = _make_event_with_attributes(
            "1",
            ts,
            attributes=[
                {"id": "1", "timestamp": str(ts - 100), "value": "a"},
                {"id": "2", "timestamp": str(ts), "value": "b"},
            ],
        )

        state, _, result = _run_process_events(connector, [event])

        assert result is None
        # On first run, last_attribute_timestamp should be set to max + 1
        assert state.get("last_attribute_timestamp") == ts + 1

    def test_second_run_filters_old_attributes(
        self, mock_opencti_connector_helper, mock_py_misp
    ):
        """Second run with saved state: only new attributes are kept."""
        config_dict = deepcopy(minimal_config_dict)
        config_dict["misp"]["datetime_attribute"] = "publish_timestamp"
        config_dict["misp"]["attribute_timestamp_filtering"] = True
        connector = fake_misp_connector(config_dict)

        ts_old = 1000
        ts_new = 2000
        ts_threshold = 1500

        event = _make_event_with_attributes(
            "1",
            ts_new,
            attributes=[
                {"id": "1", "timestamp": str(ts_old), "value": "old"},
                {"id": "2", "timestamp": str(ts_new), "value": "new"},
            ],
        )

        initial_state = {
            "last_event_date": datetime.fromtimestamp(
                ts_old, tz=timezone.utc
            ).isoformat(),
            "last_attribute_timestamp": ts_threshold,
        }

        state, mock_process, result = _run_process_events(
            connector, [event], initial_state=initial_state
        )

        assert result is None
        # _process_bundle_in_batch should have been called (event has new attrs)
        assert mock_process.call_count == 1
        # State should be updated with the max attr timestamp + 1
        assert state.get("last_attribute_timestamp") == ts_new + 1

    def test_metadata_only_update_when_all_attributes_old(
        self, mock_opencti_connector_helper, mock_py_misp
    ):
        """Event is still processed for metadata when all its attributes are older than the threshold."""
        config_dict = deepcopy(minimal_config_dict)
        config_dict["misp"]["datetime_attribute"] = "publish_timestamp"
        config_dict["misp"]["attribute_timestamp_filtering"] = True
        connector = fake_misp_connector(config_dict)

        ts = 1000
        threshold = 2000

        event = _make_event_with_attributes(
            "1",
            ts,
            attributes=[
                {"id": "1", "timestamp": str(ts), "value": "old1"},
                {"id": "2", "timestamp": str(ts + 100), "value": "old2"},
            ],
        )

        initial_state = {
            "last_event_date": datetime.fromtimestamp(ts, tz=timezone.utc).isoformat(),
            "last_attribute_timestamp": threshold,
        }

        state, mock_process, result = _run_process_events(
            connector, [event], initial_state=initial_state
        )

        assert result is None
        # Event should still be processed for metadata (tags, galaxies, threat level)
        assert mock_process.call_count == 1
        # First attribute kept as fallback for valid object_refs
        processed_event = mock_process.call_args[1]["event"]
        assert len(processed_event.Event.Attribute) == 1
        assert processed_event.Event.Attribute[0].value == "old1"

    def test_disabled_by_default(self, mock_opencti_connector_helper, mock_py_misp):
        """When attribute_timestamp_filtering is False (default), no filtering occurs."""
        config_dict = deepcopy(minimal_config_dict)
        config_dict["misp"]["datetime_attribute"] = "publish_timestamp"
        # attribute_timestamp_filtering defaults to False
        connector = fake_misp_connector(config_dict)

        ts = 1000
        event = _make_event_with_attributes(
            "1",
            ts,
            attributes=[
                {"id": "1", "timestamp": str(ts), "value": "a"},
            ],
        )

        state, mock_process, result = _run_process_events(connector, [event])

        assert result is None
        assert mock_process.call_count == 1
        # No last_attribute_timestamp should be saved
        assert "last_attribute_timestamp" not in state

    def test_fallback_to_last_event_date_when_no_attribute_timestamp(
        self, mock_opencti_connector_helper, mock_py_misp
    ):
        """When attribute filtering is enabled on an existing connector (has last_event_date
        but no last_attribute_timestamp), last_event_date is used as the filter threshold.
        """
        config_dict = deepcopy(minimal_config_dict)
        config_dict["misp"]["datetime_attribute"] = "publish_timestamp"
        config_dict["misp"]["attribute_timestamp_filtering"] = True
        connector = fake_misp_connector(config_dict)

        # last_event_date = 1500 as unix timestamp
        last_event_ts = 1500
        last_event_iso = datetime.fromtimestamp(
            last_event_ts, tz=timezone.utc
        ).isoformat()

        # Event with one old attribute (ts=1000) and one new (ts=2000)
        event = _make_event_with_attributes(
            "1",
            2000,
            attributes=[
                {"id": "1", "timestamp": "1000", "value": "old"},
                {"id": "2", "timestamp": "2000", "value": "new"},
            ],
        )

        initial_state = {
            "last_event_date": last_event_iso,
            # No last_attribute_timestamp — simulates enabling the feature on existing connector
        }

        state, mock_process, result = _run_process_events(
            connector, [event], initial_state=initial_state
        )

        assert result is None
        # Event should still be processed (has attributes newer than fallback)
        assert mock_process.call_count == 1
        # State should now have last_attribute_timestamp set
        assert state.get("last_attribute_timestamp") == 2001

    def test_fallback_sends_metadata_when_all_attributes_older_than_last_event_date(
        self, mock_opencti_connector_helper, mock_py_misp
    ):
        """When using last_event_date as fallback, events with only old attributes
        still get processed for metadata updates (tags, galaxies, threat level)."""
        config_dict = deepcopy(minimal_config_dict)
        config_dict["misp"]["datetime_attribute"] = "publish_timestamp"
        config_dict["misp"]["attribute_timestamp_filtering"] = True
        connector = fake_misp_connector(config_dict)

        last_event_ts = 5000
        last_event_iso = datetime.fromtimestamp(
            last_event_ts, tz=timezone.utc
        ).isoformat()

        # All attributes are older than the fallback threshold
        event = _make_event_with_attributes(
            "1",
            6000,
            attributes=[
                {"id": "1", "timestamp": "1000", "value": "old1"},
                {"id": "2", "timestamp": "2000", "value": "old2"},
            ],
        )

        initial_state = {
            "last_event_date": last_event_iso,
        }

        state, mock_process, result = _run_process_events(
            connector, [event], initial_state=initial_state
        )

        assert result is None
        # Event should still be processed for metadata (tags, galaxies, threat level)
        # even though no attributes matched the filter
        assert mock_process.call_count == 1
        # First attribute kept as fallback for valid object_refs
        processed_event = mock_process.call_args[1]["event"]
        assert len(processed_event.Event.Attribute) == 1
        assert processed_event.Event.Attribute[0].value == "old1"

    def test_new_event_skips_filtering_when_not_in_opencti(
        self, mock_opencti_connector_helper, mock_py_misp
    ):
        """When the event's report does not exist in OpenCTI yet (first ingestion),
        attribute filtering is skipped entirely — all attributes are kept."""
        config_dict = deepcopy(minimal_config_dict)
        config_dict["misp"]["datetime_attribute"] = "publish_timestamp"
        config_dict["misp"]["attribute_timestamp_filtering"] = True
        connector = fake_misp_connector(config_dict)

        threshold = 5000
        # All attributes are older than the threshold
        event = _make_event_with_attributes(
            "1",
            6000,
            attributes=[
                {"id": "1", "timestamp": "1000", "value": "old1"},
                {"id": "2", "timestamp": "2000", "value": "old2"},
                {"id": "3", "timestamp": "3000", "value": "old3"},
            ],
        )

        initial_state = {
            "last_event_date": datetime.fromtimestamp(
                1000, tz=timezone.utc
            ).isoformat(),
            "last_attribute_timestamp": threshold,
        }

        state, mock_process, result = _run_process_events(
            connector,
            [event],
            initial_state=initial_state,
            event_already_ingested=False,
        )

        assert result is None
        assert mock_process.call_count == 1
        # All 3 attributes should be kept (no filtering applied)
        processed_event = mock_process.call_args[1]["event"]
        assert len(processed_event.Event.Attribute) == 3

    def test_fallback_attribute_does_not_regress_watermark(
        self, mock_opencti_connector_helper, mock_py_misp
    ):
        """When all attributes are filtered out, the fallback attribute's old
        timestamp must NOT lower the persisted last_attribute_timestamp."""
        config_dict = deepcopy(minimal_config_dict)
        config_dict["misp"]["datetime_attribute"] = "publish_timestamp"
        config_dict["misp"]["attribute_timestamp_filtering"] = True
        connector = fake_misp_connector(config_dict)

        threshold = 5000
        # All attributes are older than the threshold
        event = _make_event_with_attributes(
            "1",
            6000,
            attributes=[
                {"id": "1", "timestamp": "1000", "value": "old1"},
                {"id": "2", "timestamp": "2000", "value": "old2"},
            ],
        )

        initial_state = {
            "last_event_date": datetime.fromtimestamp(
                1000, tz=timezone.utc
            ).isoformat(),
            "last_attribute_timestamp": threshold,
        }

        state, mock_process, result = _run_process_events(
            connector, [event], initial_state=initial_state
        )

        assert result is None
        assert mock_process.call_count == 1
        # last_attribute_timestamp must NOT be regressed to 1000 or 2000
        # It should remain at the original threshold (no update)
        assert state.get("last_attribute_timestamp") == threshold


class TestAttributeFilteringEndToEnd:
    """End-to-end tests exercising the full pipeline (filter → converter → bundle)
    without mocking the converter. Validates the 3 scenarios:
    1. New event (first run, no filtering) → report + observables + galaxies
    2. Updated event with some new attributes → report + subset of observables + galaxies
    3. Metadata-only update (all attrs filtered) → report + galaxies, no observables
    """

    @staticmethod
    def _make_event_with_galaxy(
        event_id: str,
        event_ts: int,
        attributes: list[dict],
        galaxy_name: str = "APT28",
    ) -> EventRestSearchListItem:
        """Build an event with attributes and a threat-actor galaxy."""
        return EventRestSearchListItem.model_validate(
            {
                "Event": {
                    "id": event_id,
                    "uuid": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
                    "info": f"Test event {event_id}",
                    "date": "2026-01-15",
                    "timestamp": str(event_ts),
                    "publish_timestamp": str(event_ts),
                    "threat_level_id": "2",
                    "Orgc": {"name": "TestOrg"},
                    "Attribute": attributes,
                    "Object": [],
                    "Galaxy": [
                        {
                            "uuid": "11111111-2222-3333-4444-555555555555",
                            "name": "Threat Actor",
                            "type": "threat-actor",
                            "namespace": "misp",
                            "GalaxyCluster": [
                                {
                                    "uuid": "66666666-7777-8888-9999-aaaaaaaaaaaa",
                                    "value": galaxy_name,
                                    "description": f"The {galaxy_name} group",
                                    "meta": {
                                        "synonyms": [
                                            galaxy_name,
                                            f"{galaxy_name}-alias",
                                        ]
                                    },
                                }
                            ],
                        }
                    ],
                    "Tag": [
                        {
                            "id": "1",
                            "name": "tlp:amber",
                            "colour": "#FFC000",
                            "is_galaxy": False,
                        }
                    ],
                }
            }
        )

    @staticmethod
    def _ip_attribute(attr_id: str, timestamp: str, value: str) -> dict:
        return {
            "id": attr_id,
            "uuid": f"attr-uuid-{attr_id}",
            "type": "ip-dst",
            "category": "Network activity",
            "value": value,
            "timestamp": timestamp,
            "to_ids": True,
            "comment": "",
        }

    def test_new_event_full_processing(
        self, mock_opencti_connector_helper, mock_py_misp
    ):
        """Case 1: First run, no filtering — all attributes + galaxies in bundle."""
        config_dict = deepcopy(minimal_config_dict)
        config_dict["misp"]["attribute_timestamp_filtering"] = True
        config_dict["misp"]["create_indicators"] = True
        config_dict["misp"]["create_observables"] = True
        connector = fake_misp_connector(config_dict)

        ts = 1000
        event = self._make_event_with_galaxy(
            "1",
            ts,
            attributes=[
                self._ip_attribute("1", str(ts - 100), "1.2.3.4"),
                self._ip_attribute("2", str(ts), "5.6.7.8"),
            ],
        )

        # No filtering (first run) — call converter directly
        author, markings, bundle_objects = connector.converter.process(
            event=event, include_relationships=True
        )

        # Should have: author, observables/indicators, galaxy intrusion-set, report
        assert author is not None
        assert author.name == "TestOrg"

        stix_types = [obj["type"] for obj in bundle_objects]
        assert "report" in stix_types
        # Galaxy produces an intrusion-set
        assert "intrusion-set" in stix_types
        # Attributes produce observables (ipv4-addr)
        assert "ipv4-addr" in stix_types
        # Count IPs — should be 2
        ip_count = sum(1 for t in stix_types if t == "ipv4-addr")
        assert ip_count == 2

    def test_partial_attribute_update(
        self, mock_opencti_connector_helper, mock_py_misp
    ):
        """Case 2: Some attributes filtered, only new ones in bundle + galaxies."""
        config_dict = deepcopy(minimal_config_dict)
        config_dict["misp"]["attribute_timestamp_filtering"] = True
        config_dict["misp"]["create_indicators"] = True
        config_dict["misp"]["create_observables"] = True
        connector = fake_misp_connector(config_dict)

        ts_old = 1000
        ts_new = 2000
        threshold = 1500

        event = self._make_event_with_galaxy(
            "1",
            ts_new,
            attributes=[
                self._ip_attribute("1", str(ts_old), "1.2.3.4"),
                self._ip_attribute("2", str(ts_new), "5.6.7.8"),
            ],
        )

        # Apply filtering
        before, after = connector._filter_event_attributes_by_timestamp(
            event, threshold
        )
        assert before == 2
        assert after == 1

        # Run converter on filtered event
        author, markings, bundle_objects = connector.converter.process(
            event=event, include_relationships=True
        )

        stix_types = [obj["type"] for obj in bundle_objects]
        assert "report" in stix_types
        assert "intrusion-set" in stix_types
        # Only 1 IP should remain (5.6.7.8)
        ip_count = sum(1 for t in stix_types if t == "ipv4-addr")
        assert ip_count == 1
        # The remaining IP should be 5.6.7.8
        ips = [obj for obj in bundle_objects if obj["type"] == "ipv4-addr"]
        assert ips[0]["value"] == "5.6.7.8"

    def test_metadata_only_update_keeps_first_attribute_as_fallback(
        self, mock_opencti_connector_helper, mock_py_misp
    ):
        """Case 3: All attributes filtered — first attribute kept as fallback,
        report + galaxies + 1 observable (upsert no-op in OpenCTI)."""
        config_dict = deepcopy(minimal_config_dict)
        config_dict["misp"]["attribute_timestamp_filtering"] = True
        config_dict["misp"]["create_indicators"] = True
        config_dict["misp"]["create_observables"] = True
        connector = fake_misp_connector(config_dict)

        ts_old = 1000
        threshold = 2000

        event = self._make_event_with_galaxy(
            "1",
            threshold + 500,  # event.timestamp is recent (metadata changed)
            attributes=[
                self._ip_attribute("1", str(ts_old), "1.2.3.4"),
                self._ip_attribute("2", str(ts_old + 100), "5.6.7.8"),
            ],
        )

        # Apply filtering — all attrs are old, but first is kept as fallback
        before, after = connector._filter_event_attributes_by_timestamp(
            event, threshold
        )
        assert before == 2
        assert after == 0  # no attributes passed the filter
        # First attribute kept as fallback for valid object_refs
        assert len(event.Event.Attribute) == 1
        assert event.Event.Attribute[0].value == "1.2.3.4"

        # Run converter on event with fallback attribute
        author, markings, bundle_objects = connector.converter.process(
            event=event, include_relationships=True
        )

        stix_types = [obj["type"] for obj in bundle_objects]
        # Report is still produced
        assert "report" in stix_types
        # Galaxy intrusion-set is still produced
        assert "intrusion-set" in stix_types
        # Exactly 1 observable (the fallback attribute) — not 2
        ip_count = sum(1 for t in stix_types if t == "ipv4-addr")
        assert ip_count == 1
        # Report's object_refs should contain the galaxy intrusion-set
        report = next(obj for obj in bundle_objects if obj["type"] == "report")
        assert any(
            (
                ref.startswith("intrusion-set--")
                if isinstance(ref, str)
                else ref["type"] == "intrusion-set"
            )
            for ref in report["object_refs"]
        )

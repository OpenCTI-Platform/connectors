import datetime
import os
from unittest.mock import MagicMock, call

import freezegun
import pycti
import pytest
import stix2
from pydantic_settings import SettingsConfigDict
from shadowserver.config import ConnectorSettings
from shadowserver.connector import CustomConnector


class _ConnectorSettings(ConnectorSettings):
    model_config = SettingsConfigDict(env_file="", yaml_file="")


@pytest.mark.usefixtures("mock_config")
def test_connector_initialization() -> None:
    connector = CustomConnector(helper=MagicMock(), config=_ConnectorSettings())

    assert connector.config.shadowserver.api_key == "CHANGEME"
    assert connector.config.shadowserver.api_secret == "CHANGEME"
    assert connector.config.shadowserver.marking == "TLP:CLEAR"
    assert connector.config.shadowserver.create_incident == True
    assert connector.config.shadowserver.incident_priority == "P1"
    assert connector.config.shadowserver.incident_severity == "high"


@pytest.mark.usefixtures("mock_config")
@pytest.mark.parametrize(
    "create_incident, expected", [("false", False), ("true", True)]
)
def test_connector_initialization_create_incident(create_incident, expected) -> None:
    os.environ["SHADOWSERVER_CREATE_INCIDENT"] = create_incident

    connector = CustomConnector(helper=MagicMock(), config=_ConnectorSettings())

    assert connector.config.shadowserver.create_incident == expected
    assert connector.config.shadowserver.incident_priority == "P1"
    assert connector.config.shadowserver.incident_severity == "high"


@pytest.mark.usefixtures("mock_config")
def test_connector_initialization_default_incident() -> None:
    os.environ.pop("SHADOWSERVER_CREATE_INCIDENT")
    os.environ.pop("SHADOWSERVER_INCIDENT_SEVERITY")
    os.environ.pop("SHADOWSERVER_INCIDENT_PRIORITY")

    connector = CustomConnector(helper=MagicMock(), config=_ConnectorSettings())

    assert connector.config.shadowserver.create_incident == False
    assert connector.config.shadowserver.incident_priority == "P4"
    assert connector.config.shadowserver.incident_severity == "low"


@pytest.mark.usefixtures("mock_config")
@freezegun.freeze_time("2025-07-01T12:00:00Z")
@pytest.mark.parametrize(
    "state,is_first_run,lookback_days,last_run_log,data,expected_data_log,expect_send_bundle",
    [
        (
            {},  # No state
            True,
            30,
            "Test Connector connector has never run",
            [],
            "No data to send to OpenCTI.",
            False,
        ),
        (
            {
                "last_run": datetime.datetime(
                    2025, 6, 18, 12, 0, 0, tzinfo=datetime.timezone.utc
                ).timestamp()
            },
            False,
            16,
            "Test Connector connector last run @ 2025-06-18T12:00:00+00:00",
            [],
            "No data to send to OpenCTI.",
            False,
        ),
        (
            {},  # No state with data
            True,
            30,
            "Test Connector connector has never run",
            [
                stix2.Identity(
                    id=pycti.Identity.generate_id(
                        name="shadowserver", identity_class="organization"
                    ),
                    name="shadowserver",
                )
            ],
            "Sending 1 STIX objects to OpenCTI...",
            True,
        ),
    ],
)
def test_connector_run(
    mocked_helper,
    state,
    is_first_run,
    lookback_days,
    last_run_log,
    data,
    expected_data_log,
    expect_send_bundle,
) -> None:
    mocked_helper.get_state.return_value = state
    connector = CustomConnector(helper=mocked_helper, config=_ConnectorSettings())
    connector._collect_intelligence = MagicMock(return_value=data)

    with pytest.raises(SystemExit) as exc_info:
        connector.run()

    assert exc_info.value.code == 0  # RUN_AND_TERMINATE

    # Logs
    assert mocked_helper.connector_logger.info.call_args_list == [
        call(
            f"Connector initialized. Lookback: {lookback_days} days. First run: {str(is_first_run)}"
        ),
        call("Starting Test Connector connector..."),
        call("Running connector...", meta={"connector_name": "Test Connector"}),
        call(last_run_log),
        call("Test Connector will run!"),
        call(expected_data_log),
        call(
            "Test Connector connector successfully run, storing last_run as 1751371200"
        ),
        call("Last_run stored, next run in: 48.0 hours"),
        call("Test Connector connector ended"),
    ]

    # State
    assert mocked_helper.get_state.call_count == 3
    mocked_helper.set_state.assert_called_once_with({"last_run": 1751371200})

    # Work initiation
    mocked_helper.api.work.initiate_work.assert_called_once_with(
        mocked_helper.connect_id, "Test Connector run @ 2025-07-01T12:00:00+00:00"
    )

    # send_stix2_bundle conditional
    if expect_send_bundle:
        assert mocked_helper.send_stix2_bundle.call_args.kwargs == {
            "work_id": "work-id",
            "cleanup_inconsistent_bundle": True,
        }
    else:
        mocked_helper.send_stix2_bundle.assert_not_called()

    # Work processed
    mocked_helper.api.work.to_processed.assert_called_once_with(
        "work-id",
        "Test Connector connector successfully run, storing last_run as 1751371200",
    )

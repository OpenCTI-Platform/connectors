import datetime
import os
from unittest.mock import MagicMock, call

import freezegun
import pycti
import pytest
import stix2
from pydantic_settings import SettingsConfigDict
from shadowserver.connector import CustomConnector
from shadowserver.settings import ConnectorSettings


class _ConnectorSettings(ConnectorSettings):
    model_config = SettingsConfigDict(env_file="", yaml_file="")


@pytest.mark.usefixtures("mock_config")
def test_connector_initialization(mocked_helper) -> None:
    connector = CustomConnector(helper=mocked_helper, config=_ConnectorSettings())

    assert connector.config.shadowserver.api_key.get_secret_value() == "CHANGEME"
    assert connector.config.shadowserver.api_secret.get_secret_value() == "CHANGEME"
    assert connector.config.shadowserver.marking == "TLP:CLEAR"
    assert connector.config.shadowserver.create_incident == True
    assert connector.config.shadowserver.incident_priority == "P1"
    assert connector.config.shadowserver.incident_severity == "high"
    assert connector.config.shadowserver.report_types == [
        "scan_http",
        "open_dns_resolvers",
    ]
    assert connector.config.shadowserver.initial_lookback == 45
    assert connector.config.shadowserver.lookback == 7


@pytest.mark.usefixtures("mock_config")
@pytest.mark.parametrize(
    "create_incident, expected", [("false", False), ("true", True)]
)
def test_connector_initialization_create_incident(
    mocked_helper, create_incident, expected
) -> None:
    os.environ["SHADOWSERVER_CREATE_INCIDENT"] = create_incident

    connector = CustomConnector(helper=mocked_helper, config=_ConnectorSettings())

    assert connector.config.shadowserver.create_incident == expected
    assert connector.config.shadowserver.incident_priority == "P1"
    assert connector.config.shadowserver.incident_severity == "high"


@pytest.mark.usefixtures("mock_config")
def test_connector_initialization_default_incident(mocked_helper) -> None:
    os.environ.pop("SHADOWSERVER_CREATE_INCIDENT")
    os.environ.pop("SHADOWSERVER_INCIDENT_SEVERITY")
    os.environ.pop("SHADOWSERVER_INCIDENT_PRIORITY")

    connector = CustomConnector(helper=mocked_helper, config=_ConnectorSettings())

    assert connector.config.shadowserver.create_incident == False
    assert connector.config.shadowserver.incident_priority == "P4"
    assert connector.config.shadowserver.incident_severity == "low"


@pytest.mark.usefixtures("mock_config")
@freezegun.freeze_time("2025-07-01T12:00:00Z")
@pytest.mark.parametrize(
    "state,is_first_run,lookback_days,last_run_log,collected_data,expected_data_log,expect_send_bundle,date_str",
    [
        (
            {},  # No state
            True,
            45,
            "Test Connector connector has never run",
            [([], "2025-07-01")],
            "No data to send to OpenCTI for 2025-07-01.",
            False,
            "2025-07-01",
        ),
        (
            {
                "last_run": datetime.datetime(
                    2025, 6, 18, 12, 0, 0, tzinfo=datetime.timezone.utc
                ).timestamp()
            },
            False,
            20,
            "Test Connector connector last run @ 2025-06-18T12:00:00+00:00",
            [([], "2025-07-01")],
            "No data to send to OpenCTI for 2025-07-01.",
            False,
            "2025-07-01",
        ),
        (
            {},  # No state with data
            True,
            45,
            "Test Connector connector has never run",
            [
                (
                    [
                        stix2.Identity(
                            id=pycti.Identity.generate_id(
                                name="shadowserver", identity_class="organization"
                            ),
                            name="shadowserver",
                        )
                    ],
                    "2025-07-01",
                )
            ],
            "Sending 1 STIX objects to OpenCTI for 2025-07-01...",
            True,
            "2025-07-01",
        ),
    ],
)
def test_connector_run(
    mocked_helper,
    state,
    is_first_run,
    lookback_days,
    last_run_log,
    collected_data,
    expected_data_log,
    expect_send_bundle,
    date_str,
) -> None:
    mocked_helper.get_state.return_value = state
    connector = CustomConnector(helper=mocked_helper, config=_ConnectorSettings())
    connector._collect_intelligence = MagicMock(return_value=collected_data)

    connector.run()

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
            "Test Connector connector successfully run, storing last_run as 2025-07-01T12:00:00+00:00"
        ),
        call("Last_run stored, next run in: 2 days, 0:00:00"),
        call("Test Connector connector ended"),
    ]

    # State
    assert mocked_helper.get_state.call_count == 3
    mocked_helper.set_state.assert_called_once_with(
        state={"last_run": "2025-07-01T12:00:00+00:00"}
    )

    # send_stix2_bundle conditional
    if expect_send_bundle:
        assert mocked_helper.send_stix2_bundle.call_args.kwargs == {
            "work_id": "work-id",
            "cleanup_inconsistent_bundle": True,
        }
    else:
        mocked_helper.send_stix2_bundle.assert_not_called()

    # Work
    if expect_send_bundle:
        mocked_helper.api.work.initiate_work.assert_called_once_with(
            connector_id=mocked_helper.connect_id,
            friendly_name=f"Test Connector run @ 2025-07-01T12:00:00 for {date_str}",
        )
        mocked_helper.api.work.to_processed.assert_called_once_with(
            "work-id", f"Connector successfully run for {date_str}"
        )
    else:
        mocked_helper.api.work.initiate_work.assert_not_called()
        mocked_helper.api.work.to_processed.assert_not_called()

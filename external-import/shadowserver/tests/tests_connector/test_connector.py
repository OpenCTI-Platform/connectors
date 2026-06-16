import os
from unittest.mock import MagicMock

import freezegun
import pycti
import pytest
import stix2
from pydantic_settings import SettingsConfigDict
from shadowserver.dataprocessor import ShadowserverProcessor
from shadowserver.settings import ConnectorSettings


class _ConnectorSettings(ConnectorSettings):
    model_config = SettingsConfigDict(env_file="", yaml_file="")


def _create_processor(settings, helper, state=None):
    """Helper to create a ShadowserverProcessor with injected dependencies."""
    from connectors_sdk.states.states import ExternalImportConnectorState

    processor = ShadowserverProcessor()
    st = state if state is not None else ExternalImportConnectorState()
    processor.inject_dependencies(settings=settings, helper=helper, state=st)
    processor.post_init()
    return processor


@pytest.mark.usefixtures("mock_config")
def test_connector_initialization(mocked_helper) -> None:
    settings = _ConnectorSettings()
    processor = _create_processor(settings, mocked_helper)

    assert processor._config.api_key.get_secret_value() == "CHANGEME"
    assert processor._config.api_secret.get_secret_value() == "CHANGEME"
    assert processor._config.marking == "TLP:CLEAR"
    assert processor._config.create_incident == True
    assert processor._config.incident_priority == "P1"
    assert processor._config.incident_severity == "high"
    assert processor._config.report_types == [
        "scan_http",
        "open_dns_resolvers",
    ]
    assert processor._config.report_names == ["company"]
    assert processor._config.initial_lookback == 45
    assert processor._config.lookback == 7


@pytest.mark.usefixtures("mock_config")
@pytest.mark.parametrize(
    "create_incident, expected", [("false", False), ("true", True)]
)
def test_connector_initialization_create_incident(
    mocked_helper, create_incident, expected
) -> None:
    os.environ["SHADOWSERVER_CREATE_INCIDENT"] = create_incident

    settings = _ConnectorSettings()
    processor = _create_processor(settings, mocked_helper)

    assert processor._config.create_incident == expected
    assert processor._config.incident_priority == "P1"
    assert processor._config.incident_severity == "high"


@pytest.mark.usefixtures("mock_config")
def test_connector_initialization_default_incident(mocked_helper) -> None:
    os.environ.pop("SHADOWSERVER_CREATE_INCIDENT")
    os.environ.pop("SHADOWSERVER_INCIDENT_SEVERITY")
    os.environ.pop("SHADOWSERVER_INCIDENT_PRIORITY")

    settings = _ConnectorSettings()
    processor = _create_processor(settings, mocked_helper)

    assert processor._config.create_incident == False
    assert processor._config.incident_priority == "P4"
    assert processor._config.incident_severity == "low"


@pytest.mark.usefixtures("mock_config")
@freezegun.freeze_time("2025-07-01T12:00:00Z")
def test_collect_intelligence_passes_report_names_and_types(
    mocked_helper, mocker
) -> None:
    """Test transform passes report_names and report_types to the API."""
    from connectors_sdk.states.states import ExternalImportConnectorState

    # Override initial_lookback to 0 so only a single day is processed
    os.environ["SHADOWSERVER_INITIAL_LOOKBACK"] = "0"
    settings = _ConnectorSettings()
    state = ExternalImportConnectorState()
    processor = _create_processor(settings, mocked_helper, state=state)

    expected_stix = stix2.Identity(
        id=pycti.Identity.generate_id(name="test", identity_class="organization"),
        name="test",
    )

    mock_api_instance = MagicMock()
    mock_api_instance.get_report_list.return_value = [
        {"id": "report-1", "report": "scan_http"}
    ]
    mock_api_instance.get_report_data.return_value = [{"ip": "1.2.3.4"}]
    mocker.patch(
        "shadowserver.dataprocessor.ShadowserverAPI", return_value=mock_api_instance
    )

    mock_transform = MagicMock()
    mock_transform.return_value.get_stix_objects.return_value = [expected_stix]
    mocker.patch(
        "shadowserver.dataprocessor.ShadowserverStixTransformation", mock_transform
    )

    data = processor.collect()
    results = list(processor.transform(data))

    # Verify report_names and report_types are passed to get_report_list
    mock_api_instance.get_report_list.assert_called_once_with(
        date="2025-07-01",
        reports=["company"],
        type=["scan_http", "open_dns_resolvers"],
    )

    # Verify results are yielded
    assert len(results) == 1
    assert len(results[0]) == 1


@pytest.mark.usefixtures("mock_config")
@freezegun.freeze_time("2025-07-01T12:00:00Z")
def test_transform_yields_per_report(mocked_helper, mocker) -> None:
    """Test that transform yields one list per report (not accumulated per day)."""
    from connectors_sdk.states.states import ExternalImportConnectorState

    # Override initial_lookback to 0 so only a single day is processed
    os.environ["SHADOWSERVER_INITIAL_LOOKBACK"] = "0"
    settings = _ConnectorSettings()
    state = ExternalImportConnectorState()
    processor = _create_processor(settings, mocked_helper, state=state)

    identity1 = stix2.Identity(
        id=pycti.Identity.generate_id(name="test1", identity_class="organization"),
        name="test1",
    )
    identity2 = stix2.Identity(
        id=pycti.Identity.generate_id(name="test2", identity_class="organization"),
        name="test2",
    )

    mock_api_instance = MagicMock()
    mock_api_instance.get_report_list.return_value = [
        {"id": "report-1", "report": "scan_http"},
        {"id": "report-2", "report": "open_dns_resolvers"},
    ]
    mock_api_instance.get_report_data.side_effect = [
        [{"ip": "1.2.3.4"}],
        [{"ip": "5.6.7.8"}],
    ]
    mocker.patch(
        "shadowserver.dataprocessor.ShadowserverAPI", return_value=mock_api_instance
    )

    mock_transform = MagicMock()
    mock_transform.side_effect = [
        MagicMock(**{"get_stix_objects.return_value": [identity1]}),
        MagicMock(**{"get_stix_objects.return_value": [identity2]}),
    ]
    mocker.patch(
        "shadowserver.dataprocessor.ShadowserverStixTransformation", mock_transform
    )

    data = processor.collect()
    results = list(processor.transform(data))

    # Should yield 2 separate lists (one per report), not one combined list
    assert len(results) == 2
    all_stix = [item for bundle in results for item in bundle]
    assert sorted(all_stix, key=lambda x: x.name) == sorted(
        [identity1, identity2], key=lambda x: x.name
    )


@pytest.mark.usefixtures("mock_config")
@freezegun.freeze_time("2025-07-01T12:00:00Z")
def test_collect_skips_day_with_no_reports(mocked_helper, mocker) -> None:
    """Test that collect skips days with no reports."""
    from connectors_sdk.states.states import ExternalImportConnectorState

    os.environ["SHADOWSERVER_INITIAL_LOOKBACK"] = "0"
    settings = _ConnectorSettings()
    processor = _create_processor(
        settings, mocked_helper, state=ExternalImportConnectorState()
    )

    mock_api_instance = MagicMock()
    mock_api_instance.get_report_list.return_value = []
    mocker.patch(
        "shadowserver.dataprocessor.ShadowserverAPI", return_value=mock_api_instance
    )

    results = list(processor.collect())

    assert results == []


@pytest.mark.usefixtures("mock_config")
@freezegun.freeze_time("2025-07-01T12:00:00Z")
def test_collect_skips_report_with_empty_rows(mocked_helper, mocker) -> None:
    """Test that collect skips reports whose download returns no rows."""
    from connectors_sdk.states.states import ExternalImportConnectorState

    os.environ["SHADOWSERVER_INITIAL_LOOKBACK"] = "0"
    settings = _ConnectorSettings()
    processor = _create_processor(
        settings, mocked_helper, state=ExternalImportConnectorState()
    )

    mock_api_instance = MagicMock()
    mock_api_instance.get_report_list.return_value = [{"id": "report-1"}]
    mock_api_instance.get_report_data.return_value = []
    mocker.patch(
        "shadowserver.dataprocessor.ShadowserverAPI", return_value=mock_api_instance
    )

    results = list(processor.collect())

    assert results == []


@pytest.mark.usefixtures("mock_config")
@freezegun.freeze_time("2025-07-01T12:00:00Z")
def test_collect_handles_download_exception(mocked_helper, mocker) -> None:
    """Test that collect logs and skips a report when the download raises."""
    from connectors_sdk.states.states import ExternalImportConnectorState

    os.environ["SHADOWSERVER_INITIAL_LOOKBACK"] = "0"
    settings = _ConnectorSettings()
    processor = _create_processor(
        settings, mocked_helper, state=ExternalImportConnectorState()
    )

    mock_api_instance = MagicMock()
    mock_api_instance.get_report_list.return_value = [{"id": "report-1"}]
    mock_api_instance.get_report_data.side_effect = RuntimeError("network error")
    mocker.patch(
        "shadowserver.dataprocessor.ShadowserverAPI", return_value=mock_api_instance
    )

    results = list(processor.collect())

    assert results == []


@pytest.mark.usefixtures("mock_config")
@freezegun.freeze_time("2025-07-01T12:00:00Z")
def test_transform_skips_empty_stix_bundle(mocked_helper, mocker) -> None:
    """Test that transform skips a report when ShadowserverStixTransformation returns no objects."""
    from connectors_sdk.states.states import ExternalImportConnectorState

    os.environ["SHADOWSERVER_INITIAL_LOOKBACK"] = "0"
    settings = _ConnectorSettings()
    processor = _create_processor(
        settings, mocked_helper, state=ExternalImportConnectorState()
    )

    mock_api_instance = MagicMock()
    mock_api_instance.get_report_list.return_value = [{"id": "report-1"}]
    mock_api_instance.get_report_data.return_value = [{"ip": "1.2.3.4"}]
    mocker.patch(
        "shadowserver.dataprocessor.ShadowserverAPI", return_value=mock_api_instance
    )

    mock_transform = MagicMock()
    mock_transform.return_value.get_stix_objects.return_value = []
    mocker.patch(
        "shadowserver.dataprocessor.ShadowserverStixTransformation", mock_transform
    )

    data = processor.collect()
    results = list(processor.transform(data))

    assert results == []


@pytest.mark.usefixtures("mock_config")
@freezegun.freeze_time("2025-07-01T12:00:00Z")
def test_transform_handles_exception(mocked_helper, mocker) -> None:
    """Test that transform logs and skips a report when ShadowserverStixTransformation raises."""
    from connectors_sdk.states.states import ExternalImportConnectorState

    os.environ["SHADOWSERVER_INITIAL_LOOKBACK"] = "0"
    settings = _ConnectorSettings()
    processor = _create_processor(
        settings, mocked_helper, state=ExternalImportConnectorState()
    )

    mock_api_instance = MagicMock()
    mock_api_instance.get_report_list.return_value = [{"id": "report-1"}]
    mock_api_instance.get_report_data.return_value = [{"ip": "1.2.3.4"}]
    mocker.patch(
        "shadowserver.dataprocessor.ShadowserverAPI", return_value=mock_api_instance
    )

    mock_transform = MagicMock()
    mock_transform.side_effect = RuntimeError("transform error")
    mocker.patch(
        "shadowserver.dataprocessor.ShadowserverStixTransformation", mock_transform
    )

    data = processor.collect()
    results = list(processor.transform(data))

    assert results == []


@pytest.mark.usefixtures("mock_config")
@freezegun.freeze_time("2025-07-01T12:00:00Z")
def test_get_lookback_uses_last_run(mocked_helper) -> None:
    """Test that _get_lookback computes from state.last_run when available."""
    import datetime as dt

    from connectors_sdk.states.states import ExternalImportConnectorState

    os.environ["SHADOWSERVER_INITIAL_LOOKBACK"] = "45"
    settings = _ConnectorSettings()
    state = ExternalImportConnectorState()
    state.last_run = dt.datetime(
        2025, 6, 24, 12, 0, 0, tzinfo=dt.timezone.utc
    )  # 7 days ago
    processor = _create_processor(settings, mocked_helper, state=state)

    # lookback config = 7, days since last_run = 7 → result = 14
    assert processor._get_lookback() == 14

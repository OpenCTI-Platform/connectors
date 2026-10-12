from unittest.mock import MagicMock

import pytest
from connectors_sdk import ConfigValidationError
from connectors_sdk.connectors.stream.deployment import DeploymentAssuranceOptions
from settings import ConnectorSettings
from splunk_deployment import build_deployment_assurance


def test_settings_load_the_existing_variables(splunk_environment):
    settings = ConnectorSettings()

    assert str(settings.splunk.url) == "https://splunk.test:8089/"
    assert settings.splunk.token.get_secret_value() == "splunk-token"
    assert settings.splunk.kv_store_name == "opencti"
    assert settings.connector.consumer_count == 10
    assert isinstance(settings.to_helper_config(), dict)


def test_deployment_settings_defaults(splunk_environment):
    settings = ConnectorSettings()

    assert settings.splunk.hits_saved_search is None
    assert DeploymentAssuranceOptions.from_settings(
        settings
    ) == DeploymentAssuranceOptions(
        security_platform_name="Splunk",
        security_platform_type="SIEM",
        security_platform_id=None,
        reporting_enabled=True,
        reconciliation_interval=60,
        hits_reporting_enabled=True,
    )


def test_deployment_settings_from_environment(splunk_environment, monkeypatch):
    monkeypatch.setenv("DEPLOYMENT_REPORTING_ENABLED", "false")
    monkeypatch.setenv("DEPLOYMENT_RECONCILIATION_INTERVAL", "15")
    monkeypatch.setenv("HITS_REPORTING_ENABLED", "false")
    monkeypatch.setenv("SECURITY_PLATFORM_NAME", "Splunk Enterprise Security")
    monkeypatch.setenv("SECURITY_PLATFORM_TYPE", "SOAR")
    monkeypatch.setenv("SECURITY_PLATFORM_ID", "platform-id")
    monkeypatch.setenv("SPLUNK_HITS_SAVED_SEARCH", "OpenCTI indicator matches")

    settings = ConnectorSettings()

    assert settings.splunk.hits_saved_search == "OpenCTI indicator matches"
    assert DeploymentAssuranceOptions.from_settings(
        settings
    ) == DeploymentAssuranceOptions(
        security_platform_name="Splunk Enterprise Security",
        security_platform_type="SOAR",
        security_platform_id="platform-id",
        reporting_enabled=False,
        reconciliation_interval=15,
        hits_reporting_enabled=False,
    )


def test_deployment_settings_reject_a_negative_interval(
    splunk_environment, monkeypatch
):
    monkeypatch.setenv("DEPLOYMENT_RECONCILIATION_INTERVAL", "-1")

    with pytest.raises(ConfigValidationError):
        ConnectorSettings()


def test_config_schema_documents_the_deployment_variables():
    schema = ConnectorSettings.config_json_schema(connector_name="splunk")
    properties = schema["properties"]

    assert properties["DEPLOYMENT_REPORTING_ENABLED"]["default"] is True
    assert properties["DEPLOYMENT_RECONCILIATION_INTERVAL"]["default"] == 60
    assert properties["HITS_REPORTING_ENABLED"]["default"] is True
    assert properties["SECURITY_PLATFORM_NAME"]["default"] == "Splunk"
    assert properties["SECURITY_PLATFORM_TYPE"]["default"] == "SIEM"
    assert properties["SECURITY_PLATFORM_ID"]["default"] is None
    assert properties["SPLUNK_HITS_SAVED_SEARCH"]["default"] is None
    assert not {
        "DEPLOYMENT_REPORTING_ENABLED",
        "SECURITY_PLATFORM_NAME",
        "SPLUNK_HITS_SAVED_SEARCH",
    } & set(schema["required"])


def test_build_deployment_assurance_with_hits(splunk_environment, monkeypatch):
    monkeypatch.setenv("SPLUNK_HITS_SAVED_SEARCH", "OpenCTI indicator matches")
    helper = MagicMock()
    push = MagicMock()

    assurance = build_deployment_assurance(
        helper, ConnectorSettings(), MagicMock(), push
    )

    assert assurance.enabled is True
    assert assurance.reporter.hits_enabled is True
    assert assurance.reconciler is not None
    assert assurance.reconciler._adapter.hits_supported is True
    helper.log_info.assert_not_called()


def test_build_deployment_assurance_without_saved_search_logs_it(
    splunk_environment,
):
    helper = MagicMock()

    assurance = build_deployment_assurance(
        helper, ConnectorSettings(), MagicMock(), MagicMock()
    )

    assert assurance.reconciler._adapter.hits_supported is False
    helper.log_info.assert_called_once_with(
        "hits are not collected (SPLUNK_HITS_SAVED_SEARCH is not configured)"
    )


def test_build_deployment_assurance_disabled(splunk_environment, monkeypatch):
    monkeypatch.setenv("DEPLOYMENT_REPORTING_ENABLED", "false")
    helper = MagicMock()

    assurance = build_deployment_assurance(
        helper, ConnectorSettings(), MagicMock(), MagicMock()
    )

    assert assurance.enabled is False
    assert assurance.start() is False
    helper.log_info.assert_not_called()
    helper.api.query.assert_not_called()

# pragma: no cover  # do not compute coverage on test files
# type: ignore
"""Tests of the deployment write-back settings."""

from types import SimpleNamespace

import pytest
from connectors_sdk.connectors.stream.deployment.settings import (
    DeploymentAssuranceOptions,
    DeploymentConfig,
    HitsConfig,
    SecurityPlatformConfig,
)
from connectors_sdk.settings.base_settings import (
    BaseConnectorSettings,
    BaseStreamConnectorConfig,
)
from connectors_sdk.settings.exceptions import ConfigValidationError
from pydantic import Field, ValidationError


class _StreamConfig(BaseStreamConnectorConfig):
    live_stream_id: str = Field(default="live", description="Stream id.")


class _TestSecurityPlatformConfig(SecurityPlatformConfig):
    name: str = Field(default="Test EDR", min_length=2, description="Platform name.")
    type: str | None = Field(default="EDR", description="Platform type.")


class _TestSettings(BaseConnectorSettings):
    connector: _StreamConfig = Field(default_factory=_StreamConfig)
    deployment: DeploymentConfig = Field(default_factory=DeploymentConfig)
    hits: HitsConfig = Field(default_factory=HitsConfig)
    security_platform: _TestSecurityPlatformConfig = Field(
        default_factory=_TestSecurityPlatformConfig
    )


@pytest.fixture
def stream_environment(monkeypatch):
    """Minimal environment of a stream connector."""
    monkeypatch.setenv("OPENCTI_URL", "http://localhost:8080")
    monkeypatch.setenv("OPENCTI_TOKEN", "changeme")
    monkeypatch.setenv("CONNECTOR_ID", "connector--test")
    monkeypatch.setenv("CONNECTOR_NAME", "Test Stream")
    monkeypatch.setenv("CONNECTOR_SCOPE", "test")
    for name in (
        "DEPLOYMENT_REPORTING_ENABLED",
        "DEPLOYMENT_RECONCILIATION_INTERVAL",
        "HITS_REPORTING_ENABLED",
        "SECURITY_PLATFORM_NAME",
        "SECURITY_PLATFORM_TYPE",
        "SECURITY_PLATFORM_ID",
    ):
        monkeypatch.delenv(name, raising=False)


def test_config_defaults():
    """Defaults follow the contract."""
    deployment = DeploymentConfig()
    assert deployment.reporting_enabled is True
    assert deployment.reconciliation_interval == 60
    assert HitsConfig().reporting_enabled is True
    platform = SecurityPlatformConfig(name="My EDR")
    assert platform.type is None
    assert platform.id is None


def test_config_validation():
    """Invalid values are rejected."""
    with pytest.raises(ValidationError):
        DeploymentConfig(reconciliation_interval=-1)
    with pytest.raises(ValidationError):
        SecurityPlatformConfig(name="x")
    with pytest.raises(ValidationError):
        SecurityPlatformConfig()


def test_settings_default_values(stream_environment):
    """Connector settings expose the defaults of the connector."""
    options = DeploymentAssuranceOptions.from_settings(_TestSettings())
    assert options == DeploymentAssuranceOptions(
        security_platform_name="Test EDR",
        security_platform_type="EDR",
        security_platform_id=None,
        reporting_enabled=True,
        reconciliation_interval=60,
        hits_reporting_enabled=True,
    )


def test_settings_environment_variables(stream_environment, monkeypatch):
    """The documented environment variables configure the write-back."""
    monkeypatch.setenv("DEPLOYMENT_REPORTING_ENABLED", "false")
    monkeypatch.setenv("DEPLOYMENT_RECONCILIATION_INTERVAL", "15")
    monkeypatch.setenv("HITS_REPORTING_ENABLED", "false")
    monkeypatch.setenv("SECURITY_PLATFORM_NAME", "Production EDR")
    monkeypatch.setenv("SECURITY_PLATFORM_TYPE", "XDR")
    monkeypatch.setenv("SECURITY_PLATFORM_ID", "platform-id")

    options = DeploymentAssuranceOptions.from_settings(_TestSettings())

    assert options == DeploymentAssuranceOptions(
        security_platform_name="Production EDR",
        security_platform_type="XDR",
        security_platform_id="platform-id",
        reporting_enabled=False,
        reconciliation_interval=15,
        hits_reporting_enabled=False,
    )


def test_settings_reject_a_negative_interval(stream_environment, monkeypatch):
    """A negative reconciliation interval is a configuration error."""
    monkeypatch.setenv("DEPLOYMENT_RECONCILIATION_INTERVAL", "-5")
    with pytest.raises(ConfigValidationError):
        _TestSettings()


def test_settings_json_schema_lists_the_variables():
    """The generated config schema documents the six variables."""
    schema = _TestSettings.config_json_schema(connector_name="test-stream")
    properties = schema["properties"]
    assert properties["DEPLOYMENT_REPORTING_ENABLED"]["default"] is True
    assert properties["DEPLOYMENT_RECONCILIATION_INTERVAL"]["default"] == 60
    assert properties["DEPLOYMENT_RECONCILIATION_INTERVAL"]["minimum"] == 0
    assert properties["HITS_REPORTING_ENABLED"]["default"] is True
    assert properties["SECURITY_PLATFORM_NAME"]["default"] == "Test EDR"
    assert properties["SECURITY_PLATFORM_TYPE"]["default"] == "EDR"
    assert properties["SECURITY_PLATFORM_ID"]["default"] is None
    assert "SECURITY_PLATFORM_NAME" not in schema["required"]


def test_from_settings_without_optional_namespaces():
    """Missing ``deployment`` uses defaults and missing ``hits`` disables hits."""
    settings = SimpleNamespace(security_platform=SecurityPlatformConfig(name="My EDR"))
    options = DeploymentAssuranceOptions.from_settings(settings)
    assert options.reporting_enabled is True
    assert options.reconciliation_interval == 60
    assert options.hits_reporting_enabled is False
    assert options.security_platform_type is None


def test_from_settings_requires_a_security_platform_namespace():
    """Settings without ``security_platform`` cannot report deployments."""
    with pytest.raises(ValueError, match="security_platform"):
        DeploymentAssuranceOptions.from_settings(SimpleNamespace())


def test_from_configs_ignores_empty_platform_type_and_id():
    """Empty type and id are treated as not configured."""
    options = DeploymentAssuranceOptions.from_configs(
        deployment=DeploymentConfig(),
        security_platform=SecurityPlatformConfig(name="My EDR", type="", id=""),
        hits=HitsConfig(reporting_enabled=False),
    )
    assert options.security_platform_type is None
    assert options.security_platform_id is None
    assert options.hits_reporting_enabled is False


def test_from_legacy_config_defaults(monkeypatch, stream_environment):
    """Legacy connectors get the connector defaults."""
    options = DeploymentAssuranceOptions.from_legacy_config(
        None, default_platform_name="Elastic Security", default_platform_type="SIEM"
    )
    assert options == DeploymentAssuranceOptions(
        security_platform_name="Elastic Security",
        security_platform_type="SIEM",
        hits_reporting_enabled=True,
    )


def test_from_legacy_config_reads_config_yml_then_environment(
    monkeypatch, stream_environment
):
    """Environment variables take precedence over ``config.yml`` values."""
    config = {
        "deployment": {"reporting_enabled": True, "reconciliation_interval": 30},
        "hits": {"reporting_enabled": False},
        "security_platform": {"name": "Elastic Prod", "type": "SIEM", "id": None},
        "opencti": "not a namespace",
    }
    monkeypatch.setenv("DEPLOYMENT_RECONCILIATION_INTERVAL", "0")
    monkeypatch.setenv("SECURITY_PLATFORM_ID", "platform-id")

    options = DeploymentAssuranceOptions.from_legacy_config(
        config, default_platform_name="Elastic Security", default_platform_type="SIEM"
    )

    assert options == DeploymentAssuranceOptions(
        security_platform_name="Elastic Prod",
        security_platform_type="SIEM",
        security_platform_id="platform-id",
        reporting_enabled=True,
        reconciliation_interval=0,
        hits_reporting_enabled=False,
    )


def test_from_legacy_config_without_hits_support(stream_environment, monkeypatch):
    """Connectors that cannot read hits never report them."""
    monkeypatch.setenv("HITS_REPORTING_ENABLED", "true")
    options = DeploymentAssuranceOptions.from_legacy_config(
        {"security_platform": "not a mapping"},
        default_platform_name="Zscaler",
        default_platform_type="NDR",
        hits_supported=False,
    )
    assert options.hits_reporting_enabled is False
    assert options.security_platform_name == "Zscaler"


def test_from_legacy_config_validates_values(stream_environment, monkeypatch):
    """Legacy values are validated like SDK settings."""
    monkeypatch.setenv("DEPLOYMENT_RECONCILIATION_INTERVAL", "soon")
    with pytest.raises(ValidationError):
        DeploymentAssuranceOptions.from_legacy_config(
            None, default_platform_name="Elastic Security"
        )

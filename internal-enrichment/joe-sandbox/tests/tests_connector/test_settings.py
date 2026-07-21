from typing import Any

import pytest
from connector import ConnectorSettings
from connectors_sdk import BaseConfigModel, ConfigValidationError


@pytest.mark.parametrize(
    "settings_dict",
    [
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                "connector": {
                    "id": "connector-id",
                    "name": "Test Connector",
                    "scope": "test, connector",
                    "log_level": "error",
                    "auto": True,
                },
                "joe_sandbox": {
                    "report_types": "executive,html,iochtml,iocjson,iocxml,unpackpe,stix,ida,pdf,pdfexecutive,misp,pcap,maec,memdumps,json,lightjsonfixed,xml,lightxml,pcapunified,pcapsslinspection",
                    "api_url": "https://jbxcloud.joesecurity.org/api",
                    "api_key": "test-api-key",
                    "analysis_url": "https://jbxcloud.joesecurity.org/analysis",
                    "accept_tac": True,
                    "api_timeout": 30,
                    "verify_ssl": True,
                    "api_retries": 5,
                    "proxies": None,
                    "user_agent": "OpenCTI",
                    "systems": "w10x64_office",
                    "analysis_time": 300,
                    "internet_access": True,
                    "internet_simulation": False,
                    "hybrid_code_analysis": True,
                    "hybrid_decompilation": True,
                    "report_cache": False,
                    "apk_instrumentation": True,
                    "amsi_unpacking": True,
                    "ssl_inspection": True,
                    "vba_instrumentation": False,
                    "js_instrumentation": False,
                    "java_jar_tracing": False,
                    "dotnet_tracing": False,
                    "start_as_normal_user": False,
                    "system_date": None,
                    "language_and_locale": None,
                    "localized_internet_country": None,
                    "email_notification": None,
                    "archive_no_unpack": False,
                    "hypervisor_based_inspection": False,
                    "fast_mode": False,
                    "secondary_results": True,
                    "cookbook_file_path": None,
                    "document_password": "1234",
                    "archive_password": "infected",
                    "command_line_argument": None,
                    "encrypt_with_password": None,
                    "browser": False,
                    "url_reputation": False,
                    "export_to_jbxview": False,
                    "delete_after_days": 30,
                    "priority": None,
                    "default_tlp": "TLP:CLEAR",
                    "yara_color": "#0059f7",
                    "default_color": "#54483b",
                },
            },
            id="full_valid_settings_dict",
        ),
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                "connector": {"id": "connector-id", "scope": "test, connector"},
                "joe_sandbox": {
                    "report_types": "executive,html,iochtml,iocjson,iocxml,unpackpe,stix,ida,pdf,pdfexecutive,misp,pcap,maec,memdumps,json,lightjsonfixed,xml,lightxml,pcapunified,pcapsslinspection",
                    "api_url": "https://jbxcloud.joesecurity.org/api",
                    "api_key": "test-api-key",
                    "analysis_url": "https://jbxcloud.joesecurity.org/analysis",
                    "accept_tac": True,
                    "api_timeout": 30,
                    "verify_ssl": True,
                    "api_retries": 5,
                    "user_agent": "OpenCTI",
                    "systems": "w10x64_office",
                    "analysis_time": 300,
                    "internet_access": True,
                    "internet_simulation": False,
                    "hybrid_code_analysis": True,
                    "hybrid_decompilation": True,
                    "report_cache": False,
                    "apk_instrumentation": True,
                    "amsi_unpacking": True,
                    "ssl_inspection": True,
                    "vba_instrumentation": False,
                    "js_instrumentation": False,
                    "java_jar_tracing": False,
                    "dotnet_tracing": False,
                    "start_as_normal_user": False,
                    "archive_no_unpack": False,
                    "fast_mode": False,
                    "secondary_results": True,
                    "document_password": "1234",
                    "archive_password": "infected",
                    "browser": False,
                    "url_reputation": False,
                    "export_to_jbxview": False,
                    "delete_after_days": 30,
                    "default_tlp": "TLP:CLEAR",
                    "yara_color": "#0059f7",
                    "default_color": "#54483b",
                },
            },
            id="minimal_valid_settings_dict",
        ),
        # ``proxies`` may legitimately carry a JSON-encoded scheme->URL
        # map. The validator on ``JoeSandboxConfig.proxies`` decodes
        # the string at validation time only to verify shape (not to
        # mutate the stored value), so the manager-facing JSON schema
        # keeps its ``"type": "string"`` shape and the runtime keeps
        # re-decoding the string before passing to ``jbxapi``.
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                "connector": {
                    "id": "connector-id",
                    "name": "Test Connector",
                    "scope": "test, connector",
                    "log_level": "error",
                    "auto": True,
                },
                "joe_sandbox": {
                    "api_url": "https://jbxcloud.joesecurity.org/api",
                    "api_key": "test-api-key",
                    "analysis_url": "https://jbxcloud.joesecurity.org/analysis",
                    "proxies": (
                        '{"http": "http://proxy:8080", "https": "http://proxy:8080"}'
                    ),
                },
            },
            id="valid_settings_dict_with_proxies",
        ),
    ],
)
def test_settings_should_accept_valid_input(settings_dict):
    """
    Test that `ConnectorSettings` (implementation of `BaseConnectorSettings` from `connectors-sdk`) accepts valid input.
    For the test purpose, `BaseConnectorSettings._load_config_dict` is overridden to return
    a fake but valid dict (instead of the env/config vars parsed from `config.yml`, `.env` or env vars).

    :param settings_dict: The dict to use as `ConnectorSettings` input
    """

    class FakeConnectorSettings(ConnectorSettings):
        """
        Subclass of `ConnectorSettings` (implementation of `BaseConnectorSettings`) for testing purpose.
        It overrides `BaseConnectorSettings._load_config_dict` to return a fake but valid config dict.
        """

        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(settings_dict)

    settings = FakeConnectorSettings()
    assert isinstance(settings.opencti, BaseConfigModel) is True
    assert isinstance(settings.connector, BaseConfigModel) is True
    assert isinstance(settings.joe_sandbox, BaseConfigModel) is True


@pytest.mark.parametrize(
    "settings_dict, field_name",
    [
        # With an empty dict, ``_OpenCTIConfig`` is the first to fail because
        # its ``url`` and ``token`` fields have no defaults; pydantic surfaces
        # those nested fields (rather than the ``opencti`` parent) when the
        # default_factory raises.
        pytest.param({}, "url", id="empty_settings_dict"),
        pytest.param(
            {
                "opencti": {"url": "http://localhost:PORT", "token": "test-token"},
                "connector": {
                    "id": "connector-id",
                    "name": "Test Connector",
                    "scope": "test, connector",
                    "log_level": "error",
                    "auto": True,
                },
                "joe_sandbox": {
                    "report_types": "executive,html,iochtml,iocjson,iocxml,unpackpe,stix,ida,pdf,pdfexecutive,misp,pcap,maec,memdumps,json,lightjsonfixed,xml,lightxml,pcapunified,pcapsslinspection",
                    "api_url": "https://jbxcloud.joesecurity.org/api",
                    "api_key": "test-api-key",
                    "analysis_url": "https://jbxcloud.joesecurity.org/analysis",
                    "accept_tac": True,
                    "api_timeout": 30,
                    "verify_ssl": True,
                    "api_retries": 5,
                    "proxies": None,
                    "user_agent": "OpenCTI",
                    "systems": "w10x64_office",
                    "analysis_time": 300,
                    "internet_access": True,
                    "internet_simulation": False,
                    "hybrid_code_analysis": True,
                    "hybrid_decompilation": True,
                    "report_cache": False,
                    "apk_instrumentation": True,
                    "amsi_unpacking": True,
                    "ssl_inspection": True,
                    "vba_instrumentation": False,
                    "js_instrumentation": False,
                    "java_jar_tracing": False,
                    "dotnet_tracing": False,
                    "start_as_normal_user": False,
                    "system_date": None,
                    "language_and_locale": None,
                    "localized_internet_country": None,
                    "email_notification": None,
                    "archive_no_unpack": False,
                    "hypervisor_based_inspection": False,
                    "fast_mode": False,
                    "secondary_results": True,
                    "cookbook_file_path": None,
                    "document_password": "1234",
                    "archive_password": "infected",
                    "command_line_argument": None,
                    "encrypt_with_password": None,
                    "browser": False,
                    "url_reputation": False,
                    "export_to_jbxview": False,
                    "delete_after_days": 30,
                    "priority": None,
                    "default_tlp": "TLP:CLEAR",
                    "yara_color": "#0059f7",
                    "default_color": "#54483b",
                },
            },
            "opencti.url",
            id="invalid_opencti_url",
        ),
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                "connector": {
                    "name": "Test Connector",
                    "scope": "test, connector",
                    "log_level": "error",
                    "auto": True,
                },
                "joe_sandbox": {
                    "report_types": "executive,html,iochtml,iocjson,iocxml,unpackpe,stix,ida,pdf,pdfexecutive,misp,pcap,maec,memdumps,json,lightjsonfixed,xml,lightxml,pcapunified,pcapsslinspection",
                    "api_url": "https://jbxcloud.joesecurity.org/api",
                    "api_key": "test-api-key",
                    "analysis_url": "https://jbxcloud.joesecurity.org/analysis",
                    "accept_tac": True,
                    "api_timeout": 30,
                    "verify_ssl": True,
                    "api_retries": 5,
                    "proxies": None,
                    "user_agent": "OpenCTI",
                    "systems": "w10x64_office",
                    "analysis_time": 300,
                    "internet_access": True,
                    "internet_simulation": False,
                    "hybrid_code_analysis": True,
                    "hybrid_decompilation": True,
                    "report_cache": False,
                    "apk_instrumentation": True,
                    "amsi_unpacking": True,
                    "ssl_inspection": True,
                    "vba_instrumentation": False,
                    "js_instrumentation": False,
                    "java_jar_tracing": False,
                    "dotnet_tracing": False,
                    "start_as_normal_user": False,
                    "system_date": None,
                    "language_and_locale": None,
                    "localized_internet_country": None,
                    "email_notification": None,
                    "archive_no_unpack": False,
                    "hypervisor_based_inspection": False,
                    "fast_mode": False,
                    "secondary_results": True,
                    "cookbook_file_path": None,
                    "document_password": "1234",
                    "archive_password": "infected",
                    "command_line_argument": None,
                    "encrypt_with_password": None,
                    "browser": False,
                    "url_reputation": False,
                    "export_to_jbxview": False,
                    "delete_after_days": 30,
                    "priority": None,
                    "default_tlp": "TLP:CLEAR",
                    "yara_color": "#0059f7",
                    "default_color": "#54483b",
                },
            },
            "connector.id",
            id="missing_connector_id",
        ),
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                "connector": {
                    "id": "connector-id",
                    "name": "Test Connector",
                    "scope": "test, connector",
                    "log_level": "error",
                    "auto": True,
                },
                "joe_sandbox": {
                    "api_url": "https://jbxcloud.joesecurity.org/api",
                    # api_key intentionally omitted: it is a credential and
                    # must be supplied by the operator/manager. Settings
                    # validation MUST refuse to start without it.
                    "analysis_url": "https://jbxcloud.joesecurity.org/analysis",
                },
            },
            "joe_sandbox.api_key",
            id="missing_joe_sandbox_api_key",
        ),
        # ``proxies`` is documented as a JSON-encoded map; the validator
        # on ``JoeSandboxConfig.proxies`` (see
        # ``_validate_proxies_is_json_object``) surfaces malformed
        # input as ``ConfigValidationError`` at startup rather than
        # letting the connector crash later with a generic
        # ``JSONDecodeError`` once an enrichment message arrives.
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                "connector": {
                    "id": "connector-id",
                    "name": "Test Connector",
                    "scope": "test, connector",
                    "log_level": "error",
                    "auto": True,
                },
                "joe_sandbox": {
                    "api_url": "https://jbxcloud.joesecurity.org/api",
                    "api_key": "test-api-key",
                    "analysis_url": "https://jbxcloud.joesecurity.org/analysis",
                    "proxies": "not-valid-json",
                },
            },
            "joe_sandbox.proxies",
            id="malformed_joe_sandbox_proxies_json",
        ),
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                "connector": {
                    "id": "connector-id",
                    "name": "Test Connector",
                    "scope": "test, connector",
                    "log_level": "error",
                    "auto": True,
                },
                "joe_sandbox": {
                    "api_url": "https://jbxcloud.joesecurity.org/api",
                    "api_key": "test-api-key",
                    "analysis_url": "https://jbxcloud.joesecurity.org/analysis",
                    # Valid JSON, but the connector / requests need a
                    # scheme->URL *mapping*, not a list.
                    "proxies": '["http://proxy:8080"]',
                },
            },
            "joe_sandbox.proxies",
            id="joe_sandbox_proxies_not_a_json_object",
        ),
    ],
)
def test_settings_should_raise_when_invalid_input(settings_dict, field_name):
    """
    Test that `ConnectorSettings` (implementation of `BaseConnectorSettings` from `connectors-sdk`) raises on invalid input.
    For the test purpose, `BaseConnectorSettings._load_config_dict` is overridden to return
    a fake and invalid dict (instead of the env/config vars parsed from `config.yml`, `.env` or env vars).

    :param settings_dict: The dict to use as `ConnectorSettings` input
    :param field_name: The field name that is expected to be reported in the
        validation error message. Asserting the error mentions this field
        prevents regressions where the wrong field becomes the failing one.
    """

    class FakeConnectorSettings(ConnectorSettings):
        """
        Subclass of `ConnectorSettings` (implementation of `BaseConnectorSettings`) for testing purpose.
        It overrides `BaseConnectorSettings._load_config_dict` to return a fake but valid config dict.
        """

        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(settings_dict)

    with pytest.raises(ConfigValidationError) as err:
        FakeConnectorSettings()
    assert "Error validating configuration" in str(err.value)
    # Walk the chained pydantic ValidationError to assert that the expected
    # field path is among the failing ones. Without this assertion, the
    # parametrized ``field_name`` would not actually be exercised: any
    # configuration error in the dict would still pass the test.
    cause = err.value.__cause__
    assert cause is not None, "ConfigValidationError must wrap the pydantic error"
    # Assert on the leaf of each error ``loc`` (the field name) rather than the
    # dot-joined path: pydantic reports nested-model errors inconsistently
    # (e.g. ``("opencti", "url")`` vs an inner-model root ``("url",)``), so
    # matching the last ``loc`` segment against the last segment of the dotted
    # ``field_name`` is stable across those shapes.
    expected_field = field_name.split(".")[-1]
    error_fields = [str(error["loc"][-1]) for error in cause.errors() if error["loc"]]
    assert expected_field in error_fields, (
        f"Expected a validation error for field {field_name!r}, "
        f"got errors for: {error_fields}"
    )
